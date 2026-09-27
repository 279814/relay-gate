package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// InsertSample 写入一个 Sample Group（§5.4）：一条 sample_request 加上
// smp.Attempts 里的每次尝试（Attempts 为空时平铺字段即唯一一次尝试）。
//
// 调用方（sample.Recorder）已在后台单 goroutine 里，所以这里不必再考虑并发；
// 但**必须假设 body 已脱敏** —— 本函数不做脱敏，那是 sample 包的职责。
// Body BLOBs are stored as v1 envelopes when a Cipher is configured.
// RespBodyFile（spill）按 sampleBlobChunk 分块加密写入，不把全文读进一个 []byte。
func (s *Store) InsertSample(smp *model.Sample) error {
	if smp != nil {
		defer smp.ReleaseTempFiles()
	}
	return s.insertSampleGroup(smp)
}

// InsertSampleWithinQuota 在落库前重读当前正文磁盘占用（§5.4）。
//
// 采集侧 LimitToRemaining 在 tee 开始时读一次剩余配额；多个在途请求若读到
// 同一剩余值，各自按该值收满，串行 InsertSample 仍会把总量写成 N 倍。
// Recorder 单 writer 每条插入前走这里：放得下就写，否则截断放不下的正文，
// 连截断后仍放不下（例如配额已耗尽，或信封膨胀后丢掉全部正文仍无可用字节）
// 则跳过本组，不插入仅含头的空壳（空壳会占 Sample Group 名额），不报错给客户端。
// 正文原本就空的样本（真实空响应）在配额有余时仍入库头/状态元数据。
//
// maxBytes <= 0 表示该维度不限，行为与 InsertSample 相同。
// 返回 inserted=false 表示因配额跳过（不是错误）。
func (s *Store) InsertSampleWithinQuota(smp *model.Sample, maxBytes int64) (inserted bool, err error) {
	if smp != nil {
		defer smp.ReleaseTempFiles()
	}
	if maxBytes <= 0 {
		return true, s.insertSampleGroup(smp)
	}
	used, err := s.SampleDiskBytes()
	if err != nil {
		return false, fmt.Errorf("统计样本磁盘: %w", err)
	}
	rem := maxBytes - used
	if rem <= 0 {
		return false, nil
	}
	normalizeSampleAttempts(smp)
	defer syncSampleFinalView(smp)
	slots := sampleBodySlots(smp)
	if plainSlotBytes(slots) > rem {
		truncateSampleSlots(slots, rem)
	}
	// droppedForQuota：因放不下而丢掉正文后 need==0 时跳过空壳；原本就无正文的样本仍入库（头/状态元数据）。
	droppedForQuota := false
	for {
		enc, err := s.encryptSampleGroup(smp)
		if err != nil {
			return false, err
		}
		need, err := enc.diskBytes()
		if err != nil {
			enc.cleanup()
			return false, err
		}
		if need <= rem {
			if need == 0 && droppedForQuota {
				enc.cleanup()
				return false, nil
			}
			err := s.insertEncryptedSampleGroup(smp, enc)
			enc.cleanup()
			return true, err
		}
		enc.cleanup()
		// 信封膨胀后仍超剩余：继续丢掉优先级最低的正文（与采集侧预算顺序一致）。
		if !dropLowestSampleSlot(slots) {
			return false, nil
		}
		droppedForQuota = true
	}
}

func (s *Store) insertSampleGroup(smp *model.Sample) error {
	normalizeSampleAttempts(smp)
	enc, err := s.encryptSampleGroup(smp)
	if err != nil {
		return err
	}
	defer enc.cleanup()
	return s.insertEncryptedSampleGroup(smp, enc)
}

// normalizeSampleAttempts 把只填了平铺字段的样本变成单尝试组。
func normalizeSampleAttempts(smp *model.Sample) {
	if len(smp.Attempts) > 0 {
		return
	}
	smp.Attempts = []*model.SampleAttempt{{
		TSRecv: smp.TSRecv, TSSent: smp.TSSent, TSFirstByte: smp.TSFirstByte, TSDone: smp.TSDone,
		ModelOut: smp.ModelOut, ModelNameID: smp.ModelNameID,
		RouteID: smp.RouteID, UpstreamID: smp.UpstreamID,
		OutURL: smp.OutURL, OutHeaders: smp.OutHeaders, OutBody: smp.OutBody,
		RespStatus: smp.RespStatus, RespHeaders: smp.RespHeaders,
		RespBody: smp.RespBody, RespBodyFile: smp.RespBodyFile,
		Outcome: smp.Outcome, Error: smp.Error,
		Truncated: smp.Truncated &^ model.TruncInBody,
	}}
	smp.RespBodyFile = ""
}

// syncSampleFinalView 把最终尝试平铺到 Sample 上（管理 API 与列表沿用的形状）。
func syncSampleFinalView(smp *model.Sample) {
	smp.AttemptCount = len(smp.Attempts)
	if len(smp.Attempts) == 0 {
		smp.Truncated &= model.TruncInBody
		return
	}
	a := smp.Attempts[len(smp.Attempts)-1]
	smp.TSSent, smp.TSFirstByte, smp.TSDone = a.TSSent, a.TSFirstByte, a.TSDone
	smp.ModelOut, smp.ModelNameID = a.ModelOut, a.ModelNameID
	smp.RouteID, smp.UpstreamID = a.RouteID, a.UpstreamID
	smp.OutURL, smp.OutHeaders, smp.OutBody = a.OutURL, a.OutHeaders, a.OutBody
	smp.RespStatus, smp.RespHeaders, smp.RespBody = a.RespStatus, a.RespHeaders, a.RespBody
	smp.RespBodyFile = ""
	smp.Outcome, smp.Error = a.Outcome, a.Error
	smp.Truncated = smp.Truncated&model.TruncInBody | a.Truncated
}

// sampleBodySlot 是组内一份正文。配额裁剪按 slot 的保留优先级进行。
type sampleBodySlot struct {
	mem   *[]byte
	file  *string // 仅 resp 可能 spill
	flags *model.TruncFlags
	bit   model.TruncFlags
}

// sampleBodySlots 按保留优先级排列：先 in，再各次 out，然后最终响应，
// 最后是更早被丢弃尝试的响应。单尝试时即 in → out → resp。
func sampleBodySlots(smp *model.Sample) []sampleBodySlot {
	slots := []sampleBodySlot{{mem: &smp.InBody, flags: &smp.Truncated, bit: model.TruncInBody}}
	for _, a := range smp.Attempts {
		slots = append(slots, sampleBodySlot{mem: &a.OutBody, flags: &a.Truncated, bit: model.TruncOutBody})
	}
	for i := len(smp.Attempts) - 1; i >= 0; i-- {
		a := smp.Attempts[i]
		slots = append(slots, sampleBodySlot{mem: &a.RespBody, file: &a.RespBodyFile,
			flags: &a.Truncated, bit: model.TruncRespBody})
	}
	return slots
}

func (b sampleBodySlot) hasFile() bool { return b.file != nil && *b.file != "" }

func (b sampleBodySlot) empty() bool { return len(*b.mem) == 0 && !b.hasFile() }

func (b sampleBodySlot) plainSize() int64 {
	n := int64(len(*b.mem))
	if b.hasFile() {
		if p, err := model.ConfinedSpillPath(*b.file); err == nil {
			if fi, err := os.Stat(p); err == nil {
				n += fi.Size()
			}
		}
	}
	return n
}

func (b sampleBodySlot) drop() {
	*b.mem = nil
	if b.hasFile() {
		model.RemoveSpillFile(*b.file)
		*b.file = ""
	}
	*b.flags |= b.bit
}

// truncateTo 把正文裁到至多 n 字节，返回保留的字节数。
func (b sampleBodySlot) truncateTo(n int64) int64 {
	if n < 0 {
		n = 0
	}
	if b.hasFile() {
		p, err := model.ConfinedSpillPath(*b.file)
		if err != nil {
			*b.file = ""
			*b.flags |= b.bit
			return 0
		}
		fi, err := os.Stat(p)
		if err != nil {
			model.RemoveSpillFile(p)
			*b.file = ""
			*b.flags |= b.bit
			return 0
		}
		if fi.Size() <= n {
			return fi.Size()
		}
		if n <= 0 {
			model.RemoveSpillFile(p)
			*b.file = ""
		} else if err := os.Truncate(p, n); err != nil {
			model.RemoveSpillFile(p)
			*b.file = ""
		}
		*b.flags |= b.bit
		return n
	}
	if int64(len(*b.mem)) <= n {
		return int64(len(*b.mem))
	}
	*b.mem = append([]byte(nil), (*b.mem)[:n]...)
	*b.flags |= b.bit
	return n
}

func plainSlotBytes(slots []sampleBodySlot) int64 {
	var n int64
	for _, b := range slots {
		n += b.plainSize()
	}
	return n
}

// truncateSampleSlots 把全组正文裁到合计不超过 rem，按 slot 优先级分配。
func truncateSampleSlots(slots []sampleBodySlot, rem int64) {
	if rem < 0 {
		rem = 0
	}
	for _, b := range slots {
		rem -= b.truncateTo(rem)
	}
}

// dropLowestSampleSlot 丢掉优先级最低的非空正文；全空时返回 false。
func dropLowestSampleSlot(slots []sampleBodySlot) bool {
	for i := len(slots) - 1; i >= 0; i-- {
		if !slots[i].empty() {
			slots[i].drop()
			return true
		}
	}
	return false
}

type encSampleAttempt struct {
	out, resp []byte
	respPath  string // 已加密 spill 文件；非空时 resp 为空
}

type encSampleGroup struct {
	in       []byte
	attempts []encSampleAttempt
}

func (e *encSampleGroup) cleanup() {
	for _, a := range e.attempts {
		if a.respPath != "" {
			_ = os.Remove(a.respPath)
		}
	}
}

func (e *encSampleGroup) diskBytes() (int64, error) {
	n := int64(len(e.in))
	for _, a := range e.attempts {
		n += int64(len(a.out) + len(a.resp))
		if a.respPath != "" {
			fi, err := os.Stat(a.respPath)
			if err != nil {
				return 0, err
			}
			n += fi.Size()
		}
	}
	return n, nil
}

func (s *Store) encryptSampleGroup(smp *model.Sample) (*encSampleGroup, error) {
	e := &encSampleGroup{}
	var err error
	if e.in, err = s.encryptSampleBody(smp.InBody); err != nil {
		return nil, err
	}
	for _, a := range smp.Attempts {
		var ea encSampleAttempt
		if ea.out, err = s.encryptSampleBody(a.OutBody); err != nil {
			e.cleanup()
			return nil, err
		}
		if a.RespBodyFile != "" {
			if ea.respPath, err = s.encryptSampleBodyFile(a.RespBodyFile); err != nil {
				e.cleanup()
				return nil, err
			}
		} else if ea.resp, err = s.encryptSampleBody(a.RespBody); err != nil {
			e.cleanup()
			return nil, err
		}
		e.attempts = append(e.attempts, ea)
	}
	return e, nil
}

// insertEncryptedSampleGroup 在一个事务里写入 request 与全部 attempt：
// 不会留下没有尝试的请求，也不会留下半组尝试。
func (s *Store) insertEncryptedSampleGroup(smp *model.Sample, enc *encSampleGroup) (err error) {
	inH, err := marshalJSONHeaders(smp.InHeaders)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("写入样本: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	res, err := tx.Exec(`INSERT INTO sample_request (
		req_id, ts_recv, endpoint, model_in,
		in_method, in_path, in_query, in_headers, in_body,
		truncated, pinned
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		smp.ReqID, smp.TSRecv, smp.Endpoint, smp.ModelIn,
		smp.InMethod, smp.InPath, smp.InQuery, inH, enc.in,
		int(smp.Truncated&model.TruncInBody), smp.Pinned)
	if err != nil {
		return fmt.Errorf("写入样本: %w", err)
	}
	requestID, err := res.LastInsertId()
	if err != nil {
		return err
	}
	for i, a := range smp.Attempts {
		if err = insertSampleAttemptRow(tx, requestID, a, enc.attempts[i]); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("提交样本: %w", err)
	}
	smp.ID = requestID
	syncSampleFinalView(smp)
	return nil
}

// insertSampleAttemptRow 写一行 sample_attempt。spill 响应按块写入 BLOB，
// 单次绑定不超过 sampleBlobChunk，避免整 spill 进一个 Go slice。
func insertSampleAttemptRow(tx *sql.Tx, requestID int64, a *model.SampleAttempt, ea encSampleAttempt) error {
	outH, err := marshalJSONHeaders(a.OutHeaders)
	if err != nil {
		return err
	}
	respH, err := marshalJSONHeaders(a.RespHeaders)
	if err != nil {
		return err
	}
	resp := ea.resp
	var f *os.File
	var buf []byte
	if ea.respPath != "" {
		f, err = os.Open(ea.respPath)
		if err != nil {
			return err
		}
		defer f.Close()
		chunk := sampleBlobChunk
		if chunk < 1 {
			chunk = 1
		}
		buf = make([]byte, chunk)
		n, rerr := io.ReadFull(f, buf)
		if rerr != nil && !errors.Is(rerr, io.EOF) && !errors.Is(rerr, io.ErrUnexpectedEOF) {
			return rerr
		}
		resp = append([]byte(nil), buf[:n]...)
	}
	res, err := tx.Exec(`INSERT INTO sample_attempt (
		request_id, ts_recv, ts_sent, ts_first_byte, ts_done,
		model_out, model_name_id, route_id, upstream_id,
		out_url, out_headers, out_body,
		resp_status, resp_headers, resp_body,
		outcome, error, truncated
	) VALUES (?, ?,?,?,?, ?,?,?,?, ?,?,?, ?,?,?, ?,?,?)`,
		requestID, a.TSRecv, a.TSSent, a.TSFirstByte, a.TSDone,
		a.ModelOut, a.ModelNameID, a.RouteID, a.UpstreamID,
		a.OutURL, outH, ea.out,
		a.RespStatus, respH, resp,
		string(a.Outcome), a.Error, int(a.Truncated&^model.TruncInBody))
	if err != nil {
		return fmt.Errorf("写入样本尝试: %w", err)
	}
	if a.ID, err = res.LastInsertId(); err != nil {
		return err
	}
	a.RequestID = requestID
	if f == nil {
		return nil
	}
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			piece := append([]byte(nil), buf[:n]...)
			if _, err := tx.Exec(`UPDATE sample_attempt SET resp_body = resp_body || ? WHERE id = ?`, piece, a.ID); err != nil {
				return fmt.Errorf("追加样本正文: %w", err)
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

const sampleRequestCols = `id, COALESCE(legacy_sample_id, 0), req_id, ts_recv, endpoint, model_in,
	in_method, in_path, in_query, in_headers, in_body, truncated, pinned`

const sampleAttemptCols = `id, request_id, ts_recv, ts_sent, ts_first_byte, ts_done,
	model_out, model_name_id, route_id, upstream_id,
	out_url, out_headers, out_body,
	resp_status, resp_headers, resp_body,
	outcome, error, truncated`

func scanSampleRequest(sc interface{ Scan(...any) error }, cipher *Cipher) (*model.Sample, error) {
	var s model.Sample
	var inH string
	var inBody []byte
	var trunc int
	if err := sc.Scan(&s.ID, &s.LegacySampleID, &s.ReqID, &s.TSRecv, &s.Endpoint, &s.ModelIn,
		&s.InMethod, &s.InPath, &s.InQuery, &inH, &inBody, &trunc, &s.Pinned); err != nil {
		return nil, err
	}
	s.Truncated = model.TruncFlags(trunc)
	var err error
	if s.InHeaders, err = unmarshalJSONHeaders(inH); err != nil {
		return nil, fmt.Errorf("样本 %d 的 in_headers: %w", s.ID, err)
	}
	if s.InBody, err = decryptSampleBody(cipher, inBody); err != nil {
		return nil, fmt.Errorf("样本 %d 的 in_body: %w", s.ID, err)
	}
	return &s, nil
}

func scanSampleAttempt(sc interface{ Scan(...any) error }, cipher *Cipher) (*model.SampleAttempt, error) {
	var a model.SampleAttempt
	var outH, respH string
	var outBody, respBody []byte
	var outcome string
	var trunc int
	if err := sc.Scan(&a.ID, &a.RequestID, &a.TSRecv, &a.TSSent, &a.TSFirstByte, &a.TSDone,
		&a.ModelOut, &a.ModelNameID, &a.RouteID, &a.UpstreamID,
		&a.OutURL, &outH, &outBody,
		&a.RespStatus, &respH, &respBody,
		&outcome, &a.Error, &trunc); err != nil {
		return nil, err
	}
	a.Outcome = model.Outcome(outcome)
	a.Truncated = model.TruncFlags(trunc)
	var err error
	if a.OutHeaders, err = unmarshalJSONHeaders(outH); err != nil {
		return nil, fmt.Errorf("样本尝试 %d 的 out_headers: %w", a.ID, err)
	}
	if a.RespHeaders, err = unmarshalJSONHeaders(respH); err != nil {
		return nil, fmt.Errorf("样本尝试 %d 的 resp_headers: %w", a.ID, err)
	}
	if a.OutBody, err = decryptSampleBody(cipher, outBody); err != nil {
		return nil, fmt.Errorf("样本尝试 %d 的 out_body: %w", a.ID, err)
	}
	if a.RespBody, err = decryptSampleBody(cipher, respBody); err != nil {
		return nil, fmt.Errorf("样本尝试 %d 的 resp_body: %w", a.ID, err)
	}
	return &a, nil
}

// SampleFilter 是样本列表的筛选条件。零值表示不筛。
// Route / 上游 / outcome 按每组的最终尝试筛选（客户端拿到的那次）。
type SampleFilter struct {
	RouteID    int64
	UpstreamID int64
	Outcome    model.Outcome
	// ReqID 按请求分组筛选，供「从日志跳到样本」用（M6）。
	ReqID string
	Limit int
	// BeforeID 用于翻页（游标式）。样本表只增不改，用 id 游标比 OFFSET 稳 ——
	// OFFSET 在翻页期间有新样本写入时会漏记录。
	BeforeID int64
}

// ListSamples 按时间倒序列出 Sample Group，每组平铺最终尝试的元数据。
//
// **不返回 body** —— 列表页只需要元数据，而 body 加起来可达 300KB+，
// 一页 50 条就是 15MB。详情用 GetSample 单独取。
func (s *Store) ListSamples(f SampleFilter) ([]*model.Sample, error) {
	limit, err := NormalizePageLimit(f.Limit)
	if err != nil {
		return nil, err
	}

	q := `SELECT r.id, COALESCE(r.legacy_sample_id, 0), r.req_id, r.ts_recv,
		COALESCE(a.ts_sent, 0), COALESCE(a.ts_first_byte, 0), COALESCE(a.ts_done, 0),
		r.endpoint, r.model_in, COALESCE(a.model_out, ''), COALESCE(a.model_name_id, 0),
		COALESCE(a.route_id, 0), COALESCE(a.upstream_id, 0),
		r.in_method, r.in_path, r.in_query,
		COALESCE(a.resp_status, 0), COALESCE(a.outcome, ''), COALESCE(a.error, ''),
		r.truncated | COALESCE(a.truncated, 0), r.pinned,
		(SELECT COUNT(*) FROM sample_attempt c WHERE c.request_id = r.id)
		FROM sample_request r
		LEFT JOIN sample_attempt a ON a.id = (
			SELECT MAX(m.id) FROM sample_attempt m WHERE m.request_id = r.id)
		WHERE 1=1`
	args := []any{}
	if f.RouteID > 0 {
		q += ` AND a.route_id = ?`
		args = append(args, f.RouteID)
	}
	if f.ReqID != "" {
		q += ` AND r.req_id = ?`
		args = append(args, f.ReqID)
	}
	if f.UpstreamID > 0 {
		q += ` AND a.upstream_id = ?`
		args = append(args, f.UpstreamID)
	}
	if f.Outcome != "" {
		q += ` AND a.outcome = ?`
		args = append(args, string(f.Outcome))
	}
	if f.BeforeID > 0 {
		q += ` AND r.id < ?`
		args = append(args, f.BeforeID)
	}
	q += ` ORDER BY r.id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*model.Sample{}
	for rows.Next() {
		var smp model.Sample
		var outcome string
		var trunc int
		if err := rows.Scan(&smp.ID, &smp.LegacySampleID, &smp.ReqID, &smp.TSRecv,
			&smp.TSSent, &smp.TSFirstByte, &smp.TSDone,
			&smp.Endpoint, &smp.ModelIn, &smp.ModelOut, &smp.ModelNameID, &smp.RouteID,
			&smp.UpstreamID, &smp.InMethod, &smp.InPath, &smp.InQuery,
			&smp.RespStatus, &outcome, &smp.Error, &trunc, &smp.Pinned,
			&smp.AttemptCount); err != nil {
			return nil, err
		}
		smp.Outcome = model.Outcome(outcome)
		smp.Truncated = model.TruncFlags(trunc)
		out = append(out, &smp)
	}
	return out, rows.Err()
}

// GetSample 取一个 Sample Group：入站请求 + 按发送顺序的全部尝试。
// 迁移来的旧样本只有一次尝试（旧的最终尝试）。
func (s *Store) GetSample(id int64) (*model.Sample, error) {
	row := s.db.QueryRow(`SELECT `+sampleRequestCols+` FROM sample_request WHERE id = ?`, id)
	smp, err := scanSampleRequest(row, s.cipher)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT `+sampleAttemptCols+` FROM sample_attempt WHERE request_id = ? ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		a, err := scanSampleAttempt(rows, s.cipher)
		if err != nil {
			return nil, err
		}
		smp.Attempts = append(smp.Attempts, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	syncSampleFinalView(smp)
	return smp, nil
}

// MaxPinnedSampleGroups 是 §5.4 默认保留策略中的「最多置顶 50 个 Group」。
const MaxPinnedSampleGroups = 50

// SetSamplePinned 置顶/取消置顶一个 Sample Group。置顶的组不参与滚动清理。
//
// §5.4：已置顶达到 MaxPinnedSampleGroups 时拒绝新的置顶；已置顶的行重复置顶
// 和取消置顶始终允许。计数与更新在同一条 UPDATE 里完成，并发置顶不会越过上限。
func (s *Store) SetSamplePinned(id int64, pinned bool) error {
	if !pinned {
		res, err := s.db.Exec(`UPDATE sample_request SET pinned = 0 WHERE id = ?`, id)
		if err != nil {
			return err
		}
		return checkAffected(res)
	}
	res, err := s.db.Exec(`UPDATE sample_request SET pinned = 1 WHERE id = ? AND (
		pinned = 1 OR (SELECT COUNT(*) FROM sample_request WHERE pinned = 1) < ?)`,
		id, MaxPinnedSampleGroups)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	var exists int
	if err := s.db.QueryRow(`SELECT 1 FROM sample_request WHERE id = ?`, id).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	return fmt.Errorf("%w: 最多置顶 %d 个样本组，请先取消置顶其他样本",
		model.ErrValidation, MaxPinnedSampleGroups)
}

// PruneSamples 按条数、天数与磁盘配额清理 Sample Group，各维度独立取先到者（§5.4）。
// pinned 豁免删除，但仍计入磁盘配额。删除 sample_request 时其 sample_attempt
// 随外键级联删除。
//
// keepCount / keepDays / maxBytes <= 0 表示该维度不限。
// 磁盘配额按 in_body/out_body/resp_body 存盘 BLOB 字节合计（信封或明文均计入），
// 超限时优先删除最旧未置顶组；不按信封形态筛选。
//
// §5.4：一个客户端请求形成一个 Sample Group（含 request_log）。删除 Group
// 时必须一并删掉同 req_id 的 request_log，否则重试产生的多行日志会在样本
// 被清后无限期残留。置顶样本豁免，其日志也保留。无样本的独立日志仍由
// PruneRequestLogs 按自身 keep 清理，这里不碰。
func (s *Store) PruneSamples(keepCount, keepDays int, maxBytes int64) (int64, error) {
	var total int64

	if keepDays > 0 {
		cutoff := time.Now().Add(-time.Duration(keepDays) * 24 * time.Hour).UnixMilli()
		reqIDs, err := s.listSampleReqIDs(
			`SELECT req_id FROM sample_request WHERE pinned = 0 AND ts_recv < ? AND req_id != ''`, cutoff)
		if err != nil {
			return total, fmt.Errorf("列举待删样本 req_id: %w", err)
		}
		res, err := s.db.Exec(
			`DELETE FROM sample_request WHERE pinned = 0 AND ts_recv < ?`, cutoff)
		if err != nil {
			return total, fmt.Errorf("按天数清理样本: %w", err)
		}
		n, _ := res.RowsAffected()
		total += n
		if err := s.deleteRequestLogsForPrunedReqIDs(reqIDs); err != nil {
			return total, err
		}
	}

	if keepCount > 0 {
		// 只数未置顶的：置顶的不参与清理，把它们算进配额会导致
		// 置顶几条就把正常样本挤掉，越用越少。
		reqIDs, err := s.listSampleReqIDs(
			`SELECT req_id FROM sample_request WHERE pinned = 0 AND req_id != '' AND id NOT IN (
				SELECT id FROM sample_request WHERE pinned = 0 ORDER BY id DESC LIMIT ?)`, keepCount)
		if err != nil {
			return total, fmt.Errorf("列举待删样本 req_id: %w", err)
		}
		res, err := s.db.Exec(`DELETE FROM sample_request WHERE pinned = 0 AND id NOT IN (
			SELECT id FROM sample_request WHERE pinned = 0 ORDER BY id DESC LIMIT ?)`, keepCount)
		if err != nil {
			return total, fmt.Errorf("按条数清理样本: %w", err)
		}
		n, _ := res.RowsAffected()
		total += n
		if err := s.deleteRequestLogsForPrunedReqIDs(reqIDs); err != nil {
			return total, err
		}
	}

	if maxBytes > 0 {
		n, err := s.pruneSamplesByDiskQuota(maxBytes)
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// listSampleReqIDs 执行返回 req_id 列的查询，去掉空串与重复。
func (s *Store) listSampleReqIDs(query string, args ...any) ([]string, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	seen := map[string]struct{}{}
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, rows.Err()
}

// deleteRequestLogsForPrunedReqIDs 删除已无对应 Sample Group 的 request_log。
// 仍有 sample_request 行的 req_id（例如置顶豁免）不会被删。
func (s *Store) deleteRequestLogsForPrunedReqIDs(reqIDs []string) error {
	for _, id := range reqIDs {
		if id == "" {
			continue
		}
		_, err := s.db.Exec(`DELETE FROM request_log WHERE req_id = ? AND NOT EXISTS (
			SELECT 1 FROM sample_request WHERE req_id = ?)`, id, id)
		if err != nil {
			return fmt.Errorf("清理已删样本的请求日志: %w", err)
		}
	}
	return nil
}

// 正文 BLOB 存盘字节合计表达式。
// 用 LENGTH(存盘列) 而不是解密后明文，才对得上实际占用的磁盘。
const (
	sampleRequestDiskBytesSQL = `COALESCE(LENGTH(in_body),0)`
	sampleAttemptDiskBytesSQL = `COALESCE(LENGTH(out_body),0)+COALESCE(LENGTH(resp_body),0)`
)

// SampleDiskBytes 返回全部 Sample Group 正文 BLOB 的存盘字节合计。
func (s *Store) SampleDiskBytes() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT
		COALESCE((SELECT SUM(` + sampleRequestDiskBytesSQL + `) FROM sample_request), 0) +
		COALESCE((SELECT SUM(` + sampleAttemptDiskBytesSQL + `) FROM sample_attempt), 0)`).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (s *Store) pruneSamplesByDiskQuota(maxBytes int64) (int64, error) {
	used, err := s.SampleDiskBytes()
	if err != nil {
		return 0, fmt.Errorf("统计样本磁盘: %w", err)
	}
	if used <= maxBytes {
		return 0, nil
	}

	rows, err := s.db.Query(`SELECT r.id, r.req_id, ` + sampleRequestDiskBytesSQL + ` + COALESCE((
			SELECT SUM(` + sampleAttemptDiskBytesSQL + `) FROM sample_attempt a WHERE a.request_id = r.id), 0) AS sz
		FROM sample_request r WHERE r.pinned = 0 ORDER BY r.id ASC`)
	if err != nil {
		return 0, fmt.Errorf("列举待删样本: %w", err)
	}
	defer rows.Close()

	type victim struct {
		id    int64
		reqID string
	}
	var toDelete []victim
	for rows.Next() && used > maxBytes {
		var v victim
		var sz int64
		if err := rows.Scan(&v.id, &v.reqID, &sz); err != nil {
			return 0, err
		}
		toDelete = append(toDelete, v)
		used -= sz
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	_ = rows.Close()

	var deleted int64
	var reqIDs []string
	for _, v := range toDelete {
		res, err := s.db.Exec(`DELETE FROM sample_request WHERE id = ? AND pinned = 0`, v.id)
		if err != nil {
			return deleted, fmt.Errorf("按磁盘配额清理样本: %w", err)
		}
		n, _ := res.RowsAffected()
		deleted += n
		if n > 0 && v.reqID != "" {
			reqIDs = append(reqIDs, v.reqID)
		}
	}
	if err := s.deleteRequestLogsForPrunedReqIDs(reqIDs); err != nil {
		return deleted, err
	}
	return deleted, nil
}

// CountSamples 返回 Sample Group 总数，供 UI 展示。
func (s *Store) CountSamples() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM sample_request`).Scan(&n)
	return n, err
}

// ClearSamples 清空 Sample Group（UI 的「一键清空」，§3.6.3d）。
// keepPinned 为 true 时保留置顶的组。尝试随外键级联删除。
func (s *Store) ClearSamples(keepPinned bool) (int64, error) {
	q := `DELETE FROM sample_request`
	if keepPinned {
		q += ` WHERE pinned = 0`
	}
	res, err := s.db.Exec(q)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// marshalJSONHeaders 把 http.Header 存成 JSON 对象。
//
// 保留多值（值是数组）：Anthropic-Beta 常有多个，压成一个字符串就分不清
// 「一个头带逗号分隔的值」与「多个同名头」，而这两者在上游看来可能不同。
func marshalJSONHeaders(h http.Header) (string, error) {
	if len(h) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("序列化请求头: %w", err)
	}
	return string(b), nil
}

func unmarshalJSONHeaders(raw string) (http.Header, error) {
	if raw == "" || raw == "{}" {
		return http.Header{}, nil
	}
	var h http.Header
	if err := json.Unmarshal([]byte(raw), &h); err != nil {
		return nil, err
	}
	return h, nil
}

func (s *Store) encryptSampleBody(plain []byte) ([]byte, error) {
	if s.cipher == nil {
		return plain, nil
	}
	return s.cipher.EncryptSampleBlob(plain)
}

func decryptSampleBody(cipher *Cipher, raw []byte) ([]byte, error) {
	if cipher == nil {
		return append([]byte(nil), raw...), nil
	}
	return cipher.DecryptSampleBlob(raw)
}

// MigrateSampleEnvelopes rewrites legacy plaintext sample body BLOBs
// (sample_request.in_body, sample_attempt.out_body/resp_body) into v1
// envelopes in place. Rows are never deleted; already-enveloped fields are
// left alone. Returns the number of Sample Groups that had at least one field
// rewritten.
func (s *Store) MigrateSampleEnvelopes() (int64, error) {
	if s.cipher == nil {
		return 0, fmt.Errorf("sample envelope migration requires Cipher")
	}
	touched := map[int64]struct{}{}

	type reqRow struct {
		id int64
		in []byte
	}
	var reqTodo []reqRow
	rows, err := s.db.Query(`SELECT id, in_body FROM sample_request`)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var r reqRow
		if err := rows.Scan(&r.id, &r.in); err != nil {
			rows.Close()
			return 0, err
		}
		if len(r.in) > 0 && !IsSampleEnvelope(r.in) {
			reqTodo = append(reqTodo, r)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	for _, r := range reqTodo {
		in, err := s.cipher.EncryptSampleBlob(r.in)
		if err != nil {
			return int64(len(touched)), fmt.Errorf("encrypt sample %d in_body: %w", r.id, err)
		}
		if _, err := s.db.Exec(`UPDATE sample_request SET in_body=? WHERE id=?`, in, r.id); err != nil {
			return int64(len(touched)), fmt.Errorf("update sample %d: %w", r.id, err)
		}
		touched[r.id] = struct{}{}
	}

	type attRow struct {
		id, requestID  int64
		out, resp      []byte
		needOut, needR bool
	}
	var attTodo []attRow
	rows, err = s.db.Query(`SELECT id, request_id, out_body, resp_body FROM sample_attempt`)
	if err != nil {
		return int64(len(touched)), err
	}
	for rows.Next() {
		var r attRow
		if err := rows.Scan(&r.id, &r.requestID, &r.out, &r.resp); err != nil {
			rows.Close()
			return int64(len(touched)), err
		}
		r.needOut = len(r.out) > 0 && !IsSampleEnvelope(r.out)
		r.needR = len(r.resp) > 0 && !IsSampleEnvelope(r.resp)
		if r.needOut || r.needR {
			attTodo = append(attTodo, r)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return int64(len(touched)), err
	}
	rows.Close()
	for _, r := range attTodo {
		out, resp := r.out, r.resp
		var err error
		if r.needOut {
			if out, err = s.cipher.EncryptSampleBlob(r.out); err != nil {
				return int64(len(touched)), fmt.Errorf("encrypt sample attempt %d out_body: %w", r.id, err)
			}
		}
		if r.needR {
			if resp, err = s.cipher.EncryptSampleBlob(r.resp); err != nil {
				return int64(len(touched)), fmt.Errorf("encrypt sample attempt %d resp_body: %w", r.id, err)
			}
		}
		if _, err := s.db.Exec(`UPDATE sample_attempt SET out_body=?, resp_body=? WHERE id=?`,
			out, resp, r.id); err != nil {
			return int64(len(touched)), fmt.Errorf("update sample attempt %d: %w", r.id, err)
		}
		touched[r.requestID] = struct{}{}
	}
	return int64(len(touched)), nil
}
