package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// InsertSample 写入一条样本（§3.6.2）。
//
// 调用方（sample.Recorder）已在后台单 goroutine 里，所以这里不必再考虑并发；
// 但**必须假设 body 已脱敏** —— 本函数不做脱敏，那是 sample 包的职责。
// Body BLOBs are stored as v1 envelopes when a Cipher is configured.
func (s *Store) InsertSample(smp *model.Sample) error {
	inBody, err := s.encryptSampleBody(smp.InBody)
	if err != nil {
		return err
	}
	outBody, err := s.encryptSampleBody(smp.OutBody)
	if err != nil {
		return err
	}
	respBody, err := s.encryptSampleBody(smp.RespBody)
	if err != nil {
		return err
	}
	return s.insertSampleEncrypted(smp, inBody, outBody, respBody)
}

// InsertSampleWithinQuota 在落库前重读当前正文磁盘占用（§5.4）。
//
// 采集侧 LimitToRemaining 在 tee 开始时读一次剩余配额；多个在途请求若读到
// 同一剩余值，各自按该值收满，串行 InsertSample 仍会把总量写成 N 倍。
// Recorder 单 writer 每条插入前走这里：放得下就写，否则截断放不下的正文，
// 连截断后仍放不下（例如配额已耗尽）则跳过本条，不报错给客户端。
//
// maxBytes <= 0 表示该维度不限，行为与 InsertSample 相同。
// 返回 inserted=false 表示因配额跳过（不是错误）。
func (s *Store) InsertSampleWithinQuota(smp *model.Sample, maxBytes int64) (inserted bool, err error) {
	if maxBytes <= 0 {
		return true, s.InsertSample(smp)
	}
	used, err := s.SampleDiskBytes()
	if err != nil {
		return false, fmt.Errorf("统计样本磁盘: %w", err)
	}
	rem := maxBytes - used
	if rem <= 0 {
		return false, nil
	}
	if plainSampleBodyBytes(smp) > rem {
		truncateSamplePlainBodies(smp, rem)
	}
	for {
		inBody, err := s.encryptSampleBody(smp.InBody)
		if err != nil {
			return false, err
		}
		outBody, err := s.encryptSampleBody(smp.OutBody)
		if err != nil {
			return false, err
		}
		respBody, err := s.encryptSampleBody(smp.RespBody)
		if err != nil {
			return false, err
		}
		need := int64(len(inBody) + len(outBody) + len(respBody))
		if need <= rem {
			return true, s.insertSampleEncrypted(smp, inBody, outBody, respBody)
		}
		// 信封膨胀后仍超剩余：继续丢掉正文（先 resp，与采集侧预算顺序一致）。
		switch {
		case len(smp.RespBody) > 0:
			smp.RespBody = nil
			smp.Truncated |= model.TruncRespBody
		case len(smp.OutBody) > 0:
			smp.OutBody = nil
			smp.Truncated |= model.TruncOutBody
		case len(smp.InBody) > 0:
			smp.InBody = nil
			smp.Truncated |= model.TruncInBody
		default:
			return false, nil
		}
	}
}

func plainSampleBodyBytes(smp *model.Sample) int64 {
	if smp == nil {
		return 0
	}
	return int64(len(smp.InBody) + len(smp.OutBody) + len(smp.RespBody))
}

// truncateSamplePlainBodies 把三条正文裁到合计不超过 rem。
// 预算顺序与采集侧一致：先保留 in，再 out，剩余给 resp。
func truncateSamplePlainBodies(smp *model.Sample, rem int64) {
	if smp == nil {
		return
	}
	if rem < 0 {
		rem = 0
	}
	if int64(len(smp.InBody)) > rem {
		smp.InBody = append([]byte(nil), smp.InBody[:rem]...)
		smp.Truncated |= model.TruncInBody
		rem = 0
	} else {
		rem -= int64(len(smp.InBody))
	}
	if int64(len(smp.OutBody)) > rem {
		smp.OutBody = append([]byte(nil), smp.OutBody[:rem]...)
		smp.Truncated |= model.TruncOutBody
		rem = 0
	} else {
		rem -= int64(len(smp.OutBody))
	}
	if int64(len(smp.RespBody)) > rem {
		smp.RespBody = append([]byte(nil), smp.RespBody[:rem]...)
		smp.Truncated |= model.TruncRespBody
	}
}

func (s *Store) insertSampleEncrypted(smp *model.Sample, inBody, outBody, respBody []byte) error {
	inH, err := marshalJSONHeaders(smp.InHeaders)
	if err != nil {
		return err
	}
	outH, err := marshalJSONHeaders(smp.OutHeaders)
	if err != nil {
		return err
	}
	respH, err := marshalJSONHeaders(smp.RespHeaders)
	if err != nil {
		return err
	}

	res, err := s.db.Exec(`INSERT INTO sample (
		req_id,
		ts_recv, ts_sent, ts_first_byte, ts_done,
		endpoint, model_in, model_out, model_name_id, route_id, upstream_id,
		in_method, in_path, in_query, in_headers, in_body,
		out_url, out_headers, out_body,
		resp_status, resp_headers, resp_body,
		outcome, error, truncated, pinned
	) VALUES (?, ?,?,?,?, ?,?,?,?,?,?, ?,?,?,?,?, ?,?,?, ?,?,?, ?,?,?,?)`,
		smp.ReqID,
		smp.TSRecv, smp.TSSent, smp.TSFirstByte, smp.TSDone,
		smp.Endpoint, smp.ModelIn, smp.ModelOut, smp.ModelNameID, smp.RouteID, smp.UpstreamID,
		smp.InMethod, smp.InPath, smp.InQuery, inH, inBody,
		smp.OutURL, outH, outBody,
		smp.RespStatus, respH, respBody,
		string(smp.Outcome), smp.Error, int(smp.Truncated), smp.Pinned)
	if err != nil {
		return fmt.Errorf("写入样本: %w", err)
	}
	smp.ID, err = res.LastInsertId()
	return err
}

const sampleCols = `id, req_id, ts_recv, ts_sent, ts_first_byte, ts_done,
	endpoint, model_in, model_out, model_name_id, route_id, upstream_id,
	in_method, in_path, in_query, in_headers, in_body,
	out_url, out_headers, out_body,
	resp_status, resp_headers, resp_body,
	outcome, error, truncated, pinned`

func scanSample(sc interface{ Scan(...any) error }, cipher *Cipher) (*model.Sample, error) {
	var s model.Sample
	var inH, outH, respH string
	var inBody, outBody, respBody []byte
	var outcome string
	var trunc int
	if err := sc.Scan(&s.ID, &s.ReqID, &s.TSRecv, &s.TSSent, &s.TSFirstByte, &s.TSDone,
		&s.Endpoint, &s.ModelIn, &s.ModelOut, &s.ModelNameID, &s.RouteID, &s.UpstreamID,
		&s.InMethod, &s.InPath, &s.InQuery, &inH, &inBody,
		&s.OutURL, &outH, &outBody,
		&s.RespStatus, &respH, &respBody,
		&outcome, &s.Error, &trunc, &s.Pinned); err != nil {
		return nil, err
	}
	s.Outcome = model.Outcome(outcome)
	s.Truncated = model.TruncFlags(trunc)

	var err error
	if s.InHeaders, err = unmarshalJSONHeaders(inH); err != nil {
		return nil, fmt.Errorf("样本 %d 的 in_headers: %w", s.ID, err)
	}
	if s.OutHeaders, err = unmarshalJSONHeaders(outH); err != nil {
		return nil, fmt.Errorf("样本 %d 的 out_headers: %w", s.ID, err)
	}
	if s.RespHeaders, err = unmarshalJSONHeaders(respH); err != nil {
		return nil, fmt.Errorf("样本 %d 的 resp_headers: %w", s.ID, err)
	}
	if s.InBody, err = decryptSampleBody(cipher, inBody); err != nil {
		return nil, fmt.Errorf("样本 %d 的 in_body: %w", s.ID, err)
	}
	if s.OutBody, err = decryptSampleBody(cipher, outBody); err != nil {
		return nil, fmt.Errorf("样本 %d 的 out_body: %w", s.ID, err)
	}
	if s.RespBody, err = decryptSampleBody(cipher, respBody); err != nil {
		return nil, fmt.Errorf("样本 %d 的 resp_body: %w", s.ID, err)
	}
	return &s, nil
}

// SampleFilter 是样本列表的筛选条件。零值表示不筛。
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

// 样本列表的分页边界。上限存在的意义是防一次拉爆内存，
// 而不是防用户多要 —— 所以超了就截到上限，见 ListSamples。
const (
	defaultSampleLimit = 50
	maxSampleLimit     = 500
)

// ListSamples 按时间倒序列出样本。
//
// **不返回 body** —— 列表页只需要元数据，而三个 body 加起来可达 300KB+，
// 一页 50 条就是 15MB。详情用 GetSample 单独取。
func (s *Store) ListSamples(f SampleFilter) ([]*model.Sample, error) {
	q := `SELECT id, req_id, ts_recv, ts_sent, ts_first_byte, ts_done,
		endpoint, model_in, model_out, model_name_id, route_id, upstream_id,
		in_method, in_path, in_query, resp_status, outcome, error, truncated, pinned
		FROM sample WHERE 1=1`
	args := []any{}
	if f.RouteID > 0 {
		q += ` AND route_id = ?`
		args = append(args, f.RouteID)
	}
	if f.ReqID != "" {
		q += ` AND req_id = ?`
		args = append(args, f.ReqID)
	}
	if f.UpstreamID > 0 {
		q += ` AND upstream_id = ?`
		args = append(args, f.UpstreamID)
	}
	if f.Outcome != "" {
		q += ` AND outcome = ?`
		args = append(args, string(f.Outcome))
	}
	if f.BeforeID > 0 {
		q += ` AND id < ?`
		args = append(args, f.BeforeID)
	}
	// 未指定给默认值，超上限则**截到上限**而不是掉回默认值 ——
	// 后者会让 limit=1000 拿到 50 条，翻页逻辑据此以为「到底了」。
	limit := f.Limit
	switch {
	case limit <= 0:
		limit = defaultSampleLimit
	case limit > maxSampleLimit:
		limit = maxSampleLimit
	}
	q += ` ORDER BY id DESC LIMIT ?`
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
		if err := rows.Scan(&smp.ID, &smp.ReqID, &smp.TSRecv, &smp.TSSent, &smp.TSFirstByte, &smp.TSDone,
			&smp.Endpoint, &smp.ModelIn, &smp.ModelOut, &smp.ModelNameID, &smp.RouteID,
			&smp.UpstreamID, &smp.InMethod, &smp.InPath, &smp.InQuery,
			&smp.RespStatus, &outcome, &smp.Error, &trunc, &smp.Pinned); err != nil {
			return nil, err
		}
		smp.Outcome = model.Outcome(outcome)
		smp.Truncated = model.TruncFlags(trunc)
		out = append(out, &smp)
	}
	return out, rows.Err()
}

func (s *Store) GetSample(id int64) (*model.Sample, error) {
	row := s.db.QueryRow(`SELECT `+sampleCols+` FROM sample WHERE id = ?`, id)
	smp, err := scanSample(row, s.cipher)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return smp, err
}

// SetSamplePinned 置顶/取消置顶。置顶的样本不参与滚动清理。
func (s *Store) SetSamplePinned(id int64, pinned bool) error {
	res, err := s.db.Exec(`UPDATE sample SET pinned = ? WHERE id = ?`, pinned, id)
	if err != nil {
		return err
	}
	return checkAffected(res)
}

// PruneSamples 按条数、天数与磁盘配额清理，各维度独立取先到者（§5.4）。
// pinned 豁免删除，但仍计入磁盘配额。
//
// keepCount / keepDays / maxBytes <= 0 表示该维度不限。
// 磁盘配额按 in_body/out_body/resp_body 存盘 BLOB 字节合计（信封或明文均计入），
// 超限时优先删除最旧未置顶行；只删 sample 表整行，不按信封形态筛选。
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
			`SELECT req_id FROM sample WHERE pinned = 0 AND ts_recv < ? AND req_id != ''`, cutoff)
		if err != nil {
			return total, fmt.Errorf("列举待删样本 req_id: %w", err)
		}
		res, err := s.db.Exec(
			`DELETE FROM sample WHERE pinned = 0 AND ts_recv < ?`, cutoff)
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
			`SELECT req_id FROM sample WHERE pinned = 0 AND req_id != '' AND id NOT IN (
				SELECT id FROM sample WHERE pinned = 0 ORDER BY id DESC LIMIT ?)`, keepCount)
		if err != nil {
			return total, fmt.Errorf("列举待删样本 req_id: %w", err)
		}
		res, err := s.db.Exec(`DELETE FROM sample WHERE pinned = 0 AND id NOT IN (
			SELECT id FROM sample WHERE pinned = 0 ORDER BY id DESC LIMIT ?)`, keepCount)
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

// deleteRequestLogsForPrunedReqIDs 删除已无对应 sample 的 request_log。
// 仍有 sample 行的 req_id（例如置顶豁免）不会被删。
func (s *Store) deleteRequestLogsForPrunedReqIDs(reqIDs []string) error {
	for _, id := range reqIDs {
		if id == "" {
			continue
		}
		_, err := s.db.Exec(`DELETE FROM request_log WHERE req_id = ? AND NOT EXISTS (
			SELECT 1 FROM sample WHERE req_id = ?)`, id, id)
		if err != nil {
			return fmt.Errorf("清理已删样本的请求日志: %w", err)
		}
	}
	return nil
}

// sampleBodyDiskBytesSQL 是正文 BLOB 存盘字节合计表达式。
// 用 LENGTH(存盘列) 而不是解密后明文，才对得上实际占用的磁盘。
const sampleBodyDiskBytesSQL = `COALESCE(LENGTH(in_body),0)+COALESCE(LENGTH(out_body),0)+COALESCE(LENGTH(resp_body),0)`

// SampleDiskBytes 返回 sample 表正文 BLOB 的存盘字节合计。
func (s *Store) SampleDiskBytes() (int64, error) {
	var n sql.NullInt64
	err := s.db.QueryRow(`SELECT SUM(` + sampleBodyDiskBytesSQL + `) FROM sample`).Scan(&n)
	if err != nil {
		return 0, err
	}
	if !n.Valid {
		return 0, nil
	}
	return n.Int64, nil
}

func (s *Store) pruneSamplesByDiskQuota(maxBytes int64) (int64, error) {
	used, err := s.SampleDiskBytes()
	if err != nil {
		return 0, fmt.Errorf("统计样本磁盘: %w", err)
	}
	if used <= maxBytes {
		return 0, nil
	}

	rows, err := s.db.Query(`SELECT id, req_id, ` + sampleBodyDiskBytesSQL + ` AS sz
		FROM sample WHERE pinned = 0 ORDER BY id ASC`)
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
		res, err := s.db.Exec(`DELETE FROM sample WHERE id = ? AND pinned = 0`, v.id)
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

// CountSamples 返回样本总数，供 UI 展示。
func (s *Store) CountSamples() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM sample`).Scan(&n)
	return n, err
}

// ClearSamples 清空样本表（UI 的「一键清空」，§3.6.3d）。
// keepPinned 为 true 时保留置顶的。
func (s *Store) ClearSamples(keepPinned bool) (int64, error) {
	q := `DELETE FROM sample`
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

// MigrateSampleEnvelopes rewrites legacy plaintext sample body BLOBs into v1
// envelopes in place. Rows are never deleted; already-enveloped fields are left
// alone. Returns the number of rows that had at least one field rewritten.
func (s *Store) MigrateSampleEnvelopes() (int64, error) {
	if s.cipher == nil {
		return 0, fmt.Errorf("sample envelope migration requires Cipher")
	}
	rows, err := s.db.Query(`SELECT id, in_body, out_body, resp_body FROM sample`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	type row struct {
		id                     int64
		in, out, resp          []byte
		needIn, needOut, needR bool
	}
	var todo []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.in, &r.out, &r.resp); err != nil {
			return 0, err
		}
		r.needIn = len(r.in) > 0 && !IsSampleEnvelope(r.in)
		r.needOut = len(r.out) > 0 && !IsSampleEnvelope(r.out)
		r.needR = len(r.resp) > 0 && !IsSampleEnvelope(r.resp)
		if r.needIn || r.needOut || r.needR {
			todo = append(todo, r)
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	var migrated int64
	for _, r := range todo {
		in, out, resp := r.in, r.out, r.resp
		var err error
		if r.needIn {
			if in, err = s.cipher.EncryptSampleBlob(r.in); err != nil {
				return migrated, fmt.Errorf("encrypt sample %d in_body: %w", r.id, err)
			}
		}
		if r.needOut {
			if out, err = s.cipher.EncryptSampleBlob(r.out); err != nil {
				return migrated, fmt.Errorf("encrypt sample %d out_body: %w", r.id, err)
			}
		}
		if r.needR {
			if resp, err = s.cipher.EncryptSampleBlob(r.resp); err != nil {
				return migrated, fmt.Errorf("encrypt sample %d resp_body: %w", r.id, err)
			}
		}
		if _, err := s.db.Exec(`UPDATE sample SET in_body=?, out_body=?, resp_body=? WHERE id=?`,
			in, out, resp, r.id); err != nil {
			return migrated, fmt.Errorf("update sample %d: %w", r.id, err)
		}
		migrated++
	}
	return migrated, nil
}
