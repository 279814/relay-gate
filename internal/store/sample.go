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
func (s *Store) InsertSample(smp *model.Sample) error {
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
		smp.InMethod, smp.InPath, smp.InQuery, inH, smp.InBody,
		smp.OutURL, outH, smp.OutBody,
		smp.RespStatus, respH, smp.RespBody,
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

func scanSample(sc interface{ Scan(...any) error }) (*model.Sample, error) {
	var s model.Sample
	var inH, outH, respH string
	var outcome string
	var trunc int
	if err := sc.Scan(&s.ID, &s.ReqID, &s.TSRecv, &s.TSSent, &s.TSFirstByte, &s.TSDone,
		&s.Endpoint, &s.ModelIn, &s.ModelOut, &s.ModelNameID, &s.RouteID, &s.UpstreamID,
		&s.InMethod, &s.InPath, &s.InQuery, &inH, &s.InBody,
		&s.OutURL, &outH, &s.OutBody,
		&s.RespStatus, &respH, &s.RespBody,
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
	smp, err := scanSample(row)
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

// PruneSamples 按条数与天数清理，两者取**先到者**（§3.6.3c）。pinned 豁免。
//
// keepCount / keepDays <= 0 表示该维度不限。
func (s *Store) PruneSamples(keepCount, keepDays int) (int64, error) {
	var total int64

	if keepDays > 0 {
		cutoff := time.Now().Add(-time.Duration(keepDays) * 24 * time.Hour).UnixMilli()
		res, err := s.db.Exec(
			`DELETE FROM sample WHERE pinned = 0 AND ts_recv < ?`, cutoff)
		if err != nil {
			return total, fmt.Errorf("按天数清理样本: %w", err)
		}
		n, _ := res.RowsAffected()
		total += n
	}

	if keepCount > 0 {
		// 只数未置顶的：置顶的不参与清理，把它们算进配额会导致
		// 置顶几条就把正常样本挤掉，越用越少。
		res, err := s.db.Exec(`DELETE FROM sample WHERE pinned = 0 AND id NOT IN (
			SELECT id FROM sample WHERE pinned = 0 ORDER BY id DESC LIMIT ?)`, keepCount)
		if err != nil {
			return total, fmt.Errorf("按条数清理样本: %w", err)
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
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
