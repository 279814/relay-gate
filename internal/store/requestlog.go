package store

import (
	"fmt"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// InsertRequestLog 写入一次尝试的日志（M6，§3.5）。
//
// 调用方（sample.LogRecorder）已在后台单 goroutine 里，不必再考虑并发。
func (s *Store) InsertRequestLog(l *model.RequestLog) error {
	res, err := s.db.Exec(`INSERT INTO request_log (
		req_id, attempt, attempts,
		ts_recv, ts_sent, ts_first_byte, ts_done,
		endpoint, model_in, model_out, model_name_id, route_id, upstream_id, upstream_name,
		resp_status, ttft_ms, bytes_written,
		outcome, retried, half_open, error
	) VALUES (?,?,?, ?,?,?,?, ?,?,?,?,?,?,?, ?,?,?, ?,?,?,?)`,
		l.ReqID, l.Attempt, l.Attempts,
		l.TSRecv, l.TSSent, l.TSFirstByte, l.TSDone,
		l.Endpoint, l.ModelIn, l.ModelOut, l.ModelNameID, l.RouteID, l.UpstreamID, l.UpstreamName,
		l.RespStatus, l.TTFTMs, l.BytesWritten,
		string(l.Outcome), l.Retried, l.HalfOpen, l.Error)
	if err != nil {
		return fmt.Errorf("写入请求日志: %w", err)
	}
	l.ID, err = res.LastInsertId()
	return err
}

const requestLogCols = `id, req_id, attempt, attempts,
	ts_recv, ts_sent, ts_first_byte, ts_done,
	endpoint, model_in, model_out, model_name_id, route_id, upstream_id, upstream_name,
	resp_status, ttft_ms, bytes_written,
	outcome, retried, half_open, error`

func scanRequestLog(sc interface{ Scan(...any) error }) (*model.RequestLog, error) {
	var l model.RequestLog
	var outcome string
	if err := sc.Scan(&l.ID, &l.ReqID, &l.Attempt, &l.Attempts,
		&l.TSRecv, &l.TSSent, &l.TSFirstByte, &l.TSDone,
		&l.Endpoint, &l.ModelIn, &l.ModelOut, &l.ModelNameID, &l.RouteID,
		&l.UpstreamID, &l.UpstreamName,
		&l.RespStatus, &l.TTFTMs, &l.BytesWritten,
		&outcome, &l.Retried, &l.HalfOpen, &l.Error); err != nil {
		return nil, err
	}
	l.Outcome = model.Outcome(outcome)
	return &l, nil
}

// RequestLogFilter 是日志列表的筛选条件。零值表示不筛。
type RequestLogFilter struct {
	RouteID    int64
	UpstreamID int64
	Outcome    model.Outcome
	ReqID      string
	// OnlyRetried 只看被丢弃并换过站的尝试 —— 「重试实际发生过几次」
	// 是这张表最常被问的问题。
	OnlyRetried bool
	// OnlyFailed 只看没成功的（outcome != ok）。
	OnlyFailed bool
	Limit      int
	// BeforeID 游标式翻页。日志表只增不改，用 id 游标比 OFFSET 稳 ——
	// OFFSET 在翻页期间有新日志写入时会漏记录。
	BeforeID int64
}

const (
	defaultRequestLogLimit = 100
	maxRequestLogLimit     = 1000
)

// ListRequestLogs 按时间倒序列出日志。
//
// 日志行本身只有元数据（没有 body），所以这里返回完整行 ——
// 与 ListSamples 需要裁掉 body 的情形不同。
func (s *Store) ListRequestLogs(f RequestLogFilter) ([]*model.RequestLog, error) {
	q := `SELECT ` + requestLogCols + ` FROM request_log WHERE 1=1`
	args := []any{}
	if f.RouteID > 0 {
		q += ` AND route_id = ?`
		args = append(args, f.RouteID)
	}
	if f.UpstreamID > 0 {
		q += ` AND upstream_id = ?`
		args = append(args, f.UpstreamID)
	}
	if f.Outcome != "" {
		q += ` AND outcome = ?`
		args = append(args, string(f.Outcome))
	}
	if f.ReqID != "" {
		q += ` AND req_id = ?`
		args = append(args, f.ReqID)
	}
	if f.OnlyRetried {
		q += ` AND retried = 1`
	}
	if f.OnlyFailed {
		q += ` AND outcome != ?`
		args = append(args, string(model.OutcomeOK))
	}
	if f.BeforeID > 0 {
		q += ` AND id < ?`
		args = append(args, f.BeforeID)
	}

	// 超上限则**截到上限**而不是掉回默认值 —— 后者会让 limit=5000
	// 拿到 100 条，而翻页逻辑据此以为「到底了」。
	limit := f.Limit
	switch {
	case limit <= 0:
		limit = defaultRequestLogLimit
	case limit > maxRequestLogLimit:
		limit = maxRequestLogLimit
	}

	// 按 req_id 查整组时按 attempt 升序：详情页要的是「第 1 次试了 A、
	// 第 2 次试了 B」这个顺序，倒序读起来是反的。
	if f.ReqID != "" {
		q += ` ORDER BY attempt ASC LIMIT ?`
	} else {
		q += ` ORDER BY id DESC LIMIT ?`
	}
	args = append(args, limit)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*model.RequestLog{}
	for rows.Next() {
		l, err := scanRequestLog(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// PruneRequestLogs 按条数与天数清理，两者取**先到者**。
//
// keepCount / keepDays <= 0 表示该维度不限。
//
// 与样本不同，日志没有 pinned：单行日志离开它那一组就没什么意义，
// 而按组置顶会让「保留 N 条」变成一个无法预估的数字。要留证据就置顶样本。
func (s *Store) PruneRequestLogs(keepCount, keepDays int) (int64, error) {
	var total int64

	if keepDays > 0 {
		cutoff := time.Now().Add(-time.Duration(keepDays) * 24 * time.Hour).UnixMilli()
		res, err := s.db.Exec(`DELETE FROM request_log WHERE ts_recv < ?`, cutoff)
		if err != nil {
			return total, fmt.Errorf("按天数清理请求日志: %w", err)
		}
		n, _ := res.RowsAffected()
		total += n
	}

	if keepCount > 0 {
		// 按 req_id 整组保留，而不是按行 —— 按行截会把一次重试的
		// 后半截切掉，于是详情页显示「第 2、3 次尝试」而没有第 1 次，
		// 看起来像数据坏了。
		res, err := s.db.Exec(`DELETE FROM request_log WHERE req_id NOT IN (
			SELECT req_id FROM (
				SELECT req_id, MAX(id) AS mx FROM request_log
				GROUP BY req_id ORDER BY mx DESC LIMIT ?))`, keepCount)
		if err != nil {
			return total, fmt.Errorf("按条数清理请求日志: %w", err)
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

// CountRequestLogs 返回日志行数，供 UI 展示。
func (s *Store) CountRequestLogs() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM request_log`).Scan(&n)
	return n, err
}

// ClearRequestLogs 清空日志表（UI 的「一键清空」）。
func (s *Store) ClearRequestLogs() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM request_log`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RetryStats 是重试效果的汇总，回答「重试到底有没有用」。
//
// 这是 request_log 这张表存在的理由：没有它，「换站重试」是否值得就只能
// 靠感觉 —— 而它的代价是实打实的（每次重试都在别人的站上真花一次额度）。
type RetryStats struct {
	// Requests 是客户端请求数（按 req_id 去重），不是尝试数。
	Requests int64 `json:"requests"`
	// Attempts 是总尝试数。Attempts - Requests 就是额外花掉的上游调用数。
	Attempts int64 `json:"attempts"`
	// Retried 是**发生过**重试的客户端请求数（attempts > 1）。
	Retried int64 `json:"retried"`
	// RescuedByRetry 是「首次失败但最终成功」的请求数 —— 重试真正救回来的那些。
	RescuedByRetry int64 `json:"rescued_by_retry"`
	// FailedAfterRetry 是重试过但最终仍失败的请求数。
	// 这个数偏高说明该换的是配置而不是再多试一次。
	FailedAfterRetry int64 `json:"failed_after_retry"`
}

// RetryStatsSince 汇总最近 sinceHours 小时的重试效果。sinceHours <= 0 表示全部。
func (s *Store) RetryStatsSince(sinceHours int) (*RetryStats, error) {
	where := ``
	args := []any{}
	if sinceHours > 0 {
		cutoff := time.Now().Add(-time.Duration(sinceHours) * time.Hour).UnixMilli()
		where = ` WHERE ts_recv >= ?`
		args = append(args, cutoff)
	}

	// 一条查询算完五个数：先把每组折叠成一行（组内的尝试数、最大尝试号、
	// 以及最后一次尝试的 outcome），再对这些行做计数。
	//
	// 分五条查询跑的话，每条都要重扫一遍表，而且五个数可能来自不同时刻的
	// 快照 —— 于是出现「救回来的比重试过的还多」这种不自洽的展示。
	q := `WITH grp AS (
		SELECT req_id,
		       COUNT(*) AS n,
		       MAX(attempt) AS last_attempt,
		       SUM(CASE WHEN outcome = 'ok' THEN 1 ELSE 0 END) AS oks
		FROM request_log` + where + `
		GROUP BY req_id
	)
	SELECT COUNT(*), COALESCE(SUM(n), 0),
	       COALESCE(SUM(CASE WHEN n > 1 THEN 1 ELSE 0 END), 0),
	       COALESCE(SUM(CASE WHEN n > 1 AND oks > 0 THEN 1 ELSE 0 END), 0),
	       COALESCE(SUM(CASE WHEN n > 1 AND oks = 0 THEN 1 ELSE 0 END), 0)
	FROM grp`

	var st RetryStats
	err := s.db.QueryRow(q, args...).Scan(&st.Requests, &st.Attempts,
		&st.Retried, &st.RescuedByRetry, &st.FailedAfterRetry)
	if err != nil {
		return nil, fmt.Errorf("汇总重试统计: %w", err)
	}
	return &st, nil
}
