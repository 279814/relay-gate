package store

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// RecentErrorFilter selects failed attempts using only recorded metadata.
// Time bounds are inclusive Unix milliseconds of the incoming request.
type RecentErrorFilter struct {
	model.PageRequest
	UpstreamID int64
	RouteID    int64
	Protocol   model.Protocol
	Outcome    model.Outcome
	FromMS     int64
	ToMS       int64
}

type RecentError struct {
	*model.RequestLog
	SampleID     int64              `json:"sample_id,omitempty"`
	Protocol     model.Protocol     `json:"protocol,omitempty"`
	EndpointKind model.EndpointKind `json:"endpoint_kind,omitempty"`
}

type RecentErrorPage struct {
	Logs        []RecentError `json:"logs"`
	FailedCount int64         `json:"failed_count"`
	NextCursor  string        `json:"next_cursor"`
}

// ListRecentErrors uses one read transaction for count, keyset page and exact
// sample IDs. It never reads sample ciphertext, business text or credentials.
func (s *Store) ListRecentErrors(ctx context.Context, f RecentErrorFilter) (RecentErrorPage, error) {
	page := RecentErrorPage{Logs: []RecentError{}}
	limit, err := normalizePageLimit(f.Limit)
	if err != nil {
		return page, err
	}
	if f.UpstreamID < 0 || f.RouteID < 0 || f.FromMS < 0 || f.ToMS < 0 ||
		(f.FromMS > 0 && f.ToMS > 0 && f.FromMS > f.ToMS) ||
		(f.Protocol != "" && !f.Protocol.Valid()) ||
		(f.Outcome != "" && (!f.Outcome.Valid() || f.Outcome == model.OutcomeOK)) {
		return page, model.WrapValidation("最近错误筛选无效")
	}
	cursorFilter := f
	cursorFilter.PageRequest = model.PageRequest{}
	keys, err := decodePageCursor(f.Cursor, "recent-errors", cursorFilter, 1)
	if err != nil {
		return page, err
	}
	where := `outcome <> ?`
	args := []any{model.OutcomeOK}
	if f.UpstreamID > 0 {
		where += ` AND upstream_id=?`
		args = append(args, f.UpstreamID)
	}
	if f.RouteID > 0 {
		where += ` AND route_id=?`
		args = append(args, f.RouteID)
	}
	if f.Protocol != "" {
		where += ` AND endpoint=?`
		args = append(args, f.Protocol.Path())
	}
	if f.Outcome != "" {
		where += ` AND outcome=?`
		args = append(args, f.Outcome)
	}
	if f.FromMS > 0 {
		where += ` AND ts_recv>=?`
		args = append(args, f.FromMS)
	}
	if f.ToMS > 0 {
		where += ` AND ts_recv<=?`
		args = append(args, f.ToMS)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return page, err
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM request_log WHERE `+where, args...).Scan(&page.FailedCount); err != nil {
		return page, err
	}
	if len(keys) > 0 {
		id, err := cursorID(keys[0])
		if err != nil {
			return page, err
		}
		where += ` AND id<?`
		args = append(args, id)
	}
	args = append(args, limit+1)
	rows, err := tx.QueryContext(ctx, `SELECT `+requestLogCols+` FROM request_log WHERE `+where+` ORDER BY id DESC LIMIT ?`, args...)
	if err != nil {
		return page, err
	}
	for rows.Next() {
		log, err := scanRequestLog(rows)
		if err != nil {
			rows.Close()
			return page, err
		}
		row := RecentError{RequestLog: log}
		for _, protocol := range []model.Protocol{model.ProtoAnthropic, model.ProtoOpenAIResponses, model.ProtoOpenAIChat} {
			if log.Endpoint == protocol.Path() {
				row.Protocol = protocol
				row.EndpointKind, _ = protocol.Endpoint()
				break
			}
		}
		page.Logs = append(page.Logs, row)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return page, err
	}
	if len(page.Logs) > limit {
		page.Logs = page.Logs[:limit]
		page.NextCursor, err = encodePageCursor("recent-errors", cursorFilter, strconv.FormatInt(page.Logs[len(page.Logs)-1].ID, 10))
		if err != nil {
			return page, err
		}
	}
	// One bounded metadata query handles the page, avoiding a per-row lookup.
	reqIDs := map[string]bool{}
	var sampleArgs []any
	for _, row := range page.Logs {
		if row.ReqID != "" && !reqIDs[row.ReqID] {
			reqIDs[row.ReqID] = true
			sampleArgs = append(sampleArgs, row.ReqID)
		}
	}
	if len(sampleArgs) > 0 {
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(sampleArgs)), ",")
		rows, err = tx.QueryContext(ctx, `SELECT req_id,MIN(id) FROM sample_request WHERE req_id IN (`+placeholders+`) GROUP BY req_id`, sampleArgs...)
		if err != nil {
			return page, err
		}
		samples := map[string]int64{}
		for rows.Next() {
			var reqID string
			var id int64
			if err := rows.Scan(&reqID, &id); err != nil {
				rows.Close()
				return page, err
			}
			samples[reqID] = id
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return page, err
		}
		for i := range page.Logs {
			page.Logs[i].SampleID = samples[page.Logs[i].ReqID]
		}
	}
	if err := tx.Commit(); err != nil {
		return page, err
	}
	return page, nil
}

// InsertRequestLog 写入一次尝试的日志（M6，§3.5）。
//
// 调用方（sample.LogRecorder）已在后台单 goroutine 里，不必再考虑并发。
func (s *Store) InsertRequestLog(l *model.RequestLog) error {
	res, err := s.db.Exec(`INSERT INTO request_log (
		req_id, attempt, attempts,
		ts_recv, ts_sent, ts_first_byte, ts_done,
		endpoint, model_in, model_out, model_name_id, route_id, upstream_id, upstream_name,
		resp_status, ttft_ms, bytes_written,
		outcome, retried, half_open, error, duplicate_risk, retry_reason
	) VALUES (?,?,?, ?,?,?,?, ?,?,?,?,?,?,?, ?,?,?, ?,?,?,?,?,?)`,
		l.ReqID, l.Attempt, l.Attempts,
		l.TSRecv, l.TSSent, l.TSFirstByte, l.TSDone,
		l.Endpoint, l.ModelIn, l.ModelOut, l.ModelNameID, l.RouteID, l.UpstreamID, l.UpstreamName,
		l.RespStatus, l.TTFTMs, l.BytesWritten,
		string(l.Outcome), l.Retried, l.HalfOpen, l.Error, l.DuplicateRisk, l.RetryReason)
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
	outcome, retried, half_open, error, duplicate_risk, COALESCE(retry_reason,'')`

func scanRequestLog(sc interface{ Scan(...any) error }) (*model.RequestLog, error) {
	var l model.RequestLog
	var outcome string
	if err := sc.Scan(&l.ID, &l.ReqID, &l.Attempt, &l.Attempts,
		&l.TSRecv, &l.TSSent, &l.TSFirstByte, &l.TSDone,
		&l.Endpoint, &l.ModelIn, &l.ModelOut, &l.ModelNameID, &l.RouteID,
		&l.UpstreamID, &l.UpstreamName,
		&l.RespStatus, &l.TTFTMs, &l.BytesWritten,
		&outcome, &l.Retried, &l.HalfOpen, &l.Error, &l.DuplicateRisk, &l.RetryReason); err != nil {
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

// ListRequestLogs 按时间倒序列出日志。
//
// 日志行本身只有元数据（没有 body），所以这里返回完整行 ——
// 与 ListSamples 需要裁掉 body 的情形不同。
func (s *Store) ListRequestLogs(f RequestLogFilter) ([]*model.RequestLog, error) {
	limit, err := NormalizePageLimit(f.Limit)
	if err != nil {
		return nil, err
	}

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

// PruneRequestLogs 按条数与天数清理**无对应 sample 的孤儿日志**，两者取**先到者**。
//
// keepCount / keepDays <= 0 表示该维度不限。
//
// §5.4：request_log 属于 Sample Group，文档未给日志单独更短寿命；
// 仍有 sample 行的 req_id 不得在这里删掉（置顶样本同理）。无样本的独立
// 日志才按 keep 滚动。与样本不同，孤儿日志没有 pinned：单行离开整组就
// 没什么意义，要留证据就置顶样本。
func (s *Store) PruneRequestLogs(keepCount, keepDays int) (int64, error) {
	var total int64
	const orphanOnly = `NOT EXISTS (SELECT 1 FROM sample_request WHERE sample_request.req_id = request_log.req_id)`

	if keepDays > 0 {
		cutoff := time.Now().Add(-time.Duration(keepDays) * 24 * time.Hour).UnixMilli()
		res, err := s.db.Exec(
			`DELETE FROM request_log WHERE ts_recv < ? AND `+orphanOnly, cutoff)
		if err != nil {
			return total, fmt.Errorf("按天数清理请求日志: %w", err)
		}
		n, _ := res.RowsAffected()
		total += n
	}

	if keepCount > 0 {
		// 只对孤儿按 req_id 整组保留 —— 按行截会把一次重试的后半截切掉；
		// 有 sample 的组一律不动。
		res, err := s.db.Exec(`DELETE FROM request_log WHERE `+orphanOnly+` AND req_id NOT IN (
			SELECT req_id FROM (
				SELECT request_log.req_id AS req_id, MAX(request_log.id) AS mx
				FROM request_log
				WHERE `+orphanOnly+`
				GROUP BY request_log.req_id ORDER BY mx DESC LIMIT ?))`, keepCount)
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

	// 一条查询算完五个数：先把每组折叠成一行（组内的行数、这次请求实际的
	// 总尝试次数、以及有没有哪次尝试成功了），再对这些行做计数。
	//
	// 分五条查询跑的话，每条都要重扫一遍表，而且五个数可能来自不同时刻的
	// 快照 —— 于是出现「救回来的比重试过的还多」这种不自洽的展示。
	//
	// 判「重试过」用 MAX(attempts) 而不是 COUNT(*)：日志队列满时会丢行
	// （§3.7 明说了这一点，丢弃数也因此暴露在 runtime 里）。靠 COUNT(*) 数的话，
	// 一次三连重试只落库了最后一行时会被数成「1 次尝试、没重试过」——
	// 而那一行明明如实记着 attempts=3。于是**恰恰在丢日志的高负载时段**，
	// 重试的效果被系统性低估，而这张表存在的理由就是度量那个效果。
	//
	// attempts 列的冗余（同组内恒定）正是为这种情形准备的，见 0001_legacy.sql。
	// SUM(n) 仍是「实际记下来几次」，它偏低无解也无妨 —— 那个数问的是
	// 「留下了多少行」，不是「发生过多少次」。
	q := `WITH grp AS (
		SELECT req_id,
		       COUNT(*) AS n,
		       MAX(attempts) AS tries,
		       SUM(CASE WHEN outcome = 'ok' THEN 1 ELSE 0 END) AS oks
		FROM request_log` + where + `
		GROUP BY req_id
	)
	SELECT COUNT(*), COALESCE(SUM(n), 0),
	       COALESCE(SUM(CASE WHEN tries > 1 THEN 1 ELSE 0 END), 0),
	       COALESCE(SUM(CASE WHEN tries > 1 AND oks > 0 THEN 1 ELSE 0 END), 0),
	       COALESCE(SUM(CASE WHEN tries > 1 AND oks = 0 THEN 1 ELSE 0 END), 0)
	FROM grp`

	var st RetryStats
	err := s.db.QueryRow(q, args...).Scan(&st.Requests, &st.Attempts,
		&st.Retried, &st.RescuedByRetry, &st.FailedAfterRetry)
	if err != nil {
		return nil, fmt.Errorf("汇总重试统计: %w", err)
	}
	return &st, nil
}
