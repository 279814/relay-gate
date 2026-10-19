package api

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/sample"
	"github.com/279814/relay-gate/internal/store"
)

// listRequestLogs 返回请求日志（M6）。
//
// 与样本列表的分工：样本回答「发出去的是哪些字节」，日志回答「这次请求
// 经历了什么」—— 试了几个站、每个站怎么失败的、最后有没有救回来。
func (s *Server) listRequestLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	var qerr error
	num := func(name string) int64 {
		n, err := queryInt64(q.Get(name))
		if err != nil && qerr == nil {
			qerr = fmt.Errorf("%w: 参数 %s 不是合法整数：%q",
				model.ErrValidation, name, q.Get(name))
		}
		return n
	}
	f := store.RequestLogFilter{
		RouteID:    num("route_id"),
		UpstreamID: num("upstream_id"),
		Outcome:    model.Outcome(q.Get("outcome")),
		ReqID:      q.Get("req_id"),
		// 两个是**不同**的问题：only_retried 问「实际换过站的」，
		// only_failed 问「没成功的」。一次失败但无站可换的请求只命中后者。
		OnlyRetried: q.Get("only_retried") == "true",
		OnlyFailed:  q.Get("only_failed") == "true",
		Limit:       int(num("limit")),
		BeforeID:    num("before_id"),
	}
	// 参数写错了要说出来。静默当成 0 的话，?before_id=abc 会从头开始返回，
	// 看着像「翻页转了一圈」，而真正的原因是那个 typo。
	if qerr != nil {
		s.writeErr(w, qerr)
		return
	}
	if f.Outcome != "" && !f.Outcome.Valid() {
		s.writeErr(w, fmt.Errorf("%w: 未知的 outcome：%q",
			model.ErrValidation, f.Outcome))
		return
	}
	pageLimit, err := store.NormalizePageLimit(f.Limit)
	if err != nil {
		s.writeErr(w, fmt.Errorf("%w: %v", model.ErrValidation, err))
		return
	}
	f.Limit = pageLimit

	list, err := s.st.ListRequestLogs(f)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	total, err := s.st.CountRequestLogs()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	keys, ok := s.diagnosticKeys(w, r)
	if !ok {
		return
	}
	for _, row := range list {
		redactRequestLog(row, keys)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"logs": list, "total": total})
}

// recentErrors is the P2 home summary + modal feed (§13.2).
// Plain-text errors only; reuses failed request_log rows.
func (s *Server) recentErrors(w http.ResponseWriter, r *http.Request) {
	q := &probeListQuery{r: r}
	for name := range r.URL.Query() {
		switch name {
		case "limit", "cursor", "upstream_id", "route_id", "protocol", "outcome", "from_ms", "to_ms":
		default:
			q.err = model.WrapValidation("最近错误含未知筛选参数")
		}
	}
	f := store.RecentErrorFilter{PageRequest: q.page(), UpstreamID: q.id("upstream_id"), RouteID: q.id("route_id"),
		Protocol: probeEnum(q, "protocol", model.Protocol.Valid),
		Outcome:  model.Outcome(q.oneOf("outcome", string(model.OutcomeUpstreamError), string(model.OutcomeTimeout), string(model.OutcomeFakeAlive), string(model.OutcomeClientAbort)))}
	millis := func(name string) int64 {
		raw := q.text(name)
		if _, present := r.URL.Query()[name]; !present {
			return 0
		}
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 1 || n > 253402300799999 {
			q.reject(name)
			return 0
		}
		return n
	}
	f.FromMS, f.ToMS = millis("from_ms"), millis("to_ms")
	if len(f.Cursor) > 4096 {
		q.reject("cursor")
	}
	if f.FromMS > 0 && f.ToMS > 0 && f.FromMS > f.ToMS {
		q.reject("time")
	}
	if q.err != nil {
		s.writeErr(w, q.err)
		return
	}
	page, err := s.st.ListRecentErrors(r.Context(), f)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	keys, ok := s.diagnosticKeys(w, r)
	if !ok {
		return
	}
	for _, row := range page.Logs {
		redactRequestLog(row.RequestLog, keys)
	}
	var latest any
	if len(page.Logs) > 0 {
		row := page.Logs[0]
		latest = map[string]any{"id": row.ID, "error": row.Error, "ts_recv": row.TSRecv, "upstream": row.UpstreamName, "endpoint": row.Endpoint, "model_in": row.ModelIn}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"failed_count": page.FailedCount, "latest": latest, "logs": page.Logs, "next_cursor": page.NextCursor})
}

func redactRequestLog(row *model.RequestLog, keys []string) {
	row.Error = sample.RedactDiagnosticText(row.Error, keys)
	row.RetryReason = sample.RedactDiagnosticText(row.RetryReason, keys)
	row.UpstreamName = sample.RedactDiagnosticText(row.UpstreamName, keys)
	row.ModelIn = sample.RedactDiagnosticText(row.ModelIn, keys)
	row.ModelOut = sample.RedactDiagnosticText(row.ModelOut, keys)
	row.ReqID = sample.RedactDiagnosticText(row.ReqID, keys)
	row.Endpoint = sample.RedactDiagnosticText(row.Endpoint, keys)
}

// getRetryStats 汇总重试效果（M6）。
//
// 这是整个 request_log 表存在的理由：没有它，「换站重试」值不值得就只能
// 靠感觉 —— 而它的代价是实打实的（每次重试都在别人的站上真花一次额度）。
//
// hours 默认 24。给 0 表示全部历史 —— 但那个数字会被开服头几天的配置
// 错误永久污染，所以不做默认。
func (s *Server) getRetryStats(w http.ResponseWriter, r *http.Request) {
	hours, err := queryInt64(r.URL.Query().Get("hours"))
	if err != nil {
		s.writeErr(w, fmt.Errorf("%w: 参数 hours 不是合法整数：%q",
			model.ErrValidation, r.URL.Query().Get("hours")))
		return
	}
	if r.URL.Query().Get("hours") == "" {
		hours = 24
	}

	st, err := s.st.RetryStatsSince(int(hours))
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"stats": st, "hours": hours})
}

// clearRequestLogs 是 UI 的「一键清空」。
//
// 没有 keep_pinned 的对应物：日志没有置顶。单行日志离开它那一组就没什么
// 意义，而按组置顶会让「保留 N 条」变成一个无法预估的数字。
// 要留证据就置顶样本 —— 它们靠 req_id 关联得上。
func (s *Server) clearRequestLogs(w http.ResponseWriter, r *http.Request) {
	n, err := s.st.ClearRequestLogs()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.log.Info("清空请求日志", "deleted", n)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": n})
}
