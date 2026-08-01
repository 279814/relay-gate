package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

// 请求日志与重试统计的 REST 端点（M6）。
//
// 这一组盯的是**统计的可信度**。一个错的统计数字比没有统计更糟 ——
// 它会被拿去做「要不要保留重试」这类决定，而没人会怀疑一个显示得
// 有模有样的百分比。

// seedLogs 往库里塞一组典型的日志：
//   - a：一次过成功
//   - b：重试救回来了（第 1 次 502，第 2 次成功）
//   - c：重试也没救回来（两次都超时）
//   - d：失败但没重试（401，不可重试）
func seedLogs(t *testing.T, s *Server) {
	t.Helper()
	rows := []*model.RequestLog{
		{ReqID: "a", Attempt: 1, Attempts: 1, TSRecv: 1000,
			Endpoint: "/v1/messages", RouteID: 100, UpstreamID: 10,
			UpstreamName: "st0", RespStatus: 200, Outcome: model.OutcomeOK},

		{ReqID: "b", Attempt: 1, Attempts: 2, TSRecv: 2000,
			Endpoint: "/v1/messages", RouteID: 100, UpstreamID: 10,
			UpstreamName: "st0", RespStatus: 502, Retried: true,
			Outcome: model.OutcomeUpstreamError, Error: "HTTP 502"},
		{ReqID: "b", Attempt: 2, Attempts: 2, TSRecv: 2000,
			Endpoint: "/v1/messages", RouteID: 200, UpstreamID: 20,
			UpstreamName: "st1", RespStatus: 200, Outcome: model.OutcomeOK},

		{ReqID: "c", Attempt: 1, Attempts: 2, TSRecv: 3000,
			Endpoint: "/v1/messages", RouteID: 100, UpstreamID: 10,
			UpstreamName: "st0", Retried: true, Outcome: model.OutcomeTimeout},
		{ReqID: "c", Attempt: 2, Attempts: 2, TSRecv: 3000,
			Endpoint: "/v1/messages", RouteID: 200, UpstreamID: 20,
			UpstreamName: "st1", Outcome: model.OutcomeTimeout},

		{ReqID: "d", Attempt: 1, Attempts: 1, TSRecv: 4000,
			Endpoint: "/v1/messages", RouteID: 100, UpstreamID: 10,
			UpstreamName: "st0", RespStatus: 401,
			Outcome: model.OutcomeUpstreamError},
	}
	for _, l := range rows {
		if err := s.st.InsertRequestLog(l); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAPI_ListRequestLogs(t *testing.T) {
	s, h := newTestServer(t)
	seedLogs(t, s)

	rec := do(t, h, "GET", "/admin/api/request-logs", "", true)
	if rec.Code != 200 {
		t.Fatalf("应 200，得到 %d：%s", rec.Code, rec.Body.String())
	}

	var got struct {
		Logs  []*model.RequestLog `json:"logs"`
		Total int64               `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Logs) != 6 {
		t.Errorf("应返回 6 行，得到 %d", len(got.Logs))
	}
	if got.Total != 6 {
		t.Errorf("total 应为 6，得到 %d", got.Total)
	}
	// 最新在前
	if got.Logs[0].ReqID != "d" {
		t.Errorf("应最新在前，首行是 %q", got.Logs[0].ReqID)
	}
}

// 按 req_id 取整组，且按 attempt **升序** ——
// 详情页要的是「第 1 次试了 A、第 2 次试了 B」这个顺序。
func TestAPI_ListRequestLogsByReqID(t *testing.T) {
	s, h := newTestServer(t)
	seedLogs(t, s)

	rec := do(t, h, "GET", "/admin/api/request-logs?req_id=b", "", true)
	if rec.Code != 200 {
		t.Fatalf("应 200，得到 %d", rec.Code)
	}
	var got struct {
		Logs []*model.RequestLog `json:"logs"`
	}
	json.Unmarshal(rec.Body.Bytes(), &got)

	if len(got.Logs) != 2 {
		t.Fatalf("req_id=b 应有 2 行，得到 %d", len(got.Logs))
	}
	if got.Logs[0].Attempt != 1 || got.Logs[1].Attempt != 2 {
		t.Errorf("应按 attempt 升序，得到 %d、%d",
			got.Logs[0].Attempt, got.Logs[1].Attempt)
	}
	// 两次尝试打的是不同的站 —— 这正是详情页要展示的东西
	if got.Logs[0].UpstreamName == got.Logs[1].UpstreamName {
		t.Error("两次尝试应记录不同的站名")
	}
}

// only_retried 与 only_failed 是**不同**的问题。
//
// 混为一谈的话，「401 直接返回」会被算成一次重试失败，
// 让重试的效果看起来比实际差。
func TestAPI_RequestLogFilters(t *testing.T) {
	s, h := newTestServer(t)
	seedLogs(t, s)

	cases := []struct {
		query string
		want  int
		why   string
	}{
		{"outcome=ok", 2, "a 与 b 的第二次"},
		{"route_id=200", 2, "b 与 c 的第二次尝试"},
		{"upstream_id=10", 4, "st0 收到的全部尝试"},
		{"only_retried=true", 2, "b#1 与 c#1 换过站"},
		{"only_failed=true", 4, "两次超时 + 502 + 401"},
		// 组合筛选：既失败又换过站
		{"only_retried=true&only_failed=true", 2, "b#1 与 c#1"},
	}
	for _, c := range cases {
		t.Run(c.query, func(t *testing.T) {
			rec := do(t, h, "GET", "/admin/api/request-logs?"+c.query, "", true)
			if rec.Code != 200 {
				t.Fatalf("应 200，得到 %d：%s", rec.Code, rec.Body.String())
			}
			var got struct {
				Logs []*model.RequestLog `json:"logs"`
			}
			json.Unmarshal(rec.Body.Bytes(), &got)
			if len(got.Logs) != c.want {
				t.Errorf("应返回 %d 行（%s），得到 %d", c.want, c.why, len(got.Logs))
			}
		})
	}
}

// 参数写错要明确报错，不能静默当成 0。
//
// 静默的话 ?before_id=abc 会从头开始返回，看着像「翻页转了一圈」，
// 而真正的原因是那个 typo。
func TestAPI_RequestLogRejectsBadParams(t *testing.T) {
	_, h := newTestServer(t)

	cases := []string{
		"before_id=abc",
		"limit=xyz",
		"route_id=1.5",
		"outcome=nonsense",
	}
	for _, q := range cases {
		t.Run(q, func(t *testing.T) {
			rec := do(t, h, "GET", "/admin/api/request-logs?"+q, "", true)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("应回 400，得到 %d：%s", rec.Code, rec.Body.String())
			}
		})
	}
}

// 重试统计的五个数必须自洽 ——
// 「救回来的比重试过的还多」这种展示会让人立刻不再相信整个界面。
func TestAPI_RetryStats(t *testing.T) {
	s, h := newTestServer(t)
	seedLogs(t, s)

	// hours=0 表示全部历史（种子数据的时间戳是 1970 年附近的小整数）
	rec := do(t, h, "GET", "/admin/api/retry-stats?hours=0", "", true)
	if rec.Code != 200 {
		t.Fatalf("应 200，得到 %d：%s", rec.Code, rec.Body.String())
	}

	var got struct {
		Stats struct {
			Requests         int64 `json:"requests"`
			Attempts         int64 `json:"attempts"`
			Retried          int64 `json:"retried"`
			RescuedByRetry   int64 `json:"rescued_by_retry"`
			FailedAfterRetry int64 `json:"failed_after_retry"`
		} `json:"stats"`
		Hours int64 `json:"hours"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}

	st := got.Stats
	if st.Requests != 4 {
		t.Errorf("客户端请求数应为 4，得到 %d", st.Requests)
	}
	if st.Attempts != 6 {
		t.Errorf("总尝试数应为 6，得到 %d", st.Attempts)
	}
	// d 失败了但没重试，不算进 retried
	if st.Retried != 2 {
		t.Errorf("重试过的请求数应为 2（b 与 c），得到 %d", st.Retried)
	}
	if st.RescuedByRetry != 1 {
		t.Errorf("重试救回来的应为 1（只有 b），得到 %d", st.RescuedByRetry)
	}
	if st.FailedAfterRetry != 1 {
		t.Errorf("重试后仍失败的应为 1（只有 c），得到 %d", st.FailedAfterRetry)
	}
	if st.RescuedByRetry+st.FailedAfterRetry != st.Retried {
		t.Errorf("统计不自洽：%d + %d != %d",
			st.RescuedByRetry, st.FailedAfterRetry, st.Retried)
	}
}

// 不传 hours 时默认 24 小时。
//
// 默认全部历史的话，那个数字会被开服头几天的配置错误永久污染 ——
// 而一个永远不会变好的比例，看它做不出任何决定。
func TestAPI_RetryStatsDefaultsTo24Hours(t *testing.T) {
	s, h := newTestServer(t)
	seedLogs(t, s) // 种子数据的 ts 是 1970 年，落在 24 小时窗口之外

	rec := do(t, h, "GET", "/admin/api/retry-stats", "", true)
	if rec.Code != 200 {
		t.Fatalf("应 200，得到 %d", rec.Code)
	}
	var got struct {
		Stats struct {
			Requests int64 `json:"requests"`
		} `json:"stats"`
		Hours int64 `json:"hours"`
	}
	json.Unmarshal(rec.Body.Bytes(), &got)

	if got.Hours != 24 {
		t.Errorf("默认应为 24 小时，得到 %d", got.Hours)
	}
	if got.Stats.Requests != 0 {
		t.Errorf("1970 年的数据不该落在最近 24 小时里，得到 %d", got.Stats.Requests)
	}
}

// 空库要返回零值统计，不能 500 也不能返回 null —— UI 一开就会调它。
func TestAPI_RetryStatsOnEmptyDB(t *testing.T) {
	_, h := newTestServer(t)

	rec := do(t, h, "GET", "/admin/api/retry-stats", "", true)
	if rec.Code != 200 {
		t.Fatalf("空库不该报错，得到 %d：%s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got["stats"] == nil {
		t.Error("应返回零值统计对象而不是 null —— 前端会直接读它的字段")
	}
}

func TestAPI_ClearRequestLogs(t *testing.T) {
	s, h := newTestServer(t)
	seedLogs(t, s)

	rec := do(t, h, "DELETE", "/admin/api/request-logs", "", true)
	if rec.Code != 200 {
		t.Fatalf("应 200，得到 %d", rec.Code)
	}
	var got struct {
		Deleted int64 `json:"deleted"`
	}
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Deleted != 6 {
		t.Errorf("应清掉 6 行，得到 %d", got.Deleted)
	}

	// 真的清干净了
	rec2 := do(t, h, "GET", "/admin/api/request-logs", "", true)
	var after struct {
		Total int64 `json:"total"`
	}
	json.Unmarshal(rec2.Body.Bytes(), &after)
	if after.Total != 0 {
		t.Errorf("清空后应为 0，得到 %d", after.Total)
	}
}

// 三个端点都必须在鉴权之内。
//
// 日志含 model 名、站名、失败原因 —— 那是运营信息，
// 和上游 key 一样不该对未授权的请求开放（§5.2f）。
func TestAPI_RequestLogEndpointsRequireAuth(t *testing.T) {
	_, h := newTestServer(t)

	cases := []struct{ method, path string }{
		{"GET", "/admin/api/request-logs"},
		{"GET", "/admin/api/retry-stats"},
		{"DELETE", "/admin/api/request-logs"},
	}
	for _, c := range cases {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			rec := do(t, h, c.method, c.path, "", false) // 不带凭据
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("未授权应回 401，得到 %d", rec.Code)
			}
		})
	}
}

// 样本端点要支持按 req_id 查 —— 这是「从日志跳到样本」的落地点。
//
// 测试放在这里而不是单独的 sample_test.go：它守的是 M6 的关联链，
// 而不是样本端点本身的行为。
//
// 缺了这个参数，前端只能拉一页样本回来自己找，而那对「比最近一页更早的
// 请求」会**静默找不到** —— 正是排查历史故障时要点的那些。
// store 层一直有这个能力（SampleFilter.ReqID），API 层此前没接上。
func TestAPI_ListSamplesByReqID(t *testing.T) {
	s, h := newTestServer(t)

	// 三条样本，只有一条属于目标请求
	for _, sm := range []*model.Sample{
		{ReqID: "target-req", TSRecv: 1, Endpoint: "/v1/messages",
			ModelIn: "claude-opus-5", Outcome: model.OutcomeOK},
		{ReqID: "other-req", TSRecv: 2, Endpoint: "/v1/messages"},
		{ReqID: "", TSRecv: 3, Endpoint: "/v1/messages"}, // 早于 M6 的样本
	} {
		if err := s.st.InsertSample(sm); err != nil {
			t.Fatal(err)
		}
	}

	rec := do(t, h, "GET", "/admin/api/samples?req_id=target-req", "", true)
	if rec.Code != 200 {
		t.Fatalf("应 200，得到 %d：%s", rec.Code, rec.Body.String())
	}
	var got struct {
		Samples []*model.Sample `json:"samples"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Samples) != 1 {
		t.Fatalf("按 req_id 应精确筛出 1 条，得到 %d —— API 层没接上这个参数？",
			len(got.Samples))
	}
	if got.Samples[0].ReqID != "target-req" {
		t.Errorf("筛出的不是目标样本，req_id=%q", got.Samples[0].ReqID)
	}

	// 查一个不存在的 req_id 要回空列表而不是全部 ——
	// 忽略未知参数的话，前端会拿到第一条样本并当成「找到了」。
	rec2 := do(t, h, "GET", "/admin/api/samples?req_id=nope", "", true)
	var none struct {
		Samples []*model.Sample `json:"samples"`
	}
	json.Unmarshal(rec2.Body.Bytes(), &none)
	if len(none.Samples) != 0 {
		t.Errorf("不存在的 req_id 应返回空列表，得到 %d 条 —— 参数被忽略了",
			len(none.Samples))
	}
}

// 游标翻页不重不漏。
func TestAPI_RequestLogPagination(t *testing.T) {
	s, _ := newTestServer(t)
	for i := 0; i < 10; i++ {
		if err := s.st.InsertRequestLog(&model.RequestLog{
			ReqID: fmt.Sprintf("r%02d", i), Attempt: 1, Attempts: 1,
			TSRecv: int64(i), Outcome: model.OutcomeOK}); err != nil {
			t.Fatal(err)
		}
	}
	h := s.Routes(testAdminPW)

	rec := do(t, h, "GET", "/admin/api/request-logs?limit=4", "", true)
	var page1 struct {
		Logs []*model.RequestLog `json:"logs"`
	}
	json.Unmarshal(rec.Body.Bytes(), &page1)
	if len(page1.Logs) != 4 {
		t.Fatalf("第一页应 4 行，得到 %d", len(page1.Logs))
	}

	last := page1.Logs[len(page1.Logs)-1].ID
	rec2 := do(t, h, "GET",
		fmt.Sprintf("/admin/api/request-logs?limit=4&before_id=%d", last), "", true)
	var page2 struct {
		Logs []*model.RequestLog `json:"logs"`
	}
	json.Unmarshal(rec2.Body.Bytes(), &page2)

	seen := map[int64]bool{}
	for _, l := range page1.Logs {
		seen[l.ID] = true
	}
	for _, l := range page2.Logs {
		if seen[l.ID] {
			t.Errorf("翻页重复了 id=%d", l.ID)
		}
	}
}
