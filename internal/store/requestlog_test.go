package store

import (
	"fmt"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// 请求日志（M6）。
//
// 这一组盯的是两处不平凡的 SQL：
//   - PruneRequestLogs 按 **req_id 整组**清理。按行截会把一次重试的后半截
//     切掉，详情页于是显示「第 2、3 次尝试」而没有第 1 次 —— 看起来像
//     数据坏了，而实际是清理逻辑把组切开了。
//   - RetryStatsSince 用一条 CTE 算五个数。分五条查询跑的话，五个数可能
//     来自不同时刻的快照，于是出现「救回来的比重试过的还多」这种
//     自相矛盾的展示。

// mkLog 造一条日志。attempt/attempts 与 outcome 是这张表的核心，其余给合理默认。
func mkLog(reqID string, attempt, attempts int, outcome model.Outcome) *model.RequestLog {
	return &model.RequestLog{
		ReqID: reqID, Attempt: attempt, Attempts: attempts,
		TSRecv: time.Now().UnixMilli(), TSSent: time.Now().UnixMilli(),
		Endpoint: "/v1/messages", ModelIn: "claude-opus-5",
		RouteID: 100, UpstreamID: 10, UpstreamName: "st0",
		Outcome: outcome,
	}
}

func TestRequestLogInsertAndList(t *testing.T) {
	st := testStore(t)

	// 一次客户端请求，三次尝试：前两次 502 被换站，第三次成功
	logs := []*model.RequestLog{
		mkLog("req-a", 1, 3, model.OutcomeUpstreamError),
		mkLog("req-a", 2, 3, model.OutcomeUpstreamError),
		mkLog("req-a", 3, 3, model.OutcomeOK),
	}
	logs[0].Retried, logs[1].Retried = true, true
	logs[0].RespStatus, logs[1].RespStatus = 502, 502
	logs[2].RespStatus, logs[2].TTFTMs, logs[2].BytesWritten = 200, 1234, 5678
	logs[2].UpstreamName = "st2"

	for _, l := range logs {
		if err := st.InsertRequestLog(l); err != nil {
			t.Fatal(err)
		}
		if l.ID == 0 {
			t.Fatal("插入后应回填 ID")
		}
	}

	// 按 req_id 取整组，必须按 attempt **升序** —— 详情页要的是
	// 「第 1 次试了 A、第 2 次试了 B」这个顺序，倒序读起来是反的
	got, err := st.ListRequestLogs(RequestLogFilter{ReqID: "req-a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("应取到 3 次尝试，得到 %d", len(got))
	}
	for i, l := range got {
		if l.Attempt != i+1 {
			t.Errorf("第 %d 行的 attempt 应为 %d，得到 %d", i, i+1, l.Attempt)
		}
	}

	// 字段完整往返
	last := got[2]
	if last.Outcome != model.OutcomeOK || last.RespStatus != 200 {
		t.Errorf("最后一次应是 ok/200，得到 %q/%d", last.Outcome, last.RespStatus)
	}
	if last.TTFTMs != 1234 || last.BytesWritten != 5678 {
		t.Errorf("TTFT 与字节数应往返，得到 %d/%d", last.TTFTMs, last.BytesWritten)
	}
	if last.UpstreamName != "st2" {
		t.Errorf("upstream_name 应往返，得到 %q", last.UpstreamName)
	}
	if last.Retried {
		t.Error("最后一次成功的尝试不该标 retried")
	}
	if !got[0].Retried {
		t.Error("被换站的尝试应标 retried")
	}
}

// upstream_name 冗余存一份，站被删掉后日志仍要能说清当时走的是哪个站。
//
// 只存 upstream_id 关联查的话，删站等于把历史抹平 —— 而「我删掉的那个站
// 当时表现如何」正是决定要不要重新加回来的依据。
func TestRequestLogKeepsUpstreamNameAfterDelete(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "doomed")

	l := mkLog("req-x", 1, 1, model.OutcomeOK)
	l.UpstreamID, l.UpstreamName = up.ID, up.Name
	if err := st.InsertRequestLog(l); err != nil {
		t.Fatal(err)
	}

	if err := st.DeleteUpstream(up.ID); err != nil {
		t.Fatal(err)
	}

	got, err := st.ListRequestLogs(RequestLogFilter{ReqID: "req-x"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("删站不该删掉日志（没有外键级联），得到 %d 行", len(got))
	}
	if got[0].UpstreamName != "doomed" {
		t.Errorf("站名应仍可读，得到 %q", got[0].UpstreamName)
	}
}

func TestRequestLogFilters(t *testing.T) {
	st := testStore(t)

	// req-ok：一次过成功
	ok1 := mkLog("req-ok", 1, 1, model.OutcomeOK)
	// req-retry：两次尝试，第一次被换站，第二次成功
	r1 := mkLog("req-retry", 1, 2, model.OutcomeUpstreamError)
	r1.Retried = true
	r1.RouteID, r1.UpstreamID = 200, 20
	r2 := mkLog("req-retry", 2, 2, model.OutcomeOK)
	// req-timeout：一次尝试，超时且没重试（无站可换）
	t1 := mkLog("req-timeout", 1, 1, model.OutcomeTimeout)

	for _, l := range []*model.RequestLog{ok1, r1, r2, t1} {
		if err := st.InsertRequestLog(l); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name string
		f    RequestLogFilter
		want int
	}{
		{"不筛", RequestLogFilter{}, 4},
		{"按 outcome", RequestLogFilter{Outcome: model.OutcomeOK}, 2},
		{"按 route", RequestLogFilter{RouteID: 200}, 1},
		{"按 upstream", RequestLogFilter{UpstreamID: 20}, 1},
		// OnlyRetried 与 OnlyFailed 是**不同**的问题：前者问「实际换过站的」，
		// 后者问「没成功的」。req-timeout 失败了但没重试，只应命中后者。
		{"只看重试过的", RequestLogFilter{OnlyRetried: true}, 1},
		{"只看失败的", RequestLogFilter{OnlyFailed: true}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := st.ListRequestLogs(c.f)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != c.want {
				t.Errorf("应得 %d 行，得到 %d", c.want, len(got))
			}
		})
	}
}

// 列表默认按 id 倒序（最新在前），且游标翻页不重不漏。
func TestRequestLogPagination(t *testing.T) {
	st := testStore(t)
	for i := 0; i < 10; i++ {
		l := mkLog(fmt.Sprintf("req-%02d", i), 1, 1, model.OutcomeOK)
		if err := st.InsertRequestLog(l); err != nil {
			t.Fatal(err)
		}
	}

	first, err := st.ListRequestLogs(RequestLogFilter{Limit: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 4 {
		t.Fatalf("第一页应 4 行，得到 %d", len(first))
	}
	if first[0].ReqID != "req-09" {
		t.Errorf("应最新在前，首行是 %q", first[0].ReqID)
	}

	second, err := st.ListRequestLogs(RequestLogFilter{
		Limit: 4, BeforeID: first[len(first)-1].ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 4 {
		t.Fatalf("第二页应 4 行，得到 %d", len(second))
	}
	// 两页不能有交集
	seen := map[int64]bool{}
	for _, l := range first {
		seen[l.ID] = true
	}
	for _, l := range second {
		if seen[l.ID] {
			t.Errorf("翻页重复了 id=%d", l.ID)
		}
	}

	// 超上限应截到上限，而不是掉回默认值 ——
	// 后者会让 limit=5000 拿到 100 条，翻页逻辑据此以为「到底了」
	all, err := st.ListRequestLogs(RequestLogFilter{Limit: maxRequestLogLimit + 500})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 10 {
		t.Errorf("超上限应正常返回全部 10 行，得到 %d", len(all))
	}
}

// 按条数清理必须按 **req_id 整组**，不能按行切。
//
// 按行切的后果：一次三连重试的组被切成「第 2、3 次尝试」，详情页少了
// 第 1 次 —— 而第 1 次恰恰是「最初为什么失败」的答案。
func TestPruneRequestLogsKeepsGroupsIntact(t *testing.T) {
	st := testStore(t)

	// 3 组，每组 3 次尝试，共 9 行
	for g := 0; g < 3; g++ {
		for a := 1; a <= 3; a++ {
			l := mkLog(fmt.Sprintf("grp-%d", g), a, 3, model.OutcomeUpstreamError)
			if err := st.InsertRequestLog(l); err != nil {
				t.Fatal(err)
			}
		}
	}

	// 只保留 2 组 → 应删掉最旧的一整组（3 行），而不是删掉 3 行任意的
	n, err := st.PruneRequestLogs(2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("应删掉 1 整组 = 3 行，得到 %d", n)
	}

	// 剩下的每组都必须是完整的 3 行
	for _, g := range []string{"grp-1", "grp-2"} {
		got, err := st.ListRequestLogs(RequestLogFilter{ReqID: g})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 3 {
			t.Errorf("组 %s 应完整保留 3 行，得到 %d —— 清理把组切开了", g, len(got))
		}
	}
	// 最旧那组应整组消失
	gone, err := st.ListRequestLogs(RequestLogFilter{ReqID: "grp-0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(gone) != 0 {
		t.Errorf("最旧的组应整组删除，仍剩 %d 行", len(gone))
	}
}

func TestPruneRequestLogsByDays(t *testing.T) {
	st := testStore(t)

	old := mkLog("req-old", 1, 1, model.OutcomeOK)
	old.TSRecv = time.Now().Add(-10 * 24 * time.Hour).UnixMilli()
	fresh := mkLog("req-fresh", 1, 1, model.OutcomeOK)
	for _, l := range []*model.RequestLog{old, fresh} {
		if err := st.InsertRequestLog(l); err != nil {
			t.Fatal(err)
		}
	}

	n, err := st.PruneRequestLogs(0, 7)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("应删掉 1 条过期日志，得到 %d", n)
	}
	left, err := st.ListRequestLogs(RequestLogFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 1 || left[0].ReqID != "req-fresh" {
		t.Errorf("应只留下新的那条，得到 %+v", left)
	}
}

// 0 表示该维度不限，不能理解成「全删」。
//
// 这条防的是一个致命的边界错误：若把 0 当成「保留 0 条」，
// 一次清理就会把整张表清空 —— 而清理是自动跑的，没人会立刻发现。
func TestPruneRequestLogsZeroMeansUnlimited(t *testing.T) {
	st := testStore(t)
	for i := 0; i < 3; i++ {
		if err := st.InsertRequestLog(
			mkLog(fmt.Sprintf("req-%d", i), 1, 1, model.OutcomeOK)); err != nil {
			t.Fatal(err)
		}
	}

	n, err := st.PruneRequestLogs(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("两个维度都不限时不该删任何东西，删了 %d 条", n)
	}
	left, _ := st.ListRequestLogs(RequestLogFilter{})
	if len(left) != 3 {
		t.Errorf("应全部保留，得到 %d 条", len(left))
	}
}

// RetryStatsSince 是这张表存在的理由：回答「重试到底有没有用」。
func TestRetryStats(t *testing.T) {
	st := testStore(t)

	// 一次过成功（不算重试）
	must(t, st.InsertRequestLog(mkLog("a", 1, 1, model.OutcomeOK)))

	// 重试救回来了：第一次失败、第二次成功
	must(t, st.InsertRequestLog(mkLog("b", 1, 2, model.OutcomeUpstreamError)))
	must(t, st.InsertRequestLog(mkLog("b", 2, 2, model.OutcomeOK)))

	// 重试也没救回来：三次全失败
	must(t, st.InsertRequestLog(mkLog("c", 1, 3, model.OutcomeUpstreamError)))
	must(t, st.InsertRequestLog(mkLog("c", 2, 3, model.OutcomeTimeout)))
	must(t, st.InsertRequestLog(mkLog("c", 3, 3, model.OutcomeUpstreamError)))

	// 一次过失败（没重试，比如 4xx 或无站可换）
	must(t, st.InsertRequestLog(mkLog("d", 1, 1, model.OutcomeUpstreamError)))

	got, err := st.RetryStatsSince(0)
	if err != nil {
		t.Fatal(err)
	}

	// 4 次客户端请求，7 次尝试 —— 差值 3 就是重试额外花掉的上游调用
	if got.Requests != 4 {
		t.Errorf("客户端请求数应为 4（按 req_id 去重），得到 %d", got.Requests)
	}
	if got.Attempts != 7 {
		t.Errorf("总尝试数应为 7，得到 %d", got.Attempts)
	}
	// 只有 b 与 c 重试过；d 失败了但没重试，不能算进去
	if got.Retried != 2 {
		t.Errorf("重试过的请求数应为 2，得到 %d", got.Retried)
	}
	if got.RescuedByRetry != 1 {
		t.Errorf("重试救回来的应为 1（只有 b），得到 %d", got.RescuedByRetry)
	}
	if got.FailedAfterRetry != 1 {
		t.Errorf("重试后仍失败的应为 1（只有 c），得到 %d", got.FailedAfterRetry)
	}
	// 内部自洽：救回来的 + 仍失败的 = 重试过的
	if got.RescuedByRetry+got.FailedAfterRetry != got.Retried {
		t.Errorf("统计不自洽：%d + %d != %d",
			got.RescuedByRetry, got.FailedAfterRetry, got.Retried)
	}
}

// 时间窗口要真的生效，否则「最近 24 小时」显示的是开服以来的累计值 ——
// 而那个数字永远不会变好，看它做不出任何决定。
func TestRetryStatsRespectsWindow(t *testing.T) {
	st := testStore(t)

	oldLog := mkLog("old", 1, 2, model.OutcomeUpstreamError)
	oldLog.TSRecv = time.Now().Add(-48 * time.Hour).UnixMilli()
	must(t, st.InsertRequestLog(oldLog))
	oldLog2 := mkLog("old", 2, 2, model.OutcomeOK)
	oldLog2.TSRecv = time.Now().Add(-48 * time.Hour).UnixMilli()
	must(t, st.InsertRequestLog(oldLog2))

	must(t, st.InsertRequestLog(mkLog("new", 1, 1, model.OutcomeOK)))

	got, err := st.RetryStatsSince(24)
	if err != nil {
		t.Fatal(err)
	}
	if got.Requests != 1 {
		t.Errorf("24 小时窗口内应只有 1 次请求，得到 %d", got.Requests)
	}
	if got.Retried != 0 {
		t.Errorf("窗口内没有重试过的请求，得到 %d", got.Retried)
	}
}

// 空表不能报错，也不能返回 nil 指针 —— UI 一开就会调它。
func TestRetryStatsOnEmptyTable(t *testing.T) {
	st := testStore(t)
	got, err := st.RetryStatsSince(24)
	if err != nil {
		t.Fatalf("空表不该报错：%v", err)
	}
	if got == nil {
		t.Fatal("应返回零值统计而不是 nil")
	}
	if got.Requests != 0 || got.Attempts != 0 {
		t.Errorf("空表应全为 0，得到 %+v", got)
	}
}

func TestCountAndClearRequestLogs(t *testing.T) {
	st := testStore(t)
	for i := 0; i < 5; i++ {
		must(t, st.InsertRequestLog(
			mkLog(fmt.Sprintf("req-%d", i), 1, 1, model.OutcomeOK)))
	}

	n, err := st.CountRequestLogs()
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Errorf("应有 5 行，得到 %d", n)
	}

	deleted, err := st.ClearRequestLogs()
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 5 {
		t.Errorf("应清掉 5 行，得到 %d", deleted)
	}
	if n, _ := st.CountRequestLogs(); n != 0 {
		t.Errorf("清空后应为 0，得到 %d", n)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
