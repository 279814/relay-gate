package proxy

import (
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

// 请求日志的接入（M6）。
//
// 这一组盯的是日志**作为诊断依据**的可信度。日志坏掉的方式全是静默的：
//
//  1. 只记最终那次尝试 —— 于是「前两个站为什么失败」永远查不到，
//     而那正是记日志的唯一理由。
//  2. attempts 填错 —— 列表页显示「1 次尝试」而实际试了 3 个站，
//     看日志的人会得出「重试从没发生过」的结论。
//  3. retried 与「失败」混为一谈 —— 于是算不出「重试救回来了多少」，
//     而那是判断这个功能值不值得的唯一数字。
//  4. 明文 key 进了 error 字段 —— 日志会显示在管理界面上。

// recordingLogSink 收下日志供断言。Record 必须非阻塞（与生产实现的契约一致）。
type recordingLogSink struct {
	mu  sync.Mutex
	got []*model.RequestLog
}

func (s *recordingLogSink) Record(l *model.RequestLog) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, l)
}

func (s *recordingLogSink) all() []*model.RequestLog {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*model.RequestLog(nil), s.got...)
}

// withLogs 给多站测试台接上日志收集。
func (hs *multiHarness) withLogs() *recordingLogSink {
	sink := &recordingLogSink{}
	hs.h.WithLogSink(sink)
	return sink
}

// 每次尝试都要留一行，包括**被丢弃的**那些。
//
// 只记最终那次的话，「前两个站为什么失败」就永远查不到 ——
// 而那正是这张表存在的唯一理由。
func TestRequestLog_RecordsEveryAttempt(t *testing.T) {
	hs := newMultiHarness(t,
		respondStatus(502, `s0 down`),
		respondStatus(503, `s1 down`),
		respondOK(`{"id":"ok"}`))
	hs.cfg.settings.RealTotalSec = 30
	sink := hs.withLogs()

	if rec := hs.serve(hs.req()); rec.Code != 200 {
		t.Fatalf("应换站成功，得到 %d", rec.Code)
	}

	got := sink.all()
	if len(got) != 3 {
		t.Fatalf("三次尝试应各留一行，得到 %d 行", len(got))
	}

	// 顺序、attempt 序号、以及各自打到了哪个站
	wantStations := []string{"st0", "st1", "st2"}
	wantStatus := []int{502, 503, 200}
	for i, l := range got {
		if l.Attempt != i+1 {
			t.Errorf("第 %d 行的 attempt 应为 %d，得到 %d", i, i+1, l.Attempt)
		}
		if l.UpstreamName != wantStations[i] {
			t.Errorf("第 %d 次尝试应打到 %s，日志记的是 %q",
				i+1, wantStations[i], l.UpstreamName)
		}
		if l.RespStatus != wantStatus[i] {
			t.Errorf("第 %d 次尝试的状态码应为 %d，得到 %d",
				i+1, wantStatus[i], l.RespStatus)
		}
	}

	// 前两次被换站，最后一次没有 —— 这个区分是「重试救回来了吗」的依据
	if !got[0].Retried || !got[1].Retried {
		t.Error("被丢弃并换站的尝试应标 retried")
	}
	if got[2].Retried {
		t.Error("最终采用的那次尝试不该标 retried")
	}
}

// attempts（总次数）必须在**每一行**上都是最终值。
//
// 它在写前面几行时还不知道，所以实现上要攒着、最后统一回填。漏了这一步的
// 表现：列表页显示「1 次尝试」而实际试了 3 个站 —— 看日志的人会得出
// 「重试从没发生过」的结论，而那正好与事实相反。
func TestRequestLog_AttemptsIsFinalOnEveryRow(t *testing.T) {
	hs := newMultiHarness(t,
		respondStatus(502, `down`),
		respondStatus(502, `down`),
		respondOK(`{"id":"ok"}`))
	hs.cfg.settings.RealTotalSec = 30
	sink := hs.withLogs()

	hs.serve(hs.req())

	got := sink.all()
	if len(got) != 3 {
		t.Fatalf("应有 3 行，得到 %d", len(got))
	}
	for i, l := range got {
		if l.Attempts != 3 {
			t.Errorf("第 %d 行的 attempts 应为 3（总次数），得到 %d —— "+
				"前几行没有回填最终值", i+1, l.Attempts)
		}
	}
}

// 同一次客户端请求的所有行必须共享一个 req_id，且样本挂同一个值。
//
// req_id 是详情页把多次尝试聚成一组的唯一手段，也是「从日志跳到样本」的
// 关联键。每行各生成一个的话，详情页会把一次三连重试显示成三次独立请求。
func TestRequestLog_SharesReqIDAndLinksSample(t *testing.T) {
	hs := newMultiHarness(t,
		respondStatus(502, `down`),
		respondOK(`{"id":"ok"}`))
	hs.cfg.settings.RealTotalSec = 30
	sink := hs.withLogs()

	hs.serve(hs.req())

	got := sink.all()
	if len(got) != 2 {
		t.Fatalf("应有 2 行，得到 %d", len(got))
	}
	if got[0].ReqID == "" {
		t.Fatal("req_id 不该为空 —— 没有它详情页无法聚组")
	}
	if got[0].ReqID != got[1].ReqID {
		t.Errorf("同一次请求的多行应共享 req_id，得到 %q 与 %q",
			got[0].ReqID, got[1].ReqID)
	}

	// 样本必须挂同一个 req_id，否则两张表关联不起来
	smp := hs.sink.one(t)
	if smp.ReqID != got[0].ReqID {
		t.Errorf("样本的 req_id 应与日志一致，样本 %q vs 日志 %q",
			smp.ReqID, got[0].ReqID)
	}
}

// 不同请求之间 req_id 必须不同 —— 否则所有请求会被聚成一组。
func TestRequestLog_ReqIDIsUniquePerRequest(t *testing.T) {
	hs := newMultiHarness(t, respondOK(`{"id":"ok"}`))
	sink := hs.withLogs()

	for i := 0; i < 5; i++ {
		hs.serve(hs.req())
	}

	got := sink.all()
	seen := map[string]bool{}
	for _, l := range got {
		if seen[l.ReqID] {
			t.Errorf("req_id %q 重复了 —— 不同请求会被聚成一组", l.ReqID)
		}
		seen[l.ReqID] = true
	}
	if len(seen) != 5 {
		t.Errorf("5 次请求应有 5 个不同的 req_id，得到 %d 个", len(seen))
	}
}

// 一次过成功也要记，且 attempts=1、retried=false。
//
// 只记失败的话，成功率就没有分母 —— 而「重试有没有用」是个比例问题。
func TestRequestLog_RecordsSuccessToo(t *testing.T) {
	hs := newMultiHarness(t, respondOK(`{"id":"ok"}`))
	sink := hs.withLogs()

	hs.serve(hs.req())

	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("一次过的请求应留 1 行，得到 %d", len(got))
	}
	l := got[0]
	if l.Attempt != 1 || l.Attempts != 1 {
		t.Errorf("应是 1/1，得到 %d/%d", l.Attempt, l.Attempts)
	}
	if l.Retried {
		t.Error("没重试过不该标 retried")
	}
	if l.Outcome != model.OutcomeOK {
		t.Errorf("outcome 应为 ok，得到 %q", l.Outcome)
	}
	if l.BytesWritten == 0 {
		t.Error("成功的尝试应记下写出的字节数 —— 记 0 会被误判成假活")
	}
	if l.TTFTMs < 0 {
		t.Errorf("TTFT 不该为负，得到 %d", l.TTFTMs)
	}
}

// 最后一次尝试的字节数与耗时必须是 **Commit 之后**的值。
//
// 在 Commit 之前记的话，每个成功响应的 bytes_written 都是 0 —— 而 0 字节
// 的 200 正是「假活」的判据（§4.3），于是所有正常请求都会被显示成假活。
func TestRequestLog_FinalRowRecordedAfterCommit(t *testing.T) {
	const body = `{"id":"msg_1","content":"响应内容"}`
	hs := newMultiHarness(t, respondOK(body))
	sink := hs.withLogs()

	hs.serve(hs.req())

	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("应有 1 行，得到 %d", len(got))
	}
	if got[0].BytesWritten != int64(len(body)) {
		t.Errorf("应记下完整字节数 %d，得到 %d —— 日志在 Commit 之前就记了？",
			len(body), got[0].BytesWritten)
	}
	if got[0].TSDone == 0 {
		t.Error("ts_done 应在 Commit 之后填上")
	}
}

// 失败但**没有**重试的尝试：retried=false，outcome 非 ok。
//
// 这两个字段的组合是「重试有没有救回来」的判据。混为一谈的话，
// 一个「4xx 直接返回」会被算成一次重试失败，让重试的效果看起来比实际差。
func TestRequestLog_FailedWithoutRetryIsNotMarkedRetried(t *testing.T) {
	hs := newMultiHarness(t,
		respondStatus(401, `{"error":"bad key"}`),
		respondOK(`{"id":"never"}`))
	sink := hs.withLogs()

	hs.serve(hs.req())

	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("4xx 不重试，应只有 1 行，得到 %d", len(got))
	}
	l := got[0]
	if l.Retried {
		t.Error("没换站就不该标 retried —— 否则算不出重试的真实效果")
	}
	if l.Outcome == model.OutcomeOK {
		t.Errorf("401 的 outcome 不该是 ok，得到 %q", l.Outcome)
	}
	if l.RespStatus != 401 {
		t.Errorf("状态码应记 401，得到 %d", l.RespStatus)
	}
}

// 半开的试探要打标（§4.4c）。
//
// 它的失败预期就高，混进普通成功率会拉低整体数字，
// 让人误以为站的质量在下降 —— 而实际那是对已知 dead 的站做的试探。
func TestRequestLog_MarksHalfOpen(t *testing.T) {
	hs := newMultiHarness(t, respondOK(`{"id":"ok"}`))
	hs.cfg.settings.HalfOpenEnabled = true
	hs.health.dead[100] = true
	sink := hs.withLogs()

	if rec := hs.serve(hs.req()); rec.Code != 200 {
		t.Fatalf("半开应放行，得到 %d", rec.Code)
	}

	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("应有 1 行，得到 %d", len(got))
	}
	if !got[0].HalfOpen {
		t.Error("半开放行的尝试应打标 —— 不打标会把它的失败混进普通成功率")
	}
}

// 关掉开关时零写入。
func TestRequestLog_DisabledRecordsNothing(t *testing.T) {
	hs := newMultiHarness(t, respondOK(`{"id":"ok"}`))
	hs.cfg.settings.RequestLogEnabled = false
	sink := hs.withLogs()

	if rec := hs.serve(hs.req()); rec.Code != 200 {
		t.Errorf("关掉日志不该影响转发，得到 %d", rec.Code)
	}
	if got := sink.all(); len(got) != 0 {
		t.Errorf("开关关闭时不该有任何写入，得到 %d 行", len(got))
	}
}

// 日志与样本是**两个独立的开关**。
//
// 样本关掉时日志必须照记：日志是判断「重试策略有没有用」的唯一依据，
// 而那个判断恰恰在「样本太占地方所以关掉、只留统计」的场景下最需要。
func TestRequestLog_IndependentFromSampleSwitch(t *testing.T) {
	hs := newMultiHarness(t,
		respondStatus(502, `down`),
		respondOK(`{"id":"ok"}`))
	hs.cfg.settings.RealTotalSec = 30
	hs.cfg.settings.SampleEnabled = false // 关样本
	sink := hs.withLogs()

	if rec := hs.serve(hs.req()); rec.Code != 200 {
		t.Fatalf("应换站成功，得到 %d", rec.Code)
	}

	if smps := hs.sink.all(); len(smps) != 0 {
		t.Errorf("样本已关，不该有样本，得到 %d 条", len(smps))
	}
	if got := sink.all(); len(got) != 2 {
		t.Errorf("样本关掉不该影响日志，应有 2 行，得到 %d 行", len(got))
	}
}

// 日志的 error 字段必须脱敏。
//
// 它会显示在管理界面上，而错误文本里可能带出站 URL ——
// full_url_mode 的 base_url 允许把 key 放在 query 里（§3.2）。
func TestRequestLog_RedactsKeysInError(t *testing.T) {
	const upKey = "sk-station-0-secret"
	hs := newMultiHarness(t, func(w http.ResponseWriter, r *http.Request) {
		// 让第一个站连不上，错误文本里会带上出站 URL
		w.WriteHeader(500)
	})
	up := hs.cfg.snap.Upstreams[10]
	up.APIKey = upKey
	up.FullURLMode = true
	up.BaseURL = "http://127.0.0.1:1/v1/messages?key=" + upKey
	sink := hs.withLogs()

	hs.serve(hs.req())

	for _, l := range sink.all() {
		if strings.Contains(l.Error, upKey) {
			t.Errorf("日志的 error 里有明文 key —— 它会显示在管理界面上：%q", l.Error)
		}
	}
}

// 选路失败（无可用站）时不记日志 —— 那时还没有任何一次尝试。
//
// 记了的话，日志里会出现 upstream_name 为空、状态码为 0 的行，
// 而它们会把成功率的分母拉大 —— 一个从没发出去的请求不该算作失败的尝试。
func TestRequestLog_NotRecordedWhenSelectFails(t *testing.T) {
	hs := newMultiHarness(t, respondOK(`{"id":"ok"}`))
	hs.health.dead[100] = true
	sink := hs.withLogs()

	if rec := hs.serve(hs.req()); rec.Code != 503 {
		t.Fatalf("全 dead 应回 503，得到 %d", rec.Code)
	}
	if got := sink.all(); len(got) != 0 {
		t.Errorf("选路失败不该记日志，得到 %d 行", len(got))
	}
}

// 选路结果要完整留档，否则回溯不了「为什么走了这个站」。
func TestRequestLog_RecordsRoutingDecision(t *testing.T) {
	hs := newMultiHarness(t, respondOK(`{"id":"ok"}`))
	hs.cfg.snap.RoutesByModelName[1][0].UpstreamModel = "mapped-model"
	sink := hs.withLogs()

	hs.serve(hs.req())

	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("应有 1 行，得到 %d", len(got))
	}
	l := got[0]
	if l.RouteID != 100 || l.UpstreamID != 10 || l.ModelNameID != 1 {
		t.Errorf("选路结果应完整留档：route=%d upstream=%d model_name=%d",
			l.RouteID, l.UpstreamID, l.ModelNameID)
	}
	if l.Endpoint != "/v1/messages" {
		t.Errorf("endpoint 应记录，得到 %q", l.Endpoint)
	}
	// 映射前后都要记：只记一个的话，「上游到底收到了哪个模型名」查不到
	if l.ModelIn != "claude-opus-5" || l.ModelOut != "mapped-model" {
		t.Errorf("model_in/out 应分别记录，得到 %q / %q", l.ModelIn, l.ModelOut)
	}
	if l.TSRecv == 0 || l.TSSent == 0 {
		t.Errorf("时间戳应填充：recv=%d sent=%d", l.TSRecv, l.TSSent)
	}
}
