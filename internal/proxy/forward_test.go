package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
)

func testForwarder(t *testing.T, to Timeouts) *Forwarder {
	t.Helper()
	manager := outbound.NewManager()
	t.Cleanup(manager.CloseIdleConnections)
	tr, err := manager.Transport(outbound.NetworkConfig{
		UpstreamID: 1, NetworkRevision: 1, ConnectTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &Forwarder{Transport: tr, Timeouts: to, Protocol: model.ProtoAnthropic}
}

func fastTimeouts() Timeouts {
	// 测试用的短超时。生产值有 300s 硬下限，测试里不受此限（那是配置层的约束）
	return Timeouts{Connect: 2 * time.Second, ResponseHead: 600 * time.Millisecond, FirstByte: 600 * time.Millisecond, FirstSemantic: 600 * time.Millisecond,
		Idle: 400 * time.Millisecond, Total: 5 * time.Second}
}

// 上游收到的东西必须与我们发出的完全一致。
func TestForward_PassesRequestThrough(t *testing.T) {
	var gotMethod, gotPath, gotQuery, gotBody string
	var gotHeaders http.Header

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotQuery = r.Method, r.URL.Path, r.URL.RawQuery
		gotHeaders = r.Header.Clone()
		b := make([]byte, r.ContentLength)
		r.Body.Read(b)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer up.Close()

	body := []byte(`{"model":"m","max_tokens":1}`)
	hdr := http.Header{}
	hdr.Set("X-Api-Key", "sk-up")
	hdr.Set("Anthropic-Version", "2023-06-01")
	hdr.Set("User-Agent", "claude-cli/2.1.220 (external, sdk-cli)")

	rec := httptest.NewRecorder()
	f := testForwarder(t, fastTimeouts())
	res := f.Forward(context.Background(), rec, "POST",
		up.URL+"/v1/messages?beta=true", hdr, body)

	if res.Err != nil {
		t.Fatalf("转发失败: %v", res.Err)
	}
	if gotMethod != "POST" || gotPath != "/v1/messages" {
		t.Errorf("方法/路径不对: %s %s", gotMethod, gotPath)
	}
	// query 必须原样带上：真实 Claude Code 打的是 ?beta=true
	if gotQuery != "beta=true" {
		t.Errorf("query 应原样转发，得到 %q", gotQuery)
	}
	if gotBody != string(body) {
		t.Errorf("body 应逐字节一致\nwant %s\ngot  %s", body, gotBody)
	}
	if gotHeaders.Get("User-Agent") != "claude-cli/2.1.220 (external, sdk-cli)" {
		t.Errorf("UA 应原样转发，得到 %q", gotHeaders.Get("User-Agent"))
	}
	if res.Status != 200 {
		t.Errorf("状态码应为 200，得到 %d", res.Status)
	}
	if rec.Body.String() != `{"ok":true}` {
		t.Errorf("响应体应原样回传，得到 %q", rec.Body.String())
	}
}

// 关掉自动压缩后，Go 不该偷偷加 Accept-Encoding，
// 否则会自动解压响应、迫使我们删 Content-Encoding（等于改动响应）。
func TestForward_DoesNotInjectAcceptEncoding(t *testing.T) {
	var got string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Accept-Encoding")
		w.Write([]byte("ok"))
	}))
	defer up.Close()

	f := testForwarder(t, fastTimeouts())
	res := f.Forward(context.Background(), httptest.NewRecorder(), "POST",
		up.URL, http.Header{}, []byte("{}"))
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if got != "" {
		t.Errorf("不该自动注入 Accept-Encoding，上游收到 %q", got)
	}
}

// 上游返回的 Content-Encoding 必须原样传回，字节流不解压。
func TestForward_PreservesContentEncoding(t *testing.T) {
	// 伪造一个声明了 gzip 的响应（内容不是真 gzip，正好验证我们没去解它）
	raw := []byte("\x1f\x8b\x08fake-gzip-bytes")
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/json")
		w.Write(raw)
	}))
	defer up.Close()

	rec := httptest.NewRecorder()
	f := testForwarder(t, fastTimeouts())
	res := f.Forward(context.Background(), rec, "POST", up.URL, http.Header{}, []byte("{}"))
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Error("Content-Encoding 应原样回传")
	}
	if rec.Body.String() != string(raw) {
		t.Error("响应体应原样回传，不做解压")
	}
}

// SSE 必须逐块 flush，不能攒到最后一次性刷出。
func TestForward_StreamsIncrementally(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		for i := 0; i < 3; i++ {
			w.Write([]byte("data: chunk\n\n"))
			fl.Flush()
			time.Sleep(60 * time.Millisecond)
		}
	}))
	defer up.Close()

	rec := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	f := testForwarder(t, Timeouts{Connect: 2 * time.Second,
		FirstSemantic: 2 * time.Second, Idle: 2 * time.Second, Total: 5 * time.Second})
	res := f.Forward(context.Background(), rec, "POST", up.URL, http.Header{}, []byte("{}"))

	if res.Err != nil {
		t.Fatal(res.Err)
	}
	// 3 个 chunk 分开到达 → 至少 flush 3 次。若只有 1 次说明被缓冲了
	if rec.flushes < 3 {
		t.Errorf("应逐块 flush（至少 3 次），实际 %d 次 —— 缓冲会破坏 SSE 语义", rec.flushes)
	}
	if res.BytesWritten == 0 {
		t.Error("应记录已写字节数")
	}
}

type flushRecorder struct {
	*httptest.ResponseRecorder
	flushes int
}

func (f *flushRecorder) Flush() { f.flushes++; f.ResponseRecorder.Flush() }

// §6.8 / §8.12：HTTP 200 SSE 在写出内容后出现协议错误事件，不得按 200 判活。
// Commit 保留原始流；健康与重试各自消费同一原始 Decoder 证据。
func TestCommit_MidStreamSSEErrorPassesThrough(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		w.WriteHeader(200)
		_, _ = w.Write([]byte("event: content_block_delta\n" +
			`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}` +
			"\n\n"))
		fl.Flush()
		_, _ = w.Write([]byte("event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"server_error\"}}\n\n"))
		fl.Flush()
	}))
	defer up.Close()

	f := testForwarder(t, fastTimeouts())
	at := f.Send(context.Background(), "POST", up.URL, http.Header{}, []byte("{}"))
	if at.Failed() {
		t.Fatalf("Send: %v", at.Result().Err)
	}
	rec := httptest.NewRecorder()
	res := at.Commit(rec)
	if res.Err != nil {
		t.Fatalf("Commit: %v", res.Err)
	}
	if res.Status != 200 {
		t.Fatalf("status=%d", res.Status)
	}
	if !rawProtocolError(rec.Body.Bytes(), "text/event-stream") {
		t.Fatal("mid-stream SSE error must preserve the original structured error")
	}
	if !strings.Contains(rec.Body.String(), `"text":"hi"`) {
		t.Fatalf("client must still receive prior content, body=%q", rec.Body.String())
	}
}

// 正文里出现字母 error 的正常 delta 不得变成协议错误。
func TestCommit_TextDeltaSpellingErrorIsNotProtocolError(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		w.WriteHeader(200)
		_, _ = w.Write([]byte("event: content_block_delta\n" +
			`data: {"type":"content_block_delta","index":0,` +
			`"delta":{"type":"text_delta","text":"error"}}` + "\n\n"))
		fl.Flush()
		_, _ = w.Write([]byte("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"))
		fl.Flush()
	}))
	defer up.Close()

	f := testForwarder(t, fastTimeouts())
	at := f.Send(context.Background(), "POST", up.URL, http.Header{}, []byte("{}"))
	if at.Failed() {
		t.Fatalf("Send: %v", at.Result().Err)
	}
	rec := httptest.NewRecorder()
	res := at.Commit(rec)
	if res.Err != nil {
		t.Fatalf("Commit: %v", res.Err)
	}
	if rawProtocolError(rec.Body.Bytes(), "text/event-stream") {
		t.Fatalf("text spelling \"error\" must not become a protocol error, got %v", rawProtocolError(rec.Body.Bytes(), "text/event-stream"))
	}
}

// 首 Token 超时：上游收下请求但迟迟不吐字节。
func TestForward_FirstTokenTimeout(t *testing.T) {
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.(http.Flusher).Flush() // 头先回，body 一直不来
		<-release
	}))
	defer up.Close()
	defer close(release)

	f := testForwarder(t, fastTimeouts())
	start := time.Now()
	res := f.Forward(context.Background(), httptest.NewRecorder(), "POST",
		up.URL, http.Header{}, []byte("{}"))
	elapsed := time.Since(start)

	if !errors.Is(res.Err, ErrFirstTokenTimeout) {
		t.Fatalf("应返回 ErrFirstTokenTimeout，得到 %v", res.Err)
	}
	// 必须真的在 FirstSemantic 时限内中断，而不是等到 Total
	if elapsed > 2*time.Second {
		t.Errorf("应在首 Token 超时（600ms）后立即中断，实际耗时 %v —— "+
			"超时未生效会让死站一直占住请求", elapsed)
	}
	if res.BytesWritten != 0 {
		t.Error("首 Token 超时时不该已写出字节")
	}
}

// 流内静默超时：首语义证据来了，之后卡住。
// 与首 Token / 首语义超时必须区分开 —— 两者对健康状态的含义不同。
func TestForward_IdleTimeoutAfterFirstByte(t *testing.T) {
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		// 必须是 §8.8 语义证据：裸 "data: first" 不能结束 FirstSemantic。
		_, _ = w.Write([]byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n"))
		w.(http.Flusher).Flush()
		<-release // 之后再不吐东西
	}))
	defer up.Close()
	defer close(release)

	f := testForwarder(t, fastTimeouts())
	rec := httptest.NewRecorder()
	start := time.Now()
	res := f.Forward(context.Background(), rec, "POST", up.URL, http.Header{}, []byte("{}"))
	elapsed := time.Since(start)

	if !errors.Is(res.Err, ErrStreamStalled) {
		t.Fatalf("应返回 ErrStreamStalled（而非首 Token 超时），得到 %v", res.Err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("应在 Idle 超时（400ms）后中断，实际 %v", elapsed)
	}
	// 已收到的部分必须已经传给客户端
	if !strings.Contains(rec.Body.String(), `"text":"hi"`) {
		t.Error("首语义应已写给客户端")
	}
	if !res.SemanticSeen || res.FirstSemanticAt.IsZero() {
		t.Error("应记录首语义时刻")
	}
	// 不断言 TTFT > 0：环回连接上上游立刻回写，两次 time.Now() 可能
	// 落在同一个时钟刻度里（Windows 单调时钟粒度约 0.5–1ms），
	// 差值为 0 是正常的。TTFT 的契约由 TestResult_TTFT 覆盖。
	if res.TTFT() < 0 {
		t.Errorf("TTFT 不该为负，得到 %v", res.TTFT())
	}
}

// Idle 已开火且 clientCtx 已取消时，必须报 ErrCanceled，不能报 ErrStreamStalled。
// 否则客户端离开会被记成上游静默、计入路由失败。
//
// 用彼此独立的 ctx / clientCtx 调用 streamBody：真实路径里取消客户端会
// 连带取消内层 ctx 并立刻关流，读往往在 Idle 之前就返回，测不到「两者
// 同时成立」。这里让 Idle 成为唯一的解锁方，逼出 timedOut∧clientGone。
func TestStreamBody_IdleFiredButClientGoneIsCanceled(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close()

	clientCtx, clientCancel := context.WithCancel(context.Background())
	defer clientCancel()
	ctx := context.Background() // 不随 clientCancel 结束

	f := &Forwarder{Timeouts: fastTimeouts(), Protocol: model.ProtoAnthropic}
	res := &Result{
		Status:      200,
		SentAt:      time.Now(),
		RespHeaders: http.Header{"Content-Type": []string{"text/event-stream"}},
	}
	rec := httptest.NewRecorder()
	at := &Attempt{f: f, res: res, resp: &http.Response{StatusCode: 200, Body: pr}, ctx: ctx, clientCtx: clientCtx,
		wire: newWireEvidence(f.Protocol, res.RespHeaders, nil)}

	errCh := make(chan error, 1)
	go func() {
		stop := at.watchResponse()
		defer stop()
		_, err := at.streamBody(rec, pr, false)
		errCh <- err
	}()

	semantic := []byte("event: content_block_delta\n" +
		`data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hi"}}` + "\n\n")
	if _, err := pw.Write(semantic); err != nil {
		t.Fatalf("write semantic: %v", err)
	}
	// 给 streamBody 一点时间处理首语义并武装 Idle。不能轮询
	// res.SemanticSeen：那是 streamBody 在写、测试在读，-race 会抓。
	time.Sleep(50 * time.Millisecond)
	clientCancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, ErrCanceled) {
			t.Fatalf("want ErrCanceled (client gone beats idle), got %v", err)
		}
		if errors.Is(err, ErrStreamStalled) {
			t.Fatalf("must not be ErrStreamStalled when client already canceled: %v", err)
		}
		if IsUpstreamFault(err) {
			t.Errorf("client cancel must not count as upstream fault: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("streamBody did not return after idle")
	}
}

// TTFT 的契约：SentAt 与 FirstSemanticAt 都有才算得出来，缺任何一个返回 0。
//
// 返回 0 而不是负数或 panic 是刻意的：调用方（健康状态机、样本记录）
// 用 0 表示「没测到」，而未见语义证据的样本正是 FirstSemanticAt 为零的那种。
// 首语义时间戳早于发出时刻（时钟回拨/乱序）同样归零，避免 TTFTMs 存负数。
func TestResult_TTFT(t *testing.T) {
	base := time.Now()
	cases := []struct {
		name           string
		sent, semantic time.Time
		want           time.Duration
	}{
		{"正常", base, base.Add(3200 * time.Millisecond), 3200 * time.Millisecond},
		{"同一刻度", base, base, 0},
		{"首语义早于发出", base.Add(100 * time.Millisecond), base, 0},
		{"没收到首语义", base, time.Time{}, 0},
		{"没发出去", time.Time{}, base, 0},
		{"两个都没有", time.Time{}, time.Time{}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &Result{SentAt: c.sent, FirstSemanticAt: c.semantic}
			if got := r.TTFT(); got != c.want {
				t.Errorf("want %v got %v", c.want, got)
			}
		})
	}
}

// 长思考场景：首语义来得很慢，但只要在 FirstSemantic 时限内就必须放过，
// 之后持续吐 delta 也不能被 Idle 超时打断。这是 5 分钟下限要保护的场景。
func TestForward_ToleratesSlowFirstTokenThenSteadyStream(t *testing.T) {
	delta := []byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"x\"}}\n\n")
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fl := w.(http.Flusher)
		fl.Flush()
		time.Sleep(350 * time.Millisecond) // 慢，但在 FirstSemantic(600ms) 内
		for i := 0; i < 4; i++ {
			_, _ = w.Write(delta)
			fl.Flush()
			time.Sleep(200 * time.Millisecond) // 小于 Idle(400ms)
		}
	}))
	defer up.Close()

	f := testForwarder(t, fastTimeouts())
	rec := httptest.NewRecorder()
	res := f.Forward(context.Background(), rec, "POST", up.URL, http.Header{}, []byte("{}"))

	if res.Err != nil {
		t.Fatalf("慢首 Token + 稳定流不该超时，得到 %v", res.Err)
	}
	if n := strings.Count(rec.Body.String(), `"text":"x"`); n != 4 {
		t.Errorf("应收到 4 个 chunk，得到 %d", n)
	}
}

// 回归测试：多 chunk 长流必须完整传完，不能被中途误关。
//
// 曾经的 bug：看门狗用「每次迭代新建 goroutine + WithDeadline」，主循环读成功后
// 同时关 done 与 cancel readCtx，select 两个 case 同时就绪时 Go 随机挑一个，
// 挑到 ctx 分支就会关掉一个正常的流 —— 每个 chunk 约 50% 概率截断。
// 单次运行可能碰巧通过，所以这里用 20 个 chunk 把概率压到可忽略。
func TestForward_LongStreamIsNotTruncated(t *testing.T) {
	const chunks = 20
	delta := []byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"d\"}}\n\n")
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		for i := 0; i < chunks; i++ {
			_, _ = w.Write(delta)
			fl.Flush()
			time.Sleep(15 * time.Millisecond) // 分时到达，逼出上述竞态
		}
	}))
	defer up.Close()

	rec := httptest.NewRecorder()
	f := testForwarder(t, fastTimeouts()) // Idle=400ms，远大于 15ms 间隔
	res := f.Forward(context.Background(), rec, "POST", up.URL, http.Header{}, []byte("{}"))

	if res.Err != nil {
		t.Fatalf("稳定流不该出错，得到 %v", res.Err)
	}
	if n := strings.Count(rec.Body.String(), `"text":"d"`); n != chunks {
		t.Errorf("应完整收到 %d 个 chunk，实际 %d —— 流被中途截断", chunks, n)
	}
}

// 回归测试：响应头阶段的时限绝不能误伤「头回得快、body 吐得慢」的长流。
//
// 曾经的写法是给请求套一个 FirstSemantic 的 context，拿到响应头后再 cancel ——
// 但请求是用那个 context 建的，cancel 会连带取消整个响应体读取，
// 流当场断在第一块。真实的长思考正是这个形状：头秒回，body 慢慢吐。
func TestForward_HeaderDeadlineDoesNotKillSlowBody(t *testing.T) {
	delta := []byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"c\"}}\n\n")
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200) // 头立刻回
		w.(http.Flusher).Flush()
		// 之后每块都比 FirstSemantic(300ms) 晚，但都在 Idle(400ms) 之内
		for i := 0; i < 6; i++ {
			time.Sleep(200 * time.Millisecond)
			_, _ = w.Write(delta)
			w.(http.Flusher).Flush()
		}
	}))
	defer up.Close()

	rec := httptest.NewRecorder()
	f := testForwarder(t, fastTimeouts())
	res := f.Forward(context.Background(), rec, "POST", up.URL, http.Header{}, []byte("{}"))

	if res.Err != nil {
		t.Fatalf("头快 body 慢的流不该出错，得到 %v", res.Err)
	}
	if n := strings.Count(rec.Body.String(), `"text":"c"`); n != 6 {
		t.Errorf("应完整收到 6 块，实际 %d —— 响应头时限误伤了 body 读取", n)
	}
}

// 卡在响应头阶段的站按 ResponseHead 到期，不等 Total。
// 这类站在公益站里不罕见：连接建立、请求收下，然后就没有然后了。
func TestForward_HeaderPhaseStallHitsFirstTokenBudget(t *testing.T) {
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // 连响应头都不回
	}))
	defer up.Close()
	defer close(release)

	to := fastTimeouts()
	to.ResponseHead = 300 * time.Millisecond
	to.Total = 10 * time.Second // 远大于 FirstSemantic，用来证明不是它兜的底

	rec := httptest.NewRecorder()
	f := testForwarder(t, to)
	start := time.Now()
	res := f.Forward(context.Background(), rec, "POST", up.URL, http.Header{}, []byte("{}"))
	elapsed := time.Since(start)

	if !errors.Is(res.Err, ErrFirstTokenTimeout) {
		t.Errorf("应归类为首 Token 超时，得到 %v", res.Err)
	}
	if elapsed > 3*time.Second {
		t.Errorf("应在 FirstSemantic(300ms) 后就放弃，实际等了 %v", elapsed)
	}
	// 关键：必须算上游的账，否则死站永远攒不够失败次数
	if !IsUpstreamFault(res.Err) {
		t.Error("响应头阶段超时是上游的问题，必须计入健康失败")
	}
	if res.HeadersSent {
		t.Error("没拿到响应头就不该标记 HeadersSent")
	}
}

// 我们自己的超时到期必须算上游的账。
// 判成「非上游故障」的话，真死的站永远不会被标 dead —— 项目的核心价值就没了。
func TestIsUpstreamFault_OurOwnTimeoutsCountAgainstUpstream(t *testing.T) {
	cases := []struct {
		err  error
		want bool
		why  string
	}{
		{ErrConnect, true, "连不上是上游的问题"},
		{ErrFirstTokenTimeout, true, "站太慢也是站的问题"},
		{ErrStreamStalled, true, "流中断是上游的问题"},
		{ErrTotalTimeout, true, "拖过总时限还是上游的问题"},
		{ErrUpstreamBroke, true, "上游断开"},
		{ErrStreamBroke, true, "流中途断"},
		{ErrClientGone, false, "客户端走了，与上游无关"},
		{ErrCanceled, false, "客户端取消，与上游无关"},
		{nil, false, "没错就没有故障"},
	}
	for _, c := range cases {
		if got := IsUpstreamFault(c.err); got != c.want {
			t.Errorf("IsUpstreamFault(%v) = %v，期望 %v —— %s", c.err, got, c.want, c.why)
		}
	}
}

// 上游 302 不得跟随 Location：默认 http.Client 会跟最多 10 次，
// 而第二次请求会把本站的 API key 带到另一台主机。
// Forwarder 走 Transport.RoundTrip，必须把 302 原样回传，且 Location 主机零请求。
func TestForward_DoesNotFollowRedirect(t *testing.T) {
	var otherHits int
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherHits++
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"stolen":true}`))
	}))
	defer other.Close()

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", other.URL+"/v1/messages")
		w.WriteHeader(http.StatusFound)
		_, _ = w.Write([]byte(`{"redirect":true}`))
	}))
	defer up.Close()

	hdr := http.Header{}
	hdr.Set("X-Api-Key", "sk-must-not-leave-origin")

	rec := httptest.NewRecorder()
	f := testForwarder(t, fastTimeouts())
	res := f.Forward(context.Background(), rec, "POST",
		up.URL+"/v1/messages", hdr, []byte(`{"model":"m"}`))

	if res.Err != nil {
		t.Fatalf("302 不是转发错误: %v", res.Err)
	}
	if res.Status != http.StatusFound || rec.Code != http.StatusFound {
		t.Fatalf("状态码应原样回传 302，res=%d rec=%d", res.Status, rec.Code)
	}
	if otherHits != 0 {
		t.Fatalf("Location 主机不得收到任何请求，hits=%d", otherHits)
	}
	if !strings.Contains(rec.Body.String(), "redirect") {
		t.Error("302 body 应原样回传")
	}
}

// 上游 5xx 要原样传给客户端（含 body），由健康状态机决定后续动作。
func TestForward_PassesUpstreamErrorThrough(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(503)
		w.Write([]byte(`{"error":{"type":"overloaded"}}`))
	}))
	defer up.Close()

	rec := httptest.NewRecorder()
	f := testForwarder(t, fastTimeouts())
	res := f.Forward(context.Background(), rec, "POST", up.URL, http.Header{}, []byte("{}"))

	if res.Err != nil {
		t.Fatalf("5xx 不是转发错误，应正常返回: %v", res.Err)
	}
	if res.Status != 503 || rec.Code != 503 {
		t.Errorf("状态码应原样回传，res=%d rec=%d", res.Status, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "overloaded") {
		t.Error("错误 body 应原样回传，客户端需要看到上游的错误信息")
	}
}

// 连不上的站要归类为 ErrConnect。
func TestForward_ConnectError(t *testing.T) {
	f := testForwarder(t, fastTimeouts())
	// 127.0.0.1:1 上不会有服务
	res := f.Forward(context.Background(), httptest.NewRecorder(), "POST",
		"http://127.0.0.1:1/v1/messages", http.Header{}, []byte("{}"))

	if !errors.Is(res.Err, ErrConnect) {
		t.Fatalf("应返回 ErrConnect，得到 %v", res.Err)
	}
	if !IsUpstreamFault(res.Err) {
		t.Error("连接失败应计入上游健康失败")
	}
}

// 客户端主动取消不该被算作上游故障 —— 否则好站会被误标 dead。
func TestForward_ClientCancelIsNotUpstreamFault(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(started)
		<-release
	}))
	defer up.Close()
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-started; cancel() }()

	f := testForwarder(t, Timeouts{Connect: 2 * time.Second,
		FirstSemantic: 5 * time.Second, Idle: 5 * time.Second, Total: 10 * time.Second})
	res := f.Forward(ctx, httptest.NewRecorder(), "POST", up.URL, http.Header{}, []byte("{}"))

	if res.Err == nil {
		t.Fatal("取消后应返回错误")
	}
	if IsUpstreamFault(res.Err) {
		t.Errorf("客户端取消不该计入上游故障（会把好站标 dead），得到 %v", res.Err)
	}
}

func TestIsUpstreamFault(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{ErrConnect, true},
		{ErrFirstTokenTimeout, true},
		{ErrStreamStalled, true},
		{ErrUpstreamBroke, true},
		{ErrStreamBroke, true},
		{ErrClientGone, false}, // 客户端的问题
		{ErrCanceled, false},   // 主动取消
	}
	for _, c := range cases {
		if got := IsUpstreamFault(c.err); got != c.want {
			t.Errorf("IsUpstreamFault(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

// 回归测试：改了 proxy_url 必须立刻生效。
//
// 曾经的写法只用 upstream ID 做缓存键，于是用户在管理界面改了代理地址，
// 配置确实存进去了、API 也回显了新值，但出站流量还在绕过代理 —— 直到重启。
// livecfg 每 2 秒刷新配置，这种「看起来生效了其实没有」最难排查。
//
// Both forwarders must honor a changed proxy through the shared Manager.
func TestHandler_ProxyChangesAffectActualRequests(t *testing.T) {
	for _, countTokens := range []bool{false, true} {
		t.Run(fmt.Sprint(countTokens), func(t *testing.T) {
			var first, second atomic.Int32
			body := `{"id":"msg_1","type":"message"}`
			if countTokens {
				body = `{"input_tokens":13}`
			}
			makeProxy := func(hits *atomic.Int32) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(body))
				}))
			}
			proxyA, proxyB := makeProxy(&first), makeProxy(&second)
			defer proxyA.Close()
			defer proxyB.Close()
			hs := newHarness(t, nil)
			for _, address := range []string{proxyA.URL, proxyB.URL} {
				hs.cfg.snap.Upstreams[10].ProxyURL = address
				request := hs.anthropicRequest(`{"model":"claude-opus-5","messages":[]}`)
				if countTokens {
					request = hs.countTokensRequest(`{"model":"claude-opus-5","messages":[]}`)
				}
				if response := hs.serve(request); response.Code != 200 || response.Body.String() != body {
					t.Fatalf("changed proxy was not used: %d %s", response.Code, response.Body.String())
				}
			}
			if first.Load() != 1 || second.Load() != 1 {
				t.Fatalf("proxy hits=%d/%d", first.Load(), second.Load())
			}
		})
	}
}

func TestRealTimeouts(t *testing.T) {
	s := model.DefaultSettings()
	to := RealTimeouts(s)
	if to.FirstSemantic != 1200*time.Second {
		t.Errorf("首 Token 应为 1200s，得到 %v", to.FirstSemantic)
	}
	if to.Idle != 600*time.Second {
		t.Errorf("Idle 应为 600s，得到 %v", to.Idle)
	}
	// 三段必须都非零，否则 context.WithTimeout(0) 会立刻超时
	if to.Connect == 0 || to.Total == 0 {
		t.Error("所有超时值都必须非零")
	}
}

// Short header/byte limits do not replace the independent semantic deadline.
func TestRealTimeouts_ShortHeaderAndByteRemainIndependentOfSemantic(t *testing.T) {
	s := model.DefaultSettings()
	s.RealResponseHeaderSec = 60
	s.RealFirstByteSec = 60
	s.RealFirstSemanticSec = 1200
	if err := s.Validate(); err != nil {
		t.Fatalf("合法 settings 必须通过校验：%v", err)
	}
	to := RealTimeouts(s)
	if to.FirstSemantic != 1200*time.Second || to.ResponseHead != 60*time.Second || to.FirstByte != 60*time.Second {
		t.Fatalf("independent phases changed: %+v", to)
	}
}

// CapTotal clips the effective deadline even when phase settings are longer.
func TestTimeoutsFrom_CapTotalBelowFloorNotRaised(t *testing.T) {
	budget := outbound.RealBudget(model.DefaultSettings()).CapTotal(90 * time.Second)
	to := TimeoutsFrom(budget)
	deadline, kind := to.pendingDeadline(time.Unix(1, 0), false, time.Time{}, time.Time{}, time.Time{}, false, 0)
	if !deadline.Equal(time.Unix(1, 0).Add(90*time.Second)) || kind != responseTotalTimeout {
		t.Fatalf("effective deadline=%v kind=%d, want shared total", deadline, kind)
	}
	if to.Total != 90*time.Second {
		t.Fatalf("Total = %v, want 90s", to.Total)
	}
}
