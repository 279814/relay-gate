package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

func testForwarder(t *testing.T, to Timeouts) *Forwarder {
	t.Helper()
	tr, err := NewTransport("", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &Forwarder{Transport: tr, Timeouts: to}
}

func fastTimeouts() Timeouts {
	// 测试用的短超时。生产值有 300s 硬下限，测试里不受此限（那是配置层的约束）
	return Timeouts{Connect: 2 * time.Second, FirstToken: 600 * time.Millisecond,
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
		FirstToken: 2 * time.Second, Idle: 2 * time.Second, Total: 5 * time.Second})
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
	// 必须真的在 FirstToken 时限内中断，而不是等到 Total
	if elapsed > 2*time.Second {
		t.Errorf("应在首 Token 超时（600ms）后立即中断，实际耗时 %v —— "+
			"超时未生效会让死站一直占住请求", elapsed)
	}
	if res.BytesWritten != 0 {
		t.Error("首 Token 超时时不该已写出字节")
	}
}

// 流内静默超时：首字节来了，之后卡住。
// 与首 Token 超时必须区分开 —— 两者对健康状态的含义不同。
func TestForward_IdleTimeoutAfterFirstByte(t *testing.T) {
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte("data: first\n\n"))
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
	if !strings.Contains(rec.Body.String(), "data: first") {
		t.Error("首字节应已写给客户端")
	}
	if res.FirstByteAt.IsZero() {
		t.Error("应记录首字节时刻")
	}
	// 不断言 TTFT > 0：环回连接上上游立刻回写，两次 time.Now() 可能
	// 落在同一个时钟刻度里（Windows 单调时钟粒度约 0.5–1ms），
	// 差值为 0 是正常的。TTFT 的契约由 TestResult_TTFT 覆盖。
	if res.TTFT() < 0 {
		t.Errorf("TTFT 不该为负，得到 %v", res.TTFT())
	}
}

// TTFT 的契约：两个时间戳都有才算得出来，缺任何一个返回 0。
//
// 返回 0 而不是负数或 panic 是刻意的：调用方（健康状态机、样本记录）
// 用 0 表示「没测到」，而首 Token 超时的样本正是 FirstByteAt 为零的那种。
func TestResult_TTFT(t *testing.T) {
	base := time.Now()
	cases := []struct {
		name        string
		sent, first time.Time
		want        time.Duration
	}{
		{"正常", base, base.Add(3200 * time.Millisecond), 3200 * time.Millisecond},
		{"同一刻度", base, base, 0},
		{"没收到首字节", base, time.Time{}, 0},
		{"没发出去", time.Time{}, base, 0},
		{"两个都没有", time.Time{}, time.Time{}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &Result{SentAt: c.sent, FirstByteAt: c.first}
			if got := r.TTFT(); got != c.want {
				t.Errorf("want %v got %v", c.want, got)
			}
		})
	}
}

// 长思考场景：首字节来得很慢，但只要在 FirstToken 时限内就必须放过，
// 之后持续吐 delta 也不能被 Idle 超时打断。这是 5 分钟下限要保护的场景。
func TestForward_ToleratesSlowFirstTokenThenSteadyStream(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fl := w.(http.Flusher)
		fl.Flush()
		time.Sleep(350 * time.Millisecond) // 慢，但在 FirstToken(600ms) 内
		for i := 0; i < 4; i++ {
			w.Write([]byte("data: thinking\n\n"))
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
	if n := strings.Count(rec.Body.String(), "data: thinking"); n != 4 {
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
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		for i := 0; i < chunks; i++ {
			w.Write([]byte("data: delta\n\n"))
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
	if n := strings.Count(rec.Body.String(), "data: delta"); n != chunks {
		t.Errorf("应完整收到 %d 个 chunk，实际 %d —— 流被中途截断", chunks, n)
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
		FirstToken: 5 * time.Second, Idle: 5 * time.Second, Total: 10 * time.Second})
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

func TestBuildOutboundURL(t *testing.T) {
	cases := []struct {
		name  string
		up    model.Upstream
		path  string
		query string
		want  string
	}{
		{"基本", model.Upstream{BaseURL: "https://a.com"}, "/v1/messages", "", "https://a.com/v1/messages"},
		{"带 query", model.Upstream{BaseURL: "https://a.com"}, "/v1/messages", "beta=true",
			"https://a.com/v1/messages?beta=true"},
		{"base 带尾斜杠", model.Upstream{BaseURL: "https://a.com/"}, "/v1/messages", "",
			"https://a.com/v1/messages"},
		{"responses 端点", model.Upstream{BaseURL: "https://a.com"}, "/v1/responses", "",
			"https://a.com/v1/responses"},
		{"count_tokens", model.Upstream{BaseURL: "https://a.com"}, "/v1/messages/count_tokens", "",
			"https://a.com/v1/messages/count_tokens"},
		{"full_url_mode 不拼路径", model.Upstream{BaseURL: "https://a.com/custom/endpoint",
			FullURLMode: true}, "/v1/messages", "", "https://a.com/custom/endpoint"},
		{"full_url_mode 仍带 query", model.Upstream{BaseURL: "https://a.com/x",
			FullURLMode: true}, "/v1/messages", "beta=true", "https://a.com/x?beta=true"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := BuildOutboundURL(&c.up, c.path, c.query)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("want %q got %q", c.want, got)
			}
		})
	}
}

func TestRealTimeouts(t *testing.T) {
	s := model.DefaultSettings()
	to := RealTimeouts(s)
	if to.FirstToken != 1200*time.Second {
		t.Errorf("首 Token 应为 1200s，得到 %v", to.FirstToken)
	}
	if to.Idle != 600*time.Second {
		t.Errorf("Idle 应为 600s，得到 %v", to.Idle)
	}
	// 三段必须都非零，否则 context.WithTimeout(0) 会立刻超时
	if to.Connect == 0 || to.Total == 0 {
		t.Error("所有超时值都必须非零")
	}
}
