package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/store"
)

// ── 测试替身 ──────────────────────────────────────────────

// fakeConfig 让测试能精确控制快照与设置，不碰数据库。
type fakeConfig struct {
	snap     *router.Snapshot
	settings model.Settings
	state    store.RunState
	err      error // 非 nil 时三个方法都返回它，用于测内部错误路径
}

func (f *fakeConfig) Snapshot() (*router.Snapshot, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.snap, nil
}
func (f *fakeConfig) Settings() (model.Settings, error) {
	if f.err != nil {
		return model.Settings{}, f.err
	}
	return f.settings, nil
}
func (f *fakeConfig) RunState() (store.RunState, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.state, nil
}

// allAliveHealth 是最简健康视图：全部可用、无在途、不冷却。
type allAliveHealth struct{ dead map[int64]bool }

func (a allAliveHealth) State(id int64) model.HealthState {
	if a.dead[id] {
		return model.StateDead
	}
	return model.StateAlive
}
func (a allAliveHealth) InFlight(int64) int     { return 0 }
func (a allAliveHealth) CoolingDown(int64) bool { return false }

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// countingTracker 记录 Begin/done 的调用，用于验证在途计数的配平。
type countingTracker struct {
	mu     sync.Mutex
	begins []int64
	open   int
	maxOpe int // 峰值并发，验证计数窗口真的覆盖了转发过程
}

func (c *countingTracker) Begin(routeID int64) func() {
	c.mu.Lock()
	c.begins = append(c.begins, routeID)
	c.open++
	if c.open > c.maxOpe {
		c.maxOpe = c.open
	}
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		c.open--
		c.mu.Unlock()
	}
}

func (c *countingTracker) stats() (begins []int64, open, peak int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int64(nil), c.begins...), c.open, c.maxOpe
}

// testSettings 用短超时，避免测试挂在生产的 300s 下限上。
// 那个下限是配置层的约束（SaveSettings 校验），转发层只管用给它的值。
func testSettings() model.Settings {
	s := model.DefaultSettings()
	s.RealConnectSec = 2
	s.RealFirstTokenSec = 2
	s.RealIdleSec = 2
	s.RealTotalSec = 5
	return s
}

// harness 组装一个指向 mock 上游的完整 Handler。
type harness struct {
	h       *Handler
	cfg     *fakeConfig
	up      *httptest.Server
	gotReq  *capturedRequest
	tracker *countingTracker
	relayPW string
}

type capturedRequest struct {
	method  string
	path    string
	query   string
	headers http.Header
	body    []byte
}

// newHarness 起一个 mock 上游并配好 1 个 ModelName / 1 个 Upstream / 1 条 Route。
// respond 为 nil 时回一个最简 200 JSON。
func newHarness(t *testing.T, respond http.HandlerFunc) *harness {
	t.Helper()

	hs := &harness{gotReq: &capturedRequest{}, tracker: &countingTracker{},
		relayPW: "rk-client-key"}

	hs.up = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		hs.gotReq.method = r.Method
		hs.gotReq.path = r.URL.Path
		hs.gotReq.query = r.URL.RawQuery
		hs.gotReq.headers = r.Header.Clone()
		hs.gotReq.body = body

		if respond != nil {
			respond(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"msg_1","type":"message"}`))
	}))
	t.Cleanup(hs.up.Close)

	mn := &model.ModelName{ID: 1, Name: "claude-opus-5",
		Protocol: model.ProtoAnthropic, MatchMode: model.MatchExact, Enabled: true}
	up := &model.Upstream{ID: 10, Name: "mock", BaseURL: hs.up.URL,
		APIKey: "sk-upstream-secret", AuthStyle: model.AuthAuto, Enabled: true}
	rt := &model.Route{ID: 100, ModelNameID: 1, UpstreamID: 10,
		Priority: 1, Weight: 100, Enabled: true}

	hs.cfg = &fakeConfig{
		snap:     router.BuildSnapshot([]*model.ModelName{mn}, []*model.Upstream{up}, []*model.Route{rt}),
		settings: testSettings(),
		state:    store.StateRunning,
	}
	hs.h = NewHandler(hs.cfg, allAliveHealth{dead: map[int64]bool{}}, hs.tracker,
		[]string{hs.relayPW}, discardLog())
	t.Cleanup(hs.h.CloseIdleConnections)
	return hs
}

// serve 走完整的 mux 路由，确保端点注册也在测试范围内。
func (hs *harness) serve(r *http.Request) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	hs.h.Routes(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	return rec
}

// anthropicRequest 构造一个带完整 Claude Code 头的入站请求。
func (hs *harness) anthropicRequest(body string) *http.Request {
	r := httptest.NewRequest("POST", "/v1/messages?beta=true", strings.NewReader(body))
	r.Header = claudeCodeHeaders()
	r.Header.Set("X-Api-Key", hs.relayPW) // 客户端拿的是 relay key
	return r
}

// ── 主干：逐字节保真 ──────────────────────────────────────

// 整条链路最重要的断言：上游收到的 body 与客户端发来的**逐字节相同**。
// 不映射（UpstreamModel 为空）时连 model 字段都不该动。
func TestHandler_ForwardsBodyByteForByte(t *testing.T) {
	hs := newHarness(t, nil)

	// 刻意用「JSON 合法但 round-trip 会变形」的写法：
	// 键序非字母序、1.0 不是整数、A 是转义的 A、& 会被默认 HTML 转义。
	body := `{"max_tokens":1,"model":"claude-opus-5","temperature":1.0,` +
		`"system":"AA & B","stream":true}`

	rec := hs.serve(hs.anthropicRequest(body))

	if rec.Code != 200 {
		t.Fatalf("状态码应为 200，得到 %d，body=%s", rec.Code, rec.Body.String())
	}
	if string(hs.gotReq.body) != body {
		t.Errorf("body 必须逐字节一致\nwant %s\ngot  %s", body, hs.gotReq.body)
	}
	if hs.gotReq.path != "/v1/messages" {
		t.Errorf("路径应 1:1 直通，得到 %q", hs.gotReq.path)
	}
	if hs.gotReq.query != "beta=true" {
		t.Errorf("query 应原样带上，得到 %q", hs.gotReq.query)
	}
	if rec.Body.String() != `{"id":"msg_1","type":"message"}` {
		t.Errorf("响应体应原样回传，得到 %q", rec.Body.String())
	}
}

// 出站头 = 入站头 - 黑名单 + 上游鉴权。relay key 一个字节都不能漏出去。
func TestHandler_RewritesOnlyAuthHeaders(t *testing.T) {
	hs := newHarness(t, nil)
	r := hs.anthropicRequest(`{"model":"claude-opus-5"}`)
	r.Header.Set("Authorization", "Bearer "+hs.relayPW) // 两个位置都带 relay key

	hs.serve(r)

	got := hs.gotReq.headers
	for k, vs := range got {
		for _, v := range vs {
			if strings.Contains(v, hs.relayPW) {
				t.Errorf("relay key 泄露到上游请求头 %s: %q", k, v)
			}
		}
	}
	if got.Get("X-Api-Key") != "sk-upstream-secret" {
		t.Errorf("应注入上游 key，得到 %q", got.Get("X-Api-Key"))
	}
	if got.Get("Authorization") != "Bearer sk-upstream-secret" {
		t.Errorf("auto 应双发，得到 %q", got.Get("Authorization"))
	}
	// 业务头必须一个不少 —— M0 实测有站按 UA 前缀白名单拦截
	if got.Get("User-Agent") != "claude-cli/2.1.220 (external, sdk-cli)" {
		t.Errorf("User-Agent 应原样转发，得到 %q", got.Get("User-Agent"))
	}
	if !strings.Contains(got.Get("Anthropic-Beta"), "claude-code-20250219") {
		t.Errorf("Anthropic-Beta 应原样转发，得到 %q", got.Get("Anthropic-Beta"))
	}
	if got.Get("X-Stainless-Retry-Count") != "0" {
		t.Error("X-Stainless-* 这类看似无用的头也必须转发")
	}
}

// 配了映射时只改 model 的值，其余字节不动。
func TestHandler_AppliesModelMapping(t *testing.T) {
	hs := newHarness(t, nil)
	hs.cfg.snap.RoutesByModelName[1][0].UpstreamModel = "claude-opus-4-20250514"

	body := `{"model":"claude-opus-5","max_tokens":1,"system":"keep & me"}`
	hs.serve(hs.anthropicRequest(body))

	want := `{"model":"claude-opus-4-20250514","max_tokens":1,"system":"keep & me"}`
	if string(hs.gotReq.body) != want {
		t.Errorf("应只替换 model 值\nwant %s\ngot  %s", want, hs.gotReq.body)
	}
}

// ── 入站鉴权 ──────────────────────────────────────────────

func TestHandler_RejectsBadRelayKey(t *testing.T) {
	hs := newHarness(t, nil)

	cases := []struct {
		name string
		set  func(*http.Request)
	}{
		{"无凭据", func(r *http.Request) { r.Header.Del("X-Api-Key") }},
		{"错的 key", func(r *http.Request) { r.Header.Set("X-Api-Key", "rk-wrong") }},
		{"Bearer 错的 key", func(r *http.Request) {
			r.Header.Del("X-Api-Key")
			r.Header.Set("Authorization", "Bearer rk-wrong")
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := hs.anthropicRequest(`{"model":"claude-opus-5"}`)
			c.set(r)
			rec := hs.serve(r)
			if rec.Code != 401 {
				t.Errorf("应回 401，得到 %d", rec.Code)
			}
			// 关键：绝不能已经打到上游 —— 否则等于免费公开上游 key
			if hs.gotReq.method != "" {
				t.Error("鉴权失败的请求不该转发到上游")
			}
			if !strings.Contains(rec.Body.String(), "authentication_error") {
				t.Errorf("错误应是 Anthropic 格式，得到 %s", rec.Body.String())
			}
		})
	}
}

// 三个位置都该认：不同协议的客户端习惯不同。
func TestHandler_AcceptsKeyInAllThreePlaces(t *testing.T) {
	places := []struct {
		name string
		set  func(*http.Request, string)
	}{
		{"X-Api-Key", func(r *http.Request, k string) { r.Header.Set("X-Api-Key", k) }},
		{"Bearer", func(r *http.Request, k string) { r.Header.Set("Authorization", "Bearer "+k) }},
		{"Api-Key", func(r *http.Request, k string) { r.Header.Set("Api-Key", k) }},
	}
	for _, p := range places {
		t.Run(p.name, func(t *testing.T) {
			hs := newHarness(t, nil)
			r := hs.anthropicRequest(`{"model":"claude-opus-5"}`)
			r.Header.Del("X-Api-Key")
			p.set(r, hs.relayPW)
			if rec := hs.serve(r); rec.Code != 200 {
				t.Errorf("应放行，得到 %d：%s", rec.Code, rec.Body.String())
			}
		})
	}
}

// 未配置任何 relay key 时必须全拒。「没配就放开」是最危险的默认值。
func TestHandler_NoRelayKeysConfiguredRejectsAll(t *testing.T) {
	hs := newHarness(t, nil)
	hs.h = NewHandler(hs.cfg, allAliveHealth{}, hs.tracker, nil, discardLog())

	r := hs.anthropicRequest(`{"model":"claude-opus-5"}`)
	if rec := hs.serve(r); rec.Code != 401 {
		t.Errorf("未配置 relay key 时应一律拒绝，得到 %d", rec.Code)
	}
}

// ── 总闸与选路错误 ────────────────────────────────────────

func TestHandler_PausedRejectsNewRequests(t *testing.T) {
	hs := newHarness(t, nil)
	hs.cfg.state = store.StatePaused

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))
	if rec.Code != 503 {
		t.Errorf("暂停时应回 503，得到 %d", rec.Code)
	}
	if rec.Header().Get("X-Relay-State") != "paused" {
		t.Error("应带 X-Relay-State: paused，否则分不清是暂停还是上游全挂")
	}
	if hs.gotReq.method != "" {
		t.Error("暂停时不该转发到上游")
	}
}

func TestHandler_SelectErrors(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		setup      func(*harness)
		wantStatus int
		wantInBody string
	}{
		{
			name: "未配置的 model → 404",
			body: `{"model":"gpt-5.6-sol"}`,
			// 没有兜底 ModelName 时必须明确 404，而不是静默转发
			wantStatus: 404,
			wantInBody: "not_found_error",
		},
		{
			name:       "全部 dead → 503",
			body:       `{"model":"claude-opus-5"}`,
			setup:      func(hs *harness) { hs.h.health = allAliveHealth{dead: map[int64]bool{100: true}} },
			wantStatus: 503,
			wantInBody: "overloaded_error",
		},
		{
			name:       "body 不是 JSON 对象 → 400",
			body:       `[1,2,3]`,
			wantStatus: 400,
			wantInBody: "invalid_request_error",
		},
		{
			name:       "没有 model 字段 → 400",
			body:       `{"max_tokens":1}`,
			wantStatus: 400,
			wantInBody: "invalid_request_error",
		},
		{
			name:       "model 是 null → 400",
			body:       `{"model":null}`,
			wantStatus: 400,
			wantInBody: "invalid_request_error",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hs := newHarness(t, nil)
			if c.setup != nil {
				c.setup(hs)
			}
			rec := hs.serve(hs.anthropicRequest(c.body))
			if rec.Code != c.wantStatus {
				t.Errorf("状态码 want %d got %d：%s", c.wantStatus, rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), c.wantInBody) {
				t.Errorf("响应应含 %q，得到 %s", c.wantInBody, rec.Body.String())
			}
			if hs.gotReq.method != "" {
				t.Error("选路失败的请求不该转发到上游")
			}
		})
	}
}

// 503/404 必须可诊断：不带 X-Relay-Reason 的话，只看到「服务不可用」，
// 分不清是配置错了还是所有站都挂了。
func TestHandler_SelectErrorCarriesReason(t *testing.T) {
	hs := newHarness(t, nil)
	hs.h.health = allAliveHealth{dead: map[int64]bool{100: true}}

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))
	reason := rec.Header().Get("X-Relay-Reason")
	if reason == "" {
		t.Fatal("应带 X-Relay-Reason 说明原因")
	}
	if !strings.Contains(reason, "dead") {
		t.Errorf("原因应说明有站 dead，得到 %q", reason)
	}
}

// 协议配错必须明确报错，而不是把 Anthropic 的 body 发到 chat/completions。
func TestHandler_ProtocolMismatch(t *testing.T) {
	hs := newHarness(t, nil)
	r := httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"claude-opus-5"}`))
	r.Header.Set("X-Api-Key", hs.relayPW)
	r.Header.Set("Content-Type", "application/json")

	rec := hs.serve(r)
	if rec.Code != 400 {
		t.Errorf("协议不一致应回 400，得到 %d", rec.Code)
	}
	// OpenAI 端点的错误必须是 OpenAI 格式，否则客户端报解析失败而不是真正原因
	if !strings.Contains(rec.Body.String(), `"error"`) ||
		strings.Contains(rec.Body.String(), `"type":"error"`) {
		t.Errorf("应是 OpenAI 错误格式，得到 %s", rec.Body.String())
	}
}

// ── 端点与协议 ────────────────────────────────────────────

// 三个端点都要注册，且各自路径 1:1 直通。
func TestHandler_AllThreeEndpoints(t *testing.T) {
	cases := []struct {
		path  string
		proto model.Protocol
	}{
		{"/v1/messages", model.ProtoAnthropic},
		{"/v1/responses", model.ProtoOpenAIResponses},
		{"/v1/chat/completions", model.ProtoOpenAIChat},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			hs := newHarness(t, nil)
			hs.cfg.snap.ModelNames[0].Protocol = c.proto

			r := httptest.NewRequest("POST", c.path, strings.NewReader(`{"model":"claude-opus-5"}`))
			r.Header.Set("X-Api-Key", hs.relayPW)
			rec := hs.serve(r)

			if rec.Code != 200 {
				t.Fatalf("应放行，得到 %d：%s", rec.Code, rec.Body.String())
			}
			if hs.gotReq.path != c.path {
				t.Errorf("出站路径应与入站相同，want %q got %q", c.path, hs.gotReq.path)
			}
		})
	}
}

// GET 不该匹配到透传端点（方法模式路由的隐含约定）。
func TestHandler_RejectsNonPost(t *testing.T) {
	hs := newHarness(t, nil)
	r := httptest.NewRequest("GET", "/v1/messages", nil)
	r.Header.Set("X-Api-Key", hs.relayPW)
	if rec := hs.serve(r); rec.Code != 405 {
		t.Errorf("GET 应回 405，得到 %d", rec.Code)
	}
}

// ── 响应透传 ──────────────────────────────────────────────

// 上游的错误必须原样回传（含状态码与 body）：客户端需要看到真正的原因。
func TestHandler_PassesUpstreamErrorThrough(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream-Request-Id", "req-abc")
		w.WriteHeader(429)
		w.Write([]byte(`{"error":{"type":"rate_limit_error","message":"上游限流"}}`))
	})

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))
	if rec.Code != 429 {
		t.Errorf("状态码应原样回传，得到 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "rate_limit_error") {
		t.Errorf("上游错误体应原样回传，得到 %s", rec.Body.String())
	}
	if rec.Header().Get("X-Upstream-Request-Id") != "req-abc" {
		t.Error("上游响应头应原样回传")
	}
}

// SSE 必须逐块 flush。缓冲会表现为「长时间无输出后一次性刷出」。
//
// 事件之间要留间隔：连写的话 TCP 与 Transport 会把它们合并成一次 Read，
// 「有没有缓冲」就不可观测了 —— 只有分时到达才能验证这个性质。
func TestHandler_StreamsSSEIncrementally(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		for _, ev := range []string{"message_start", "content_block_delta", "message_stop"} {
			w.Write([]byte("event: " + ev + "\ndata: {}\n\n"))
			fl.Flush()
			time.Sleep(50 * time.Millisecond) // 远小于 Idle(2s)，不会触发超时
		}
	})

	mux := http.NewServeMux()
	hs.h.Routes(mux)
	rec := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	mux.ServeHTTP(rec, hs.anthropicRequest(`{"model":"claude-opus-5","stream":true}`))

	if rec.Code != 200 {
		t.Fatalf("状态码应为 200，得到 %d", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "text/event-stream" {
		t.Error("Content-Type 必须保留，否则客户端不会按 SSE 解析")
	}
	if rec.flushes < 3 {
		t.Errorf("应逐块 flush（至少 3 次），实际 %d 次", rec.flushes)
	}
	if !strings.Contains(rec.Body.String(), "message_stop") {
		t.Error("完整事件流应回传")
	}
}

// ── 边界 ──────────────────────────────────────────────────

func TestHandler_BodyTooLarge(t *testing.T) {
	hs := newHarness(t, nil)
	big := bytes.Repeat([]byte("x"), MaxRequestBody+1)

	r := httptest.NewRequest("POST", "/v1/messages", bytes.NewReader(big))
	r.Header.Set("X-Api-Key", hs.relayPW)
	rec := hs.serve(r)

	if rec.Code != 400 {
		t.Errorf("超限应回 400，得到 %d", rec.Code)
	}
	if hs.gotReq.method != "" {
		t.Error("超限请求不该转发到上游")
	}
}

// 配置读取失败要回 500，而不是拿零值配置继续跑 ——
// 零值 Settings 的超时全是 0，会让每个请求立刻超时。
func TestHandler_ConfigErrorIsServerError(t *testing.T) {
	hs := newHarness(t, nil)
	hs.cfg.err = io.ErrUnexpectedEOF

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))
	if rec.Code != 500 {
		t.Errorf("配置读取失败应回 500，得到 %d", rec.Code)
	}
	if hs.gotReq.method != "" {
		t.Error("配置不可读时不该转发到上游")
	}
}

// Transport 必须按 Upstream 缓存：每请求新建会丢掉连接复用，
// 对高延迟的公益站来说每次都要重新 TLS 握手。
func TestHandler_ReusesTransportPerUpstream(t *testing.T) {
	hs := newHarness(t, nil)
	s := testSettings()
	up := hs.cfg.snap.Upstreams[10]

	tr1, err := hs.h.transportFor(up, s)
	if err != nil {
		t.Fatal(err)
	}
	tr2, err := hs.h.transportFor(up, s)
	if err != nil {
		t.Fatal(err)
	}
	if tr1 != tr2 {
		t.Error("同一 Upstream 应复用同一个 Transport")
	}

	// 配置变更（尤其 proxy_url）后必须丢弃旧的，否则改了代理不生效
	hs.h.InvalidateTransport(up.ID)
	tr3, err := hs.h.transportFor(up, s)
	if err != nil {
		t.Fatal(err)
	}
	if tr3 == tr1 {
		t.Error("InvalidateTransport 后应重建 Transport")
	}
}

// 并发请求下 transports map 不能出现竞态或重复建 Transport。
// （Windows 上没 cgo 跑不了 -race，这里至少验证功能正确。）
func TestHandler_ConcurrentRequests(t *testing.T) {
	hs := newHarness(t, nil)

	const n = 20
	codes := make(chan int, n)
	for i := 0; i < n; i++ {
		go func() {
			rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))
			codes <- rec.Code
		}()
	}
	for i := 0; i < n; i++ {
		if code := <-codes; code != 200 {
			t.Errorf("第 %d 个并发请求失败：%d", i, code)
		}
	}
	if len(hs.h.transports) != 1 {
		t.Errorf("同一 Upstream 应只有 1 个 Transport，得到 %d", len(hs.h.transports))
	}
}

// ── 在途计数 ──────────────────────────────────────────────

// 选中 Route 后必须登记在途，请求结束后必须减回去。
// 只增不减的话，配了 max_concurrency 的 Route 会被永久排除在选路之外。
func TestHandler_TracksInFlight(t *testing.T) {
	hs := newHarness(t, nil)

	hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))

	begins, open, peak := hs.tracker.stats()
	if len(begins) != 1 || begins[0] != 100 {
		t.Errorf("应为选中的 Route 100 登记一次在途，得到 %v", begins)
	}
	if open != 0 {
		t.Errorf("请求结束后在途应归零，得到 %d", open)
	}
	if peak != 1 {
		t.Errorf("峰值应为 1，得到 %d", peak)
	}
}

// 计数窗口必须覆盖整个转发过程，而不是在 Forward 之前就减掉了 ——
// 否则并发上限永远看到 0，形同虚设。
func TestHandler_InFlightCoversForwarding(t *testing.T) {
	var duringForward int
	hs := newHarness(t, nil)
	hs.up.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, open, _ := hs.tracker.stats() // 上游正在处理时读一次
		duringForward = open
		w.Write([]byte(`{}`))
	})

	hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))

	if duringForward != 1 {
		t.Errorf("转发进行中在途应为 1，得到 %d —— 计数窗口没覆盖转发过程", duringForward)
	}
	if _, open, _ := hs.tracker.stats(); open != 0 {
		t.Errorf("结束后应归零，得到 %d", open)
	}
}

// 选路失败时不该登记在途 —— 那时还没有选中任何 Route。
func TestHandler_NoInFlightWhenSelectFails(t *testing.T) {
	hs := newHarness(t, nil)
	hs.h.health = allAliveHealth{dead: map[int64]bool{100: true}}

	hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))

	if begins, _, _ := hs.tracker.stats(); len(begins) != 0 {
		t.Errorf("选路失败不该登记在途，得到 %v", begins)
	}
}

// 上游出错也要减回去，否则一次故障就会永久占住一个并发额度。
func TestHandler_InFlightReleasedOnUpstreamError(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	})

	hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))

	if _, open, _ := hs.tracker.stats(); open != 0 {
		t.Errorf("上游出错后在途也应归零，得到 %d", open)
	}
}

func TestWriteAPIError_Formats(t *testing.T) {
	// Anthropic 格式：顶层 type=error + error{type,message}
	rec := httptest.NewRecorder()
	writeAPIError(rec, 401, model.ProtoAnthropic, "authentication_error", "无效的 API key")
	body := rec.Body.String()
	if !strings.Contains(body, `"type":"error"`) ||
		!strings.Contains(body, `"authentication_error"`) {
		t.Errorf("Anthropic 错误格式不对：%s", body)
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Error("应声明 JSON")
	}

	// OpenAI 格式：只有 error{message,type,code}，无顶层 type
	for _, p := range []model.Protocol{model.ProtoOpenAIChat, model.ProtoOpenAIResponses} {
		rec = httptest.NewRecorder()
		writeAPIError(rec, 400, p, "invalid_request_error", "坏请求")
		body = rec.Body.String()
		if strings.Contains(body, `"type":"error"`) {
			t.Errorf("%s 不该用 Anthropic 格式：%s", p, body)
		}
		if !strings.Contains(body, `"message":"坏请求"`) {
			t.Errorf("%s 错误格式不对：%s", p, body)
		}
	}
}
