package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
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

// countingHealth 是测试用的健康视图：默认全部可用、不冷却，
// 同时记录 TryAcquire/release 的调用，用于验证并发额度的配平。
//
// 额度的「占」与「放」都在 router.Select / Candidate.Release 里，
// 所以这两件事必须由同一个替身观察 —— 拆开就看不出计数窗口是否覆盖转发。
type countingHealth struct {
	dead map[int64]bool

	mu       sync.Mutex
	acquired []int64 // 按顺序记录占位的 routeID
	open     int
	peak     int // 峰值并发，验证额度窗口真的覆盖了转发过程
	refused  int
}

func newCountingHealth() *countingHealth {
	return &countingHealth{dead: map[int64]bool{}}
}

func (c *countingHealth) State(id int64) model.HealthState {
	if c.dead[id] {
		return model.StateDead
	}
	return model.StateAlive
}
func (c *countingHealth) CoolingDown(int64) bool { return false }

func (c *countingHealth) TryAcquire(routeID int64, limit int) (func(), bool) {
	c.mu.Lock()
	if limit > 0 && c.open >= limit {
		c.refused++
		c.mu.Unlock()
		return nil, false
	}
	c.acquired = append(c.acquired, routeID)
	c.open++
	if c.open > c.peak {
		c.peak = c.open
	}
	c.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			c.open--
			c.mu.Unlock()
		})
	}, true
}

func (c *countingHealth) stats() (acquired []int64, open, peak int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int64(nil), c.acquired...), c.open, c.peak
}

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testSettings 用短超时，避免测试挂在生产的 300s 下限上。
// 那个下限是配置层的约束（SaveSettings 校验），转发层只管用给它的值。
func testSettings() model.Settings {
	s := model.DefaultSettings()
	s.RealConnectSec = 2
	s.RealIdleSec = 2
	s.RealTotalSec = 5
	// 四个阶段上限都要设，不能只设旧的 real_first_token_sec。
	//
	// 生产路径上 store.SaveSettings 会把那个粗旋钮展开到这四个字段，所以从库里
	// 读出来的配置两套都填好了。但这里是手工构造 Settings，只设旧字段的话
	// 新字段仍是默认的 1200 秒 —— 于是「首 Token 超时 2 秒」静默变成 1200 秒，
	// 被 total 兜住，而依赖它换站的重试用例会因为一个与本意无关的原因失败。
	s.RealFirstTokenSec = 2
	s.RealResponseHeaderSec = 2
	s.RealFirstByteSec = 2
	s.RealFirstSemanticSec = 2
	return s
}

// harness 组装一个指向 mock 上游的完整 Handler。
// recordingSink 收下样本供断言。Record 必须非阻塞（与生产实现的契约一致）。
type recordingSink struct {
	mu   sync.Mutex
	got  []*model.Sample
	hook func(*model.Sample) // 可选：投递时同步执行，用于测阻塞行为
}

func (s *recordingSink) Record(smp *model.Sample) {
	s.mu.Lock()
	s.got = append(s.got, smp)
	s.mu.Unlock()
	if s.hook != nil {
		s.hook(smp)
	}
}

func (s *recordingSink) all() []*model.Sample {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*model.Sample(nil), s.got...)
}

func (s *recordingSink) one(t *testing.T) *model.Sample {
	t.Helper()
	got := s.all()
	if len(got) != 1 {
		t.Fatalf("应恰好记录 1 条样本，得到 %d 条", len(got))
	}
	return got[0]
}

type harness struct {
	h       *Handler
	cfg     *fakeConfig
	up      *httptest.Server
	gotReq  *capturedRequest
	health  *countingHealth
	sink    *recordingSink
	relayPW string
}

// capturedRequest 记录 mock 上游收到的最后一个请求。
//
// 写入必须加锁：mock 上游的每个连接都在自己的 goroutine 里跑，
// 并发测试（TestHandler_ConcurrentRequests）会同时写这几个字段。
//
// 读取直接访问字段是安全的，不需要加锁 —— 顺序测试里 hs.serve() 返回时
// HTTP 往返已经完成，那本身就是一条 happens-before 边。并发测试不读这些
// 字段（它只关心状态码与 Transport 复用）。
type capturedRequest struct {
	mu      sync.Mutex
	method  string
	path    string
	query   string
	headers http.Header
	body    []byte
}

func (c *capturedRequest) record(r *http.Request, body []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.method = r.Method
	c.path = r.URL.Path
	c.query = r.URL.RawQuery
	c.headers = r.Header.Clone()
	c.body = body
}

// newHarness 起一个 mock 上游并配好 1 个 ModelName / 1 个 Upstream / 1 条 Route。
// respond 为 nil 时回一个最简 200 JSON。
func newHarness(t *testing.T, respond http.HandlerFunc) *harness {
	t.Helper()

	hs := &harness{gotReq: &capturedRequest{}, health: newCountingHealth(),
		sink: &recordingSink{}, relayPW: "rk-client-key"}

	hs.up = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		hs.gotReq.record(r, body)

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
	// 默认关掉半开，让旧测试不受影响。需要半开的测试自己开。
	hs.cfg.settings.HalfOpenEnabled = false
	hs.h = NewHandler(hs.cfg, hs.health, hs.sink, []string{hs.relayPW}, discardLog()).
		WithTargets(testTargets(hs.cfg), nil)
	t.Cleanup(hs.h.CloseIdleConnections)
	return hs
}

// testTargets 造一个与生产同构的出站解析面：canonical Endpoint + 同一个
// Resolver。
//
// 刻意不用「直接返回 base_url + path」的假实现：那样测试就绕开了 Resolver，
// 而它正是三条出站路径共用的那份规则 —— 绕过它，本要防的分叉就重新回到
// 测试覆盖之外了。
func testTargets(cfg *fakeConfig) *outbound.Provider {
	return outbound.NewProvider(testEndpoints{cfg: cfg}, nil, outbound.NewResolver(testHasher{}))
}

// testEndpoints 按 fakeConfig 里的 Upstream 现造 canonical Endpoint。
//
// url_override 与 auth profile 都由 Upstream 的旧字段翻译而来，走的是
// store.canonicalEndpointBundle 用的那同一套映射 —— 所以测试里的 Endpoint
// 与生产库里那条是同一套规则产出的。auth 若在这里硬编码一种，
// 「auth_style 落到 auth profile」这段翻译就再也没有测试覆盖。
type testEndpoints struct {
	cfg        *fakeConfig
	fixedQuery string
}

func (source testEndpoints) Endpoint(_ context.Context, upstreamID int64,
	kind model.EndpointKind) (*model.UpstreamEndpoint, error) {

	up := &model.Upstream{ID: upstreamID, L1Path: "/v1/models", AuthStyle: model.AuthAuto}
	if source.cfg != nil && source.cfg.snap != nil {
		if found := source.cfg.snap.Upstreams[upstreamID]; found != nil {
			up = found
		}
	}
	mode, headerName := testAuthProfile(up.AuthStyle)
	return &model.UpstreamEndpoint{
		ID: 1, UpstreamID: upstreamID, Kind: kind,
		URLMode:              model.EndpointURLCanonical,
		URLOverride:          up.EndpointURLOverride(kind),
		FixedQueryTemplate:   source.fixedQuery,
		LegacyCompatRealOnly: mode == model.AuthModeLegacyAutoRealOnly,
		AuthProfile: model.EndpointAuthProfile{
			Mode: mode, HeaderName: headerName,
			SecretRef: "upstream_api_key", Revision: 1,
		},
		Revision: 1,
	}, nil
}

// testAuthProfile 与 store.legacyAuthProfile 同构。
//
// 两份而不是共用：store 侧那个是私有的，导出它只为测试用会把一个迁移期的
// 内部细节变成公开契约。auth_style 只有三个值，且它在 P0-17 就会被删掉。
func testAuthProfile(style model.AuthStyle) (model.AuthMode, string) {
	switch style {
	case model.AuthBearer:
		return model.AuthModeBearer, "Authorization"
	case model.AuthXAPIKey:
		return model.AuthModeXAPIKey, "X-Api-Key"
	default:
		// auto → 迁移期的双发兼容。真实转发沿用旧行为（升级不改变线上语义），
		// 合成探活则 fail closed（见 outbound.ApplyAuth）。
		return model.AuthModeLegacyAutoRealOnly, ""
	}
}

type testHasher struct{}

func (testHasher) SumRequestURL(raw []byte) string {
	return fmt.Sprintf("test:%x", len(raw))
}

// testTargetsWithQuery 给每个 Endpoint 配一个固定 query 模板。
// 用于「key 放在 query 里」那类站（§3.2）。
func testTargetsWithQuery(cfg *fakeConfig, template string) *outbound.Provider {
	return outbound.NewProvider(testEndpoints{cfg: cfg, fixedQuery: template}, nil,
		outbound.NewResolver(testHasher{}))
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
	hs.h = NewHandler(hs.cfg, hs.health, hs.sink, nil, discardLog())

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
			setup:      func(hs *harness) { hs.health.dead[100] = true },
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
	hs.health.dead[100] = true

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

// 连接池必须按网络身份复用：每请求新建会丢掉连接复用，
// 对高延迟的公益站来说每次都要重新 TLS 握手。
func TestHandler_ReusesTransportPerUpstream(t *testing.T) {
	hs := newHarness(t, nil)
	budget := outbound.RealBudget(testSettings())
	up := hs.cfg.snap.Upstreams[10]

	tr1, err := hs.h.TransportFor(up, budget)
	if err != nil {
		t.Fatal(err)
	}
	tr2, err := hs.h.TransportFor(up, budget)
	if err != nil {
		t.Fatal(err)
	}
	if tr1 != tr2 {
		t.Error("同一 Upstream 应复用同一个 Transport")
	}

	// 配置变更（尤其 proxy_url）后必须丢弃旧的，否则改了代理不生效
	hs.h.InvalidateTransport(up.ID)
	tr3, err := hs.h.TransportFor(up, budget)
	if err != nil {
		t.Fatal(err)
	}
	if tr3 == tr1 {
		t.Error("InvalidateTransport 后应重建 Transport")
	}
}

// 并发请求下连接池不能出现竞态或重复建池。
// （Windows 上没 cgo 跑不了 -race，这里至少验证功能正确；CI 的 Linux job 跑 race。）
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
	if got := hs.h.transports.PoolCount(); got != 1 {
		t.Errorf("同一 Upstream 的同一份预算应只有 1 个池，得到 %d", got)
	}
}

// ── 并发额度 ──────────────────────────────────────────────

// 选中 Route 即占下额度，请求结束后必须归还。
// 只占不还的话，配了 max_concurrency 的 Route 会被永久排除在选路之外。
func TestHandler_TracksInFlight(t *testing.T) {
	hs := newHarness(t, nil)

	hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))

	acquired, open, peak := hs.health.stats()
	if len(acquired) != 1 || acquired[0] != 100 {
		t.Errorf("应为选中的 Route 100 占一次额度，得到 %v", acquired)
	}
	if open != 0 {
		t.Errorf("请求结束后在途应归零，得到 %d", open)
	}
	if peak != 1 {
		t.Errorf("峰值应为 1，得到 %d", peak)
	}
}

// 额度窗口必须覆盖整个转发过程，而不是在 Forward 之前就还回去了 ——
// 否则并发上限永远看到 0，形同虚设。
func TestHandler_InFlightCoversForwarding(t *testing.T) {
	var duringForward int
	hs := newHarness(t, nil)
	hs.up.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, open, _ := hs.health.stats() // 上游正在处理时读一次
		duringForward = open
		w.Write([]byte(`{}`))
	})

	hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))

	if duringForward != 1 {
		t.Errorf("转发进行中在途应为 1，得到 %d —— 额度窗口没覆盖转发过程", duringForward)
	}
	if _, open, _ := hs.health.stats(); open != 0 {
		t.Errorf("结束后应归零，得到 %d", open)
	}
}

// 选路失败时不该占额度 —— 那时还没有选中任何 Route。
func TestHandler_NoInFlightWhenSelectFails(t *testing.T) {
	hs := newHarness(t, nil)
	hs.health.dead[100] = true

	hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))

	if acquired, _, _ := hs.health.stats(); len(acquired) != 0 {
		t.Errorf("选路失败不该占额度，得到 %v", acquired)
	}
}

// 上游出错也要归还，否则一次故障就会永久占住一个并发额度。
func TestHandler_InFlightReleasedOnUpstreamError(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	})

	hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))

	if _, open, _ := hs.health.stats(); open != 0 {
		t.Errorf("上游出错后在途也应归零，得到 %d", open)
	}
}

// 端到端的并发上限：一批同时打进来的请求，实际到达上游的并发数
// 不得超过 max_concurrency。
//
// 这里断言的是**上游侧**观察到的并发，而不是网关内部的计数 ——
// 内部计数对得上但请求照样都发出去了，是这类 bug 最典型的表现。
// 配 max_concurrency 的通常是「多开一路就限流甚至封号」的公益站，
// 超发一次的代价是整个站不可用。
func TestHandler_ConcurrencyLimitHoldsAtUpstream(t *testing.T) {
	const limit = 2
	const burst = 30

	var mu sync.Mutex
	var atUpstream, peakAtUpstream int

	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		atUpstream++
		if atUpstream > peakAtUpstream {
			peakAtUpstream = atUpstream
		}
		mu.Unlock()

		time.Sleep(20 * time.Millisecond) // 拉长重叠窗口

		mu.Lock()
		atUpstream--
		mu.Unlock()
		w.Write([]byte(`{}`))
	})
	hs.cfg.snap.RoutesByModelName[1][0].MaxConcurrency = limit

	var start sync.WaitGroup
	start.Add(1)
	var wg sync.WaitGroup
	codes := make(chan int, burst)
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start.Wait()
			codes <- hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`)).Code
		}()
	}
	start.Done()
	wg.Wait()
	close(codes)

	var ok, rejected int
	for c := range codes {
		switch c {
		case 200:
			ok++
		case 503: // 达上限被拒是正确行为
			rejected++
		default:
			t.Errorf("意外的状态码 %d", c)
		}
	}

	mu.Lock()
	peak := peakAtUpstream
	mu.Unlock()
	if peak > limit {
		t.Errorf("上游同时收到 %d 个请求，超过 max_concurrency=%d", peak, limit)
	}
	if ok == 0 {
		t.Error("一个都没成功，上限判定过严")
	}
	if _, open, _ := hs.health.stats(); open != 0 {
		t.Errorf("全部结束后额度应归零，得到 %d", open)
	}
}

// ── 样本记录（§9.4）────────────────────────────────────────
//
// 样本功能的失败方式是**悄无声息的** —— 记漏了、记错了、或拖慢了转发，
// 都不会报错。所以下面每一条都对应 §9.4 表格里的一行。

// 不映射时 in_body 与 out_body 必须**完全**逐字节相同。
// 这是「只改了两处」在生产环境的持续验证（§3.6.1）。
func TestSample_UnmappedBodiesAreIdentical(t *testing.T) {
	hs := newHarness(t, nil)
	body := `{"model":"claude-opus-5","max_tokens":1,"temperature":1.0,"system":"A & B"}`

	hs.serve(hs.anthropicRequest(body))

	smp := hs.sink.one(t)
	if !bytes.Equal(smp.InBody, smp.OutBody) {
		t.Errorf("不映射时两份 body 应完全一致\nin  %s\nout %s", smp.InBody, smp.OutBody)
	}
	if string(smp.InBody) != body {
		t.Errorf("样本应留档原始字节\nwant %s\ngot  %s", body, smp.InBody)
	}
	if smp.ModelIn != "claude-opus-5" || smp.ModelOut != "claude-opus-5" {
		t.Errorf("未映射时 model_in/out 应相同：%q / %q", smp.ModelIn, smp.ModelOut)
	}
}

// 映射时两份 body 只应在 model 处不同。
func TestSample_MappedBodiesDifferOnlyInModel(t *testing.T) {
	hs := newHarness(t, nil)
	hs.cfg.snap.RoutesByModelName[1][0].UpstreamModel = "claude-opus-4-20250514"

	hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","max_tokens":1}`))

	smp := hs.sink.one(t)
	if string(smp.InBody) != `{"model":"claude-opus-5","max_tokens":1}` {
		t.Errorf("in_body 应是入站原文，得到 %s", smp.InBody)
	}
	if string(smp.OutBody) != `{"model":"claude-opus-4-20250514","max_tokens":1}` {
		t.Errorf("out_body 应是改写后的字节，得到 %s", smp.OutBody)
	}
	if smp.ModelIn != "claude-opus-5" || smp.ModelOut != "claude-opus-4-20250514" {
		t.Errorf("model_in/out 应分别记录：%q / %q", smp.ModelIn, smp.ModelOut)
	}
}

// §9.4 的验收标准：用真 key 字符串全表 grep，断言 0 命中。
// 不脱敏的话，样本库就是一份明文 key 库，比配置表更容易被整体导出。
func TestSample_NoPlaintextKeysAnywhere(t *testing.T) {
	hs := newHarness(t, nil)
	const upKey = "sk-upstream-secret"

	// key 出现在所有可能的位置：入站头、出站头、以及 body 里
	r := hs.anthropicRequest(`{"model":"claude-opus-5","api_key":"` + hs.relayPW + `"}`)
	r.Header.Set("Authorization", "Bearer "+hs.relayPW)
	r.Header.Set("Api-Key", hs.relayPW)
	hs.serve(r)

	smp := hs.sink.one(t)

	// 把整条样本序列化后整体搜 —— 逐字段检查会漏掉将来新增的字段
	blob, err := json.Marshal(smp)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{hs.relayPW, upKey} {
		if bytes.Contains(blob, []byte(secret)) {
			t.Errorf("样本里出现了完整 key %q —— 样本库不能是明文 key 库", secret)
		}
	}

	// 脱敏必须保留结构：调探活时要知道 key 放在哪个头、什么格式（§3.6.3b）
	if got := smp.OutHeaders.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
		t.Errorf("应保留 Bearer 前缀（探活模板要用），得到 %q", got)
	}
	if smp.OutHeaders.Get("X-Api-Key") == "" {
		t.Error("应保留 X-Api-Key 头名，只脱敏值")
	}
}

// body 超限时截断并标记，但**转发的 body 仍是完整的**。
// 这条最容易写错成「截断后再转发」，那会直接破坏请求。
func TestSample_TruncatesBodyButForwardsFull(t *testing.T) {
	hs := newHarness(t, nil)
	hs.cfg.settings.SampleMaxBodyBytes = 1024

	filler := strings.Repeat("x", 4096)
	body := `{"model":"claude-opus-5","system":"` + filler + `"}`
	hs.serve(hs.anthropicRequest(body))

	// 转发出去的必须是完整的原文
	if string(hs.gotReq.body) != body {
		t.Errorf("转发的 body 必须完整（%d 字节），实际发出 %d 字节",
			len(body), len(hs.gotReq.body))
	}

	smp := hs.sink.one(t)
	if len(smp.InBody) >= len(body) {
		t.Errorf("样本里的 body 应被截断，得到 %d 字节", len(smp.InBody))
	}
	if !smp.Truncated.Has(model.TruncInBody) {
		t.Error("应标记 in_body 被截断 —— 不标记的话无法判断是恰好这么大还是被砍过")
	}
	if !smp.Truncated.Has(model.TruncOutBody) {
		t.Error("应标记 out_body 被截断")
	}
}

// 大 SSE 响应存头 + 尾，转发给客户端的仍是完整流。
func TestSample_LargeSSEKeepsHeadAndTail(t *testing.T) {
	const chunks = 400
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		w.Write([]byte("event: message_start\ndata: {\"head\":true}\n\n"))
		fl.Flush()
		for i := 0; i < chunks; i++ {
			w.Write([]byte("data: " + strings.Repeat("m", 200) + "\n\n"))
		}
		w.Write([]byte("event: message_stop\ndata: {\"usage\":{\"output_tokens\":42}}\n\n"))
		fl.Flush()
	})
	hs.cfg.settings.SampleRespHeadBytes = 512
	hs.cfg.settings.SampleRespTailBytes = 256

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","stream":true}`))

	// 客户端必须收到完整流
	if n := strings.Count(rec.Body.String(), "data: "); n != chunks+2 {
		t.Errorf("客户端应收到全部 %d 个事件，得到 %d", chunks+2, n)
	}

	smp := hs.sink.one(t)
	if len(smp.RespBody) > 1024 {
		t.Errorf("样本响应体应被封顶，得到 %d 字节", len(smp.RespBody))
	}
	// 头部含错误信息与首个 delta
	if !bytes.Contains(smp.RespBody, []byte("message_start")) {
		t.Error("应保留头部（含首个 delta 与错误信息）")
	}
	// 尾部含 message_stop 与 usage —— 公益站配额排查最需要的正是这个
	if !bytes.Contains(smp.RespBody, []byte("output_tokens")) {
		t.Error("应保留尾部的 usage —— 「这次花了多少 token」只能从这里看到")
	}
	if !smp.Truncated.Has(model.TruncRespBody) {
		t.Error("应标记 resp_body 被截断")
	}
}

// 上游 500 的样本必须完整落库。恰恰是失败的那次，
// 才需要知道「我到底发了什么头过去」。
func TestSample_RecordsUpstreamFailure(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte(`{"error":"internal"}`))
	})

	hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))

	smp := hs.sink.one(t)
	if smp.Outcome != model.OutcomeUpstreamError {
		t.Errorf("outcome 应为 upstream_error，得到 %q", smp.Outcome)
	}
	if smp.RespStatus != 500 {
		t.Errorf("应记录状态码 500，得到 %d", smp.RespStatus)
	}
	if len(smp.OutHeaders) == 0 {
		t.Error("失败样本更要留下出站头 —— 那正是排查时要看的")
	}
	if !bytes.Contains(smp.RespBody, []byte("internal")) {
		t.Error("应留下上游的错误响应体")
	}
}

// 关掉开关时零写入，转发不受影响。
func TestSample_DisabledRecordsNothing(t *testing.T) {
	hs := newHarness(t, nil)
	hs.cfg.settings.SampleEnabled = false

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))

	if rec.Code != 200 {
		t.Errorf("关掉样本不该影响转发，得到 %d", rec.Code)
	}
	if got := hs.sink.all(); len(got) != 0 {
		t.Errorf("开关关闭时不该有任何写入，得到 %d 条", len(got))
	}
}

// key 出现在 URL 里时也必须脱敏（§3.6.3b / §9.4）。
//
// 曾经的漏洞：只脱敏了三组头与三份 body，in_query 与 out_url 是原样落库的。
// 而 §3.2 明确写了「少数中转站也接受 ?key= 查询参数」，full_url_mode 的
// base_url 正是为这类站准备的 —— 它会被整段存进 out_url。
// 验收标准是「真 key 全表 grep 零命中」，漏一个字段就不成立。
func TestSample_RedactsKeysInURL(t *testing.T) {
	t.Run("固定 query 里的上游 key", func(t *testing.T) {
		const upKey = "sk-upstream-secret-in-url"
		hs := newHarness(t, nil)
		up := hs.cfg.snap.Upstreams[10]
		up.APIKey = upKey
		// 「key 放在 query 里」的站在 schema 2 里由 Endpoint 的固定 query
		// 模板表达（§7.1），而不是把 key 塞进 base_url —— 后者带 query
		// 本就过不了 validateBaseURL。
		hs.h = hs.h.WithTargets(testTargetsWithQuery(hs.cfg, "key={{UPSTREAM_API_KEY}}"), nil)

		hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))

		smp := hs.sink.one(t)
		if strings.Contains(smp.OutURL, upKey) {
			t.Errorf("out_url 明文含上游 key：%q", smp.OutURL)
		}
		// 脱敏不该把 URL 整段抹掉 —— 样本还要能看出打的是哪个端点
		if !strings.Contains(smp.OutURL, "/v1/messages") {
			t.Errorf("脱敏后仍应能看出端点路径，得到 %q", smp.OutURL)
		}
	})

	t.Run("入站 query 带 relay key", func(t *testing.T) {
		hs := newHarness(t, nil)

		r := httptest.NewRequest("POST",
			"/v1/messages?beta=true&key="+hs.relayPW,
			strings.NewReader(`{"model":"claude-opus-5"}`))
		r.Header = claudeCodeHeaders()
		r.Header.Set("X-Api-Key", hs.relayPW)

		mux := http.NewServeMux()
		hs.h.Routes(mux)
		mux.ServeHTTP(httptest.NewRecorder(), r)

		smp := hs.sink.one(t)
		if strings.Contains(smp.InQuery, hs.relayPW) {
			t.Errorf("in_query 明文含 relay key：%q", smp.InQuery)
		}
		if strings.Contains(smp.OutURL, hs.relayPW) {
			t.Errorf("out_url 明文含 relay key：%q", smp.OutURL)
		}
		// beta=true 必须还在：它是诊断「上游为何拒绝」的关键信息
		if !strings.Contains(smp.InQuery, "beta=true") {
			t.Errorf("非 key 的 query 参数不该被动，得到 %q", smp.InQuery)
		}
	})
}

// 转发出去的 URL 本身**不能**被脱敏影响 —— 脱敏只作用于样本副本。
// 搞混的话上游会收到一个打了码的 key，症状是「配了 key 却一直 401」。
func TestSample_RedactionDoesNotAffectForwardedURL(t *testing.T) {
	const upKey = "sk-upstream-secret-in-url"
	var gotQuery string

	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Write([]byte(`{}`))
	})
	hs.cfg.snap.Upstreams[10].APIKey = upKey
	hs.h = hs.h.WithTargets(testTargetsWithQuery(hs.cfg, "key={{UPSTREAM_API_KEY}}"), nil)

	hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))

	if !strings.Contains(gotQuery, "key="+upKey) {
		t.Errorf("上游应收到**明文** key，得到 %q", gotQuery)
	}
	// 固定 query 与入站 query 之间只能有一个 &，且不能出现第二个 ? ——
	// 拼出 ?key=x?beta=true 是非法 URL，上游会拒或把后半段当成 key 的一部分。
	if strings.Count(gotQuery, "?") != 0 {
		t.Errorf("query 里不该出现第二个 ?，得到 %q", gotQuery)
	}
	if !strings.Contains(gotQuery, "beta=true") {
		t.Errorf("入站 query 应被续接上，得到 %q", gotQuery)
	}
	// 顺序是固定 query 在前、入站在后（§7.1）
	if gotQuery != "key="+upKey+"&beta=true" {
		t.Errorf("固定 query 应在前、入站在后，得到 %q", gotQuery)
	}
}

// 四个时间戳都要记，且顺序合理 —— 它们的差值就是排队时长、TTFT、总时长。
func TestSample_Timestamps(t *testing.T) {
	hs := newHarness(t, nil)
	hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))

	smp := hs.sink.one(t)
	if smp.TSRecv == 0 || smp.TSSent == 0 || smp.TSFirstByte == 0 || smp.TSDone == 0 {
		t.Fatalf("四个时间戳都应填充：recv=%d sent=%d first=%d done=%d",
			smp.TSRecv, smp.TSSent, smp.TSFirstByte, smp.TSDone)
	}
	if smp.TSRecv > smp.TSSent || smp.TSSent > smp.TSFirstByte || smp.TSFirstByte > smp.TSDone {
		t.Errorf("时间戳顺序应为 recv ≤ sent ≤ first_byte ≤ done，得到 %d %d %d %d",
			smp.TSRecv, smp.TSSent, smp.TSFirstByte, smp.TSDone)
	}
}

// 选路结果要留档，否则无法回溯「为什么走了这个站」。
func TestSample_RecordsRoutingDecision(t *testing.T) {
	hs := newHarness(t, nil)
	hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))

	smp := hs.sink.one(t)
	if smp.RouteID != 100 || smp.UpstreamID != 10 || smp.ModelNameID != 1 {
		t.Errorf("选路结果应完整留档：route=%d upstream=%d model_name=%d",
			smp.RouteID, smp.UpstreamID, smp.ModelNameID)
	}
	if smp.Endpoint != "/v1/messages" {
		t.Errorf("endpoint 应记录，得到 %q", smp.Endpoint)
	}
	// query 丢了会改变上游行为，必须留档
	if smp.InQuery != "beta=true" {
		t.Errorf("in_query 应留档，得到 %q", smp.InQuery)
	}
	if !strings.HasPrefix(smp.OutURL, hs.up.URL) {
		t.Errorf("out_url 应记录实际发往的地址，得到 %q", smp.OutURL)
	}
}

// 200 但一个字节都没吐的站要单独分类 —— 它最容易被误判成好站。
func TestSample_FakeAliveOutcome(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200) // 头回了，body 一个字节都没有
	})

	hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))

	if smp := hs.sink.one(t); smp.Outcome != model.OutcomeFakeAlive {
		t.Errorf("200 但零字节应归类为 fake_alive，得到 %q", smp.Outcome)
	}
}

// 选路失败时不记样本 —— 那时还没选中任何站，没有「发往公益站的请求」可记。
func TestSample_NotRecordedWhenSelectFails(t *testing.T) {
	hs := newHarness(t, nil)
	hs.health.dead[100] = true

	hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))

	if got := hs.sink.all(); len(got) != 0 {
		t.Errorf("选路失败不该记样本，得到 %d 条", len(got))
	}
}

// 回归测试：响应体与响应头里的 key 也必须脱敏。
//
// 曾经的 bug：只扫了 in_body/out_body，漏掉 resp_body 与 resp_headers。
// 真实中转站的鉴权错误经常把 key 回显在消息里
// （`{"error":"Invalid API key: sk-xxx"}` 是常见格式），
// 漏这一处，样本库里就躺着明文 key —— 而 §3.6.3b 的要求是无条件的。
func TestSample_RedactsKeysInResponseToo(t *testing.T) {
	const upKey = "sk-upstream-secret"
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		// 上游把收到的 key 原样回显（错误消息里带 key 的真实写法）
		w.Header().Set("X-Api-Key", upKey)
		w.Header().Set("Set-Cookie", "session="+upKey)
		w.WriteHeader(401)
		w.Write([]byte(`{"error":{"message":"Invalid API key: ` + upKey + ` provided"}}`))
	})

	r := hs.anthropicRequest(`{"model":"claude-opus-5"}`)
	hs.serve(r)

	smp := hs.sink.one(t)
	blob, err := json.Marshal(smp)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{upKey, hs.relayPW} {
		if bytes.Contains(blob, []byte(secret)) {
			t.Errorf("响应里回显的 key %q 未脱敏 —— 样本库不能是明文 key 库", secret)
		}
	}
	// 但错误信息的其余部分必须留下：那正是排查时要看的
	if !bytes.Contains(smp.RespBody, []byte("Invalid API key")) {
		t.Errorf("脱敏不该毁掉错误信息本身，得到 %s", smp.RespBody)
	}
}

// signalWriter 在第一次 Write 时发信号，让测试能等到
// 「网关确实已把数据交给客户端」这个确定的时刻。
type signalWriter struct {
	*httptest.ResponseRecorder
	once  sync.Once
	wrote chan struct{}
}

func (s *signalWriter) Write(p []byte) (int, error) {
	n, err := s.ResponseRecorder.Write(p)
	s.once.Do(func() { close(s.wrote) })
	return n, err
}

func (s *signalWriter) Flush() { s.ResponseRecorder.Flush() }

// §9.4 最后一行，文档特别强调的一条：客户端中途断开时
// outcome=client_abort，且**已收到的部分照常留档**。
//
// 「失败请求的样本不能丢」—— 恰恰是失败的那次，才需要知道
// 「我到底发了什么头过去」。
func TestSample_ClientAbortStillRecorded(t *testing.T) {
	release := make(chan struct{})
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte("event: message_start\ndata: {\"partial\":true}\n\n"))
		w.(http.Flusher).Flush()
		<-release // 客户端取消后才收工
	})
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	r := hs.anthropicRequest(`{"model":"claude-opus-5","stream":true}`).WithContext(ctx)

	// 等网关把首块写给客户端之后再取消。
	// 直接在上游 flush 后就 cancel 是不行的：那时网关的读循环可能还没
	// 把这块数据从 socket 读出来，ctx 看门狗就先关了连接 ——
	// 于是「已收到的部分」真的是空的，测试会随机失败。
	rec := &signalWriter{ResponseRecorder: httptest.NewRecorder(),
		wrote: make(chan struct{})}
	go func() {
		select {
		case <-rec.wrote:
		case <-time.After(3 * time.Second):
		}
		cancel()
	}()

	mux := http.NewServeMux()
	hs.h.Routes(mux)
	mux.ServeHTTP(rec, r)

	smp := hs.sink.one(t)
	if smp.Outcome != model.OutcomeClientAbort {
		t.Errorf("客户端断开应归类为 client_abort，得到 %q（error=%q）",
			smp.Outcome, smp.Error)
	}
	// 已收到的部分必须留档
	if !bytes.Contains(smp.RespBody, []byte("message_start")) {
		t.Errorf("已收到的响应片段应留档，得到 %q", smp.RespBody)
	}
	// 出站头是排查时最需要的东西
	if smp.OutHeaders.Get("User-Agent") == "" {
		t.Error("失败样本更要留下出站头")
	}
	if smp.RouteID == 0 {
		t.Error("选路结果应留档")
	}
}

// ── 上游故障必须变成客户端可见的错误 ──────────────────────
//
// 这一组是整条链路最容易悄悄坏掉的地方：Forward 在拿到响应头之前失败时
// 一个字节都没写给客户端，若 serve() 不管，net/http 会在 handler 返回时
// 补一个 **HTTP 200 空 body** —— 客户端拿到的是「成功但没内容」，
// 既看不到错误也不会重试。

func TestHandler_ConnectFailureIsNot200(t *testing.T) {
	hs := newHarness(t, nil)
	// 指向一个不会有服务的地址
	hs.cfg.snap.Upstreams[10].BaseURL = "http://127.0.0.1:1"

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))

	if rec.Code == 200 {
		t.Fatalf("连不上上游却回了 200 —— 客户端会把空响应当成成功。body=%q",
			rec.Body.String())
	}
	if rec.Code != http.StatusBadGateway {
		t.Errorf("连接失败应回 502，得到 %d", rec.Code)
	}
	// 必须是客户端能解析的协议错误结构
	if !strings.Contains(rec.Body.String(), "api_error") {
		t.Errorf("应回 Anthropic 格式的错误，得到 %q", rec.Body.String())
	}
	if rec.Header().Get("X-Relay-Reason") == "" {
		t.Error("应带 X-Relay-Reason 说明是哪一步失败")
	}
}

// 首 Token 超时同样发生在写响应头之前（上游连头都没回），也必须变成错误。
func TestHandler_HeaderPhaseStallIsNot200(t *testing.T) {
	release := make(chan struct{})
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		<-release // 连响应头都不回
	})
	defer close(release)
	hs.cfg.settings.RealFirstTokenSec = 1
	hs.cfg.settings.RealTotalSec = 30

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))

	if rec.Code == 200 {
		t.Fatalf("上游卡在响应头阶段却回了 200，body=%q", rec.Body.String())
	}
	if rec.Code != http.StatusGatewayTimeout {
		t.Errorf("超时应回 504，得到 %d", rec.Code)
	}
}

// 响应头已经发出后再失败，就不能再改状态码了 ——
// 那时客户端已经拿到 200，只能断流。
func TestHandler_MidStreamFailureKeepsStatus(t *testing.T) {
	release := make(chan struct{})
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		w.Write([]byte("data: partial\n\n"))
		w.(http.Flusher).Flush()
		<-release
	})
	defer close(release)
	hs.cfg.settings.RealIdleSec = 1

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","stream":true}`))

	if rec.Code != 200 {
		t.Errorf("响应头已发出后状态码不该改变，得到 %d", rec.Code)
	}
	// 已收到的部分必须留给客户端
	if !strings.Contains(rec.Body.String(), "data: partial") {
		t.Error("已收到的片段应已写给客户端")
	}
	// 但不能再往里塞错误 JSON —— 那会污染 SSE 流
	if strings.Contains(rec.Body.String(), "api_error") {
		t.Error("流已开始后不该再写错误结构，会破坏 SSE 解析")
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
