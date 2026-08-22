package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/probetemplate"
)

// drainBody 读完请求体。假上游**必须**这么做，否则断流相关的断言全是假的。
//
// Go 的 http.Server 只在请求体被读完（或本来就没有体）之后才启动后台读，
// 而正是那个后台读负责发现「客户端断开了」并取消 r.Context()。handler 不读
// body 的话，服务端永远察觉不到客户端已经走了 —— 测试于是看不到断流，
// 而真实上游一定会读 body（它得解析 model 与 messages 才能生成），
// 所以那种失败是测试失真，不是实现有问题。
func drainBody(r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
}

// fastSettings 把超时压到毫秒级，让超时用例不必真等 120 秒。
func fastSettings() model.Settings {
	s := model.DefaultSettings()
	s.L1TotalSec = 2
	s.L2TotalSec = 2
	s.L2FirstTokenSec = 1
	return s
}

func testProber() *Prober {
	return &Prober{Transport: http.DefaultTransport, Targets: testTargets()}
}

// testTargets 造一个内存版 TargetProvider，行为与生产装配一致：
// canonical Endpoint + 同一个 Resolver。
//
// 不用假的「直接回 base_url」实现：那样测试就不再覆盖 Resolver，而它正是
// 探活与真实转发共用的那一份 URL 规则 —— 绕过它等于把本要防的分叉
// 重新引进测试里。
func testTargets() *outbound.Provider {
	return outbound.NewProvider(testEndpoints{}, nil, outbound.NewResolver(testHasher{}))
}

// testEndpoints 为任意 (upstream, kind) 现造一条 canonical Endpoint。
//
// url_override 与 auth profile 都由 Upstream 的旧字段翻译而来，走的是
// store.canonicalEndpointBundle 用的那同一套映射 —— 这样测试里的 Endpoint
// 与生产库里的那条是同一套规则产出的。auth 若在这里硬编码一种，
// 探活测试就再也覆盖不到「auth_style 落到 auth profile」这段翻译。
type testEndpoints struct{ upstream *model.Upstream }

func (source testEndpoints) Endpoint(_ context.Context, upstreamID int64,
	kind model.EndpointKind) (*model.UpstreamEndpoint, error) {

	upstream := source.upstream
	if upstream == nil {
		// 多数用例只关心 canonical path，不配 override。
		// 显式 x-api-key 而不是默认的 auto：auto 会映射成
		// legacy_auto_real_only，而它对合成探活 fail closed（未校准的认证
		// 不能猜）—— 那时用例会红在一个与它本意无关的地方。
		upstream = &model.Upstream{ID: upstreamID, L1Path: "/v1/models",
			AuthStyle: model.AuthXAPIKey}
	}
	mode, headerName := testAuthProfile(upstream.AuthStyle)
	return &model.UpstreamEndpoint{
		ID: 1, UpstreamID: upstreamID, Kind: kind,
		URLMode:              model.EndpointURLCanonical,
		URLOverride:          upstream.EndpointURLOverride(kind),
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
// 两份而不是共用：store 侧那个是私有的，而导出它只为测试用会把一个
// 迁移期的内部细节变成公开契约。同构的代价是这里要跟着改 ——
// 但 auth_style 只有三个值，且它在 P0-17 就会被删掉。
func testAuthProfile(style model.AuthStyle) (model.AuthMode, string) {
	switch style {
	case model.AuthBearer:
		return model.AuthModeBearer, "Authorization"
	case model.AuthXAPIKey:
		return model.AuthModeXAPIKey, "X-Api-Key"
	default:
		return model.AuthModeLegacyAutoRealOnly, ""
	}
}

type testHasher struct{}

func (testHasher) SumRequestURL(raw []byte) string {
	return fmt.Sprintf("test:%x", len(raw))
}

// proberFor 造一个 Endpoint 配置跟随该 Upstream 的 Prober。
// 需要覆盖 l1_path / full_url_mode 行为的用例用它。
func proberFor(up *model.Upstream) *Prober {
	return &Prober{
		Transport: http.DefaultTransport,
		Targets: outbound.NewProvider(testEndpoints{upstream: up}, nil,
			outbound.NewResolver(testHasher{})),
	}
}

func upstreamFor(url string) *model.Upstream {
	return &model.Upstream{
		ID: 1, Name: "test", BaseURL: url, APIKey: "sk-test-key-123456",
		// **必须显式给 AuthStyle**。默认的 auto 会映射成
		// legacy_auto_real_only，而它对合成探活是 fail closed 的
		// （未校准的认证方式不能猜，见 outbound.ApplyAuth）—— 那时探活
		// 一个请求都发不出去，测试会红在一个与本意无关的地方。
		// 「auto 探活 fail closed」本身由 TestProbe_LegacyAutoFailsClosed 覆盖。
		AuthStyle: model.AuthXAPIKey, L1Path: "/v1/models", Enabled: true,
	}
}

func modelNameFor(proto model.Protocol) *model.ModelName {
	mn := &model.ModelName{ID: 1, Name: "claude-opus-5", Protocol: proto, Enabled: true}
	mn.Defaults()
	return mn
}

// ── L1 ───────────────────────────────────────────────────

func TestL1_Verdicts(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   health.Verdict
	}{
		{"200 通过", 200, `{"data":[]}`, health.VerdictOK},
		// 很多站不提供 /v1/models 但 /v1/messages 正常。判失败会整站连坐 ——
		// L1 是 Upstream 粒度的，一次误判会拖死它下面所有 Route。
		{"404 视为通过", 404, `not found`, health.VerdictOK},
		{"405 视为通过", 405, `method not allowed`, health.VerdictOK},
		{"401 整站鉴权失败", 401, `{"error":"bad key"}`, health.VerdictFatal},
		{"403 整站被拒", 403, `forbidden`, health.VerdictFatal},
		{"500 服务不可用", 500, `boom`, health.VerdictUnavailable},
		{"503 服务不可用", 503, `unavailable`, health.VerdictUnavailable},
		{"429 限流", 429, `slow down`, health.VerdictRateLimited},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/models" {
					t.Errorf("L1 应打 l1_path，得到 %s", r.URL.Path)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			out := testProber().L1(context.Background(), upstreamFor(srv.URL), fastSettings())
			if out.Verdict != tc.want {
				t.Errorf("期望 %s，得到 %s（err=%v）", tc.want, out.Verdict, out.Err)
			}
		})
	}
}

// L1 必须带上鉴权与 Claude Code 指纹。M0 实测有站按 UA 白名单拦截，
// 探活不带 UA 会把活站判成死站。
func TestL1_SendsAuthAndClaudeCodeFingerprint(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	up := upstreamFor(srv.URL)
	proberFor(up).L1(context.Background(), up, fastSettings())

	// 认证由 outbound.ApplyAuth 按 Endpoint 的 auth profile 写入 ——
	// x_api_key 这一种就只发这一个头，不再双发（§7.2）。
	if v := got.Get("X-Api-Key"); v != up.APIKey {
		t.Errorf("x_api_key profile 应发 x-api-key，得到 %q", v)
	}
	if v := got.Get("Authorization"); v != "" {
		t.Errorf("只该发一种认证方式，Authorization 应为空，得到 %q", v)
	}
	if ua := got.Get("User-Agent"); !contains(ua, "claude-cli/") {
		t.Errorf("必须伪装成 Claude Code（有站按 UA 白名单拦截），得到 %q", ua)
	}
	if b := got.Get("Anthropic-Beta"); !contains(b, "claude-code-") {
		t.Errorf("应带 anthropic-beta 开关集，得到 %q", b)
	}
	// 真实 Claude Code 不发 context-1m，加上它反而与真实请求不一致
	if b := got.Get("Anthropic-Beta"); contains(b, "context-1m") {
		t.Errorf("不该带 context-1m（真实 CC 不发它），得到 %q", b)
	}
}

// 旧 auth_style=auto 的站，合成探活必须 fail closed 且**不发网络请求**。
//
// 这是 P0-04 刻意引入的门禁（计划 §P0-04 第 11 条）：auto 映射成
// legacy_auto_real_only，而「同时发两种认证」对探活是无依据的猜测。
// 真实转发仍沿用旧的双发行为（升级不改变线上语义），探活则要求先校准。
//
// 代价是升级后所有未校准的旧站探活都会落到这里 —— 但那正是要显式暴露的
// 状态，而不是让探活用一种认证、真实请求用另一种。
func TestProbe_LegacyAutoFailsClosedWithoutSendingRequest(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(200)
	}))
	defer srv.Close()

	up := upstreamFor(srv.URL)
	up.AuthStyle = model.AuthAuto // → legacy_auto_real_only

	out := proberFor(up).L1(context.Background(), up, fastSettings())
	if out.Verdict == health.VerdictOK {
		t.Error("未校准的 auto 认证不该判成功")
	}
	if hits != 0 {
		t.Errorf("必须在写 socket 前失败，上游收到了 %d 个请求", hits)
	}
	if out.Err == nil {
		t.Fatal("应带上原因，否则用户看不出该去做什么")
	}
	if !contains(out.Err.Error(), "校准") {
		t.Errorf("错误应引导用户去校准，得到 %v", out.Err)
	}
	// 错误里不得出现 key 明文：它会落进 route_health.last_error 并显示在 UI 上。
	if contains(out.Err.Error(), up.APIKey) {
		t.Errorf("错误文本泄露了 api_key: %v", out.Err)
	}
}

// l1_path 为空表示只做连接层探测，给连 /v1/models 都报错的站留退路。
func TestL1_EmptyPathProbesConnectionOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("空 l1_path 应发 HEAD，得到 %s", r.Method)
		}
		// 故意回 500：连接层探测只关心能不能建立连接
		w.WriteHeader(500)
	}))
	defer srv.Close()

	up := upstreamFor(srv.URL)
	up.L1Path = ""
	out := testProber().L1(context.Background(), up, fastSettings())
	if out.Verdict != health.VerdictOK {
		t.Errorf("连接层探测只要能连上就算通，得到 %s（err=%v）", out.Verdict, out.Err)
	}
}

func TestL1_ConnectionRefusedIsUnavailable(t *testing.T) {
	// 关掉的服务器 → 连接被拒
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	out := testProber().L1(context.Background(), upstreamFor(url), fastSettings())
	if out.Verdict != health.VerdictUnavailable {
		t.Errorf("连不上应判服务不可用，得到 %s", out.Verdict)
	}
}

// 探活被取消（服务暂停、进程关闭）不是上游的问题。
func TestL1_CanceledContextIsIgnored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	out := testProber().L1(ctx, upstreamFor(srv.URL), fastSettings())
	if out.Verdict != health.VerdictIgnore {
		t.Errorf("被取消的探活不该算上游故障，得到 %s（err=%v）", out.Verdict, out.Err)
	}
}

// ── L2 ───────────────────────────────────────────────────

const aliveSSE = "event: message_start\n" +
	`data: {"type":"message_start","message":{"id":"x"}}` + "\n\n" +
	"event: content_block_delta\n" +
	`data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"2"}}` + "\n\n"

func sseServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		drainBody(r)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		// 首字节前留一点延迟，让 TTFT 可测量。
		//
		// 不加的话本机回环能在亚毫秒内吐完，而 Windows 的时钟粒度会把
		// time.Since 取整成 0，「应测到首 Token 延迟」的断言就随机失败。
		// 真实上游不存在 0 延迟，所以加延迟是让测试更像真实场景，不是放宽断言。
		time.Sleep(2 * time.Millisecond)
		fl, _ := w.(http.Flusher)
		for _, line := range splitKeepNL(body) {
			_, _ = w.Write([]byte(line))
			if fl != nil {
				fl.Flush()
			}
		}
	}))
}

// splitKeepNL 按行切分但保留换行符，用于模拟逐块 flush 的 SSE。
func splitKeepNL(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i+1])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func TestL2_AliveStream(t *testing.T) {
	srv := sseServer(t, aliveSSE)
	defer srv.Close()

	out := testProber().L2(context.Background(), upstreamFor(srv.URL),
		modelNameFor(model.ProtoAnthropic), &model.Route{ID: 1}, fastSettings())

	if out.Verdict != health.VerdictOK {
		t.Errorf("有 text_delta 应判存活，得到 %s（err=%v）", out.Verdict, out.Err)
	}
	if out.TTFT <= 0 {
		t.Error("应测到首 Token 延迟 —— 这是 stream:true 的目的")
	}
}

// §9.3：假活（200 但无内容）必须被 L2 判死。
func TestL2_FakeAliveIsUnavailable(t *testing.T) {
	srv := sseServer(t, "event: message_start\ndata: {\"type\":\"message_start\"}\n\n"+
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	defer srv.Close()

	out := testProber().L2(context.Background(), upstreamFor(srv.URL),
		modelNameFor(model.ProtoAnthropic), &model.Route{ID: 1}, fastSettings())

	if out.Verdict != health.VerdictUnavailable {
		t.Errorf("200 但无有效 delta 是假活，应判不可用，得到 %s", out.Verdict)
	}
	if out.Err == nil || !contains(out.Err.Error(), "假活") {
		t.Errorf("错误信息应说明是假活，得到 %v", out.Err)
	}
}

// 流内 error 事件要按内容再分类：overloaded 是限流，不是故障。
func TestL2_StreamErrorIsClassifiedByContent(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    health.Verdict
	}{
		{"overloaded 判限流", `{"type":"error","error":{"type":"overloaded_error"}}`, health.VerdictRateLimited},
		{"流内 401 判致命", `{"type":"error","error":{"code":401,"message":"invalid key"}}`, health.VerdictFatal},
		{"其余判不可用", `{"type":"error","error":{"message":"internal"}}`, health.VerdictUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := sseServer(t, "event: error\ndata: "+tc.payload+"\n\n")
			defer srv.Close()

			out := testProber().L2(context.Background(), upstreamFor(srv.URL),
				modelNameFor(model.ProtoAnthropic), &model.Route{ID: 1}, fastSettings())
			if out.Verdict != tc.want {
				t.Errorf("期望 %s，得到 %s（err=%v）", tc.want, out.Verdict, out.Err)
			}
		})
	}
}

// §9.3：首 Token 超时要判死且**主动断流**，不继续耗 token。
func TestL2_FirstTokenTimeout(t *testing.T) {
	released := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		drainBody(r)
		// 收下请求但一直不回响应头
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
		close(released)
	}))
	defer srv.Close()

	s := fastSettings()
	s.L2FirstTokenSec = 1
	s.L2TotalSec = 10

	start := time.Now()
	out := testProber().L2(context.Background(), upstreamFor(srv.URL),
		modelNameFor(model.ProtoAnthropic), &model.Route{ID: 1}, s)
	elapsed := time.Since(start)

	if out.Verdict != health.VerdictUnavailable {
		t.Errorf("首 Token 超时应判不可用，得到 %s", out.Verdict)
	}
	if elapsed > 3*time.Second {
		t.Errorf("应在 L2FirstTokenSec(1s) 附近超时，实际用了 %v", elapsed)
	}
	// 主动断流的证据：服务端的 request context 被取消了
	select {
	case <-released:
	case <-time.After(2 * time.Second):
		t.Error("超时后应主动断开连接，不让上游继续生成")
	}
}

// 判定一出立即断流（§4.1）。不断流的话每次探活都把 max_tokens 耗完，
// 对每 30 秒探一次的死站是持续浪费。
func TestL2_ClosesStreamAfterVerdict(t *testing.T) {
	gone := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		drainBody(r)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fl, _ := w.(http.Flusher)
		_, _ = w.Write([]byte(aliveSSE))
		if fl != nil {
			fl.Flush()
		}
		// 继续吐，直到客户端断开
		for i := 0; i < 200; i++ {
			if _, err := w.Write([]byte("event: content_block_delta\ndata: {}\n\n")); err != nil {
				gone <- struct{}{}
				return
			}
			if fl != nil {
				fl.Flush()
			}
			select {
			case <-r.Context().Done():
				gone <- struct{}{}
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
	}))
	defer srv.Close()

	out := testProber().L2(context.Background(), upstreamFor(srv.URL),
		modelNameFor(model.ProtoAnthropic), &model.Route{ID: 1}, fastSettings())
	if out.Verdict != health.VerdictOK {
		t.Fatalf("应判存活，得到 %s", out.Verdict)
	}

	select {
	case <-gone:
	case <-time.After(3 * time.Second):
		t.Error("判定出结果后应立即断流，停止消耗上游 token")
	}
}

// HTTP 层错误（4xx/5xx）直接走 ClassifyHTTP。
func TestL2_HTTPErrorStatuses(t *testing.T) {
	tests := []struct {
		status int
		body   string
		want   health.Verdict
	}{
		{401, `{"error":"bad key"}`, health.VerdictFatal},
		{400, `{"error":{"message":"model not found"}}`, health.VerdictFatal},
		{429, `{"error":"rate limited"}`, health.VerdictRateLimited},
		{503, `unavailable`, health.VerdictUnavailable},
	}
	for _, tc := range tests {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			out := testProber().L2(context.Background(), upstreamFor(srv.URL),
				modelNameFor(model.ProtoAnthropic), &model.Route{ID: 1}, fastSettings())
			if out.Verdict != tc.want {
				t.Errorf("HTTP %d：期望 %s，得到 %s", tc.status, tc.want, out.Verdict)
			}
		})
	}
}

// ── 探活请求体 ────────────────────────────────────────────

// captureL2 发一次 L2 并交出上游实际收到的请求。
//
// 断言实际发出去的字节而不是某个构造函数的返回值：请求内容现在由
// 四级解析 + 模板渲染产出（execute.go），中间还有 Endpoint 固定 query、
// 认证装配、Upstream 级头覆盖三步 —— 只验中间产物的话，「渲染对了但
// 装配时被覆盖」这类问题测不出来。
func captureL2(t *testing.T, proto model.Protocol, rt *model.Route) (*http.Request, []byte) {
	t.Helper()

	var got *http.Request
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		got = r.Clone(context.Background())
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(aliveSSE))
	}))
	defer srv.Close()

	mn := modelNameFor(proto)
	out := testProber().L2(context.Background(), upstreamFor(srv.URL), mn, rt, fastSettings())
	if out.Verdict != health.VerdictOK {
		t.Fatalf("探活未成功，无法断言请求内容: %s（err=%v）", out.Verdict, out.Err)
	}
	if got == nil {
		t.Fatal("上游没收到请求")
	}
	return got, body
}

// 三种协议各用自己的字段名（§3.3.1），且都必须 stream:true。
//
// 内容出自内置 manifest（P0-06），所以这里验的是「解析到内置层并正确渲染」——
// 字段名与最小输出上限本身由 builtin_test 的形状类断言钉住。
func TestL2_BodyPerProtocol(t *testing.T) {
	tests := []struct {
		proto     model.Protocol
		endpoint  string
		wantField string
		wantVal   float64
	}{
		{model.ProtoAnthropic, "/v1/messages", "max_tokens", 1},
		{model.ProtoOpenAIChat, "/v1/chat/completions", "max_tokens", 1},
		// Responses 实测 max_output_tokens=1 会被部分站直接拒绝
		{model.ProtoOpenAIResponses, "/v1/responses", "max_output_tokens", 16},
	}

	for _, tc := range tests {
		t.Run(string(tc.proto), func(t *testing.T) {
			request, body := captureL2(t, tc.proto, &model.Route{ID: 1})

			if request.URL.Path != tc.endpoint {
				t.Errorf("应打 %s，得到 %s", tc.endpoint, request.URL.Path)
			}
			var got map[string]any
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatalf("请求体不是合法 JSON: %v（%s）", err, body)
			}
			if got["stream"] != true {
				t.Error("必须 stream:true —— 否则测不出首 Token 时间")
			}
			if got["model"] != "claude-opus-5" {
				t.Errorf("model 应为 ModelName 原名，得到 %v", got["model"])
			}
			if v, ok := got[tc.wantField].(float64); !ok || v != tc.wantVal {
				t.Errorf("%s 应为 %v，得到 %v", tc.wantField, tc.wantVal, got[tc.wantField])
			}
			// prompt 必须真的渲染进去，而不是留着占位符原文。
			if bytes.Contains(body, []byte("{{")) {
				t.Errorf("请求体里还有未渲染的占位符: %s", body)
			}
			if !bytes.Contains(body, []byte("1+1=?")) {
				t.Errorf("probe_prompt 没渲染进请求体: %s", body)
			}
		})
	}
}

// 配了映射就探映射后的名字。探的模型和真实请求打的不是同一个的话，
// 探活通过但真实请求 model_not_found（§3.3.2）。
func TestL2_BodyUsesUpstreamModelMapping(t *testing.T) {
	rt := &model.Route{ID: 1, UpstreamModel: "claude-opus-5-20260514"}
	_, body := captureL2(t, model.ProtoAnthropic, rt)

	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got["model"] != "claude-opus-5-20260514" {
		t.Errorf("应探映射后的模型名，得到 %v", got["model"])
	}
}

// 未知协议在解析之前就失败，一个请求都不发。
//
// 发出去的话上游会回一个 400，而那个 400 会被归类成「这个站不支持这个形状」——
// 归因落在站上，而真正的问题是本地配置里有个不存在的协议。
func TestL2_RejectsUnknownProtocolWithoutSendingRequest(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(200)
	}))
	defer srv.Close()

	mn := &model.ModelName{Name: "x", Protocol: "telepathy", ProbeMaxTokens: 1, ProbePrompt: "1+1=?"}
	out := testProber().L2(context.Background(), upstreamFor(srv.URL), mn,
		&model.Route{ID: 1}, fastSettings())
	if out.Verdict == health.VerdictOK {
		t.Error("未知协议不该判成功")
	}
	if hits != 0 {
		t.Errorf("必须在出网之前失败，上游收到了 %d 个请求", hits)
	}
}

// L2 的 query 来自内置模板的固定 query（§3.1 实测的 ?beta=true）。
//
// 这条钉住 Recipe 的 RawQuery 真的进了 URL：旧路径完全丢掉了它
// （§3.3 列的「旧 L2 丢失真实请求中的 RawQuery」正是这条），
// 而带不带 ?beta=true 在部分站上是能不能通的区别。
func TestL2_SendsRecipeFixedQuery(t *testing.T) {
	request, _ := captureL2(t, model.ProtoAnthropic, &model.Route{ID: 1})
	if got := request.URL.Query().Get("beta"); got != "true" {
		t.Errorf("应带内置模板的 ?beta=true（§3.1 实测路径），得到 query %q", request.URL.RawQuery)
	}
}

// count_tokens 的内置模板不带 stream，也不该被 L2 的流式假设改写。
//
// 这条验的是「StreamExpected 由 Recipe 声明」这件事有实际效果：
// 探活代码不能因为「L2 一定是流式」就往一个非流式端点塞 stream 字段。
func TestCountTokensRenderedBodyHasNoStreamField(t *testing.T) {
	set := loadBuiltins(t)
	template, err := set.Compact(model.EndpointCountTokens)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := template.Compiled().Render(context.Background(), TemplateValues{
		UpstreamModel: probetemplate.ResolvedValue{Plain: []byte("m")},
		ProbePrompt:   probetemplate.ResolvedValue{Plain: []byte("p")},
		Timestamp:     time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rendered.Body, []byte(`"stream"`)) {
		t.Errorf("count_tokens 渲染后仍带 stream: %s", rendered.Body)
	}
}

// 内置模板的估算成本要真的进 Cost，而不是被 ModelName 粗算取代。
//
// 这条钉住「记的是实际发出去那份内容的成本」。旧路径只有 ModelName 一个
// 来源，而现在 body 来自 manifest —— 若记账仍按 ModelName 算，成本报告
// 描述的是一个没发出去的请求。
func TestL2_CostUsesBuiltinManifestEstimate(t *testing.T) {
	set := loadBuiltins(t)
	template, err := set.Compact(model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		drainBody(r)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(aliveSSE))
	}))
	defer server.Close()

	modelName := modelNameFor(model.ProtoAnthropic)
	// 与按 ModelName 粗算的值必须可区分，否则这条断言证明不了来源。
	if int64(estimateL2Tokens(modelName)) == template.EstimatedCost() {
		t.Skip("两种估算值恰好相等，这条断言此刻无法区分来源")
	}

	out := testProber().L2(context.Background(), upstreamFor(server.URL), modelName,
		&model.Route{ID: 1}, fastSettings())
	if out.Verdict != health.VerdictOK {
		t.Fatalf("探活未成功: %s（err=%v）", out.Verdict, out.Err)
	}
	if int64(out.EstTokens) != template.EstimatedCost() {
		t.Errorf("成本应取 manifest 的声明值 %d，得到 %d",
			template.EstimatedCost(), out.EstTokens)
	}
	// Sent 必须置位：countL2 用它区分「出网了所以花了钱」与「prepare 阶段就
	// 失败了」。不钉这条的话，一个永不置位的 Sent 会让每次真实 L2 都记 0 token，
	// 成本视图全是零 —— 而上面那条断言看的是 Outcome 而非 Cost，仍然全绿。
	if !out.Sent {
		t.Error("请求已经发出去了，Sent 必须为 true，否则记账会当成没花钱")
	}
}

// 在 prepare 阶段失败的探活不置 Sent —— 它一个字节都没发出去。
//
// 与上一条互补：那条钉「发了要置位」，这条钉「没发不能置位」。少了这条，
// 一个无条件 `out.Sent = true` 会让配置错误也被计入成本，而那正是要区分的。
func TestL2_ConfigErrorLeavesSentFalse(t *testing.T) {
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// 未知协议：在解析之前就失败。
	modelName := &model.ModelName{Name: "x", Protocol: "telepathy",
		ProbeMaxTokens: 1, ProbePrompt: "1+1=?"}
	out := testProber().L2(context.Background(), upstreamFor(server.URL), modelName,
		&model.Route{ID: 1}, fastSettings())

	if hits != 0 {
		t.Fatalf("前提不成立：这条用例要求探活没有出网，上游收到了 %d 个请求", hits)
	}
	if out.Sent {
		t.Error("没有出网的探活不能置 Sent —— 那会让配置错误被算进探活成本")
	}
	if out.EstTokens != 0 {
		t.Errorf("没有出网就没有 token 开销，得到 %d", out.EstTokens)
	}
}

// ── 探活头 ────────────────────────────────────────────────

// Upstream 级 probe_headers 覆盖模板给的头（§3.6.4），
// 给「按 UA 白名单拦截」这类站单独调指纹用。
//
// 断言上游实际收到的头，而不是某个构造函数的返回值：覆盖发生在渲染之后、
// 认证装配之前（execute.go 的 applyProbeHeaders），只验中间产物测不到
// 「覆盖了但随后被别的步骤改回去」。
func TestProbeHeaders_UpstreamOverride(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	up := upstreamFor(srv.URL)
	up.ProbeHeaders = map[string]string{
		"user-agent": "custom-agent/1.0",
		"x-custom":   "yes",
	}
	proberFor(up).L1(context.Background(), up, fastSettings())

	if value := got.Get("User-Agent"); value != "custom-agent/1.0" {
		t.Errorf("Upstream 级应覆盖模板给的 UA，得到 %q", value)
	}
	if value := got.Get("X-Custom"); value != "yes" {
		t.Errorf("应能加新头，得到 %q", value)
	}
	// 没被覆盖的模板项要保留。
	if value := got.Get("X-App"); value != "cli" {
		t.Errorf("未覆盖的模板头应保留，得到 %q", value)
	}
}

// 空值语义是「删掉这个头」。有站会因为多一个头而拒绝请求，
// 需要一个能减头的手段。
func TestProbeHeaders_EmptyValueDeletesHeader(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	up := upstreamFor(srv.URL)
	up.ProbeHeaders = map[string]string{"anthropic-beta": ""}
	proberFor(up).L1(context.Background(), up, fastSettings())

	if value := got.Get("Anthropic-Beta"); value != "" {
		t.Errorf("空值应删掉该头，得到 %q", value)
	}
}

// probe_headers 里的鉴权头必须被忽略。放行的话就是给这个站开了
// 第二个 key 来源，而 probe_headers 是明文 JSON，不受加密存储保护。
// 配置层已拒绝这种输入（model.Validate），这里是纵深防御。
//
// 断言的是「注入的假 key 没有出现在出站请求里」：buildHeaders 自己不再写
// 认证（那是 outbound.ApplyAuth 的职责），所以这条必须走完整条探活路径，
// 否则它测不到真正要防的东西。
func TestProbe_IgnoresAuthHeaderOverrideFromProbeHeaders(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	up := upstreamFor(srv.URL)
	up.ProbeHeaders = map[string]string{
		"authorization": "Bearer leaked-key",
		"x-api-key":     "another-leaked-key",
	}

	proberFor(up).L1(context.Background(), up, fastSettings())

	if got.Get("X-Api-Key") != up.APIKey {
		t.Errorf("鉴权头必须来自 api_key 字段，得到 %q", got.Get("X-Api-Key"))
	}
	for _, leaked := range []string{"leaked-key", "another-leaked-key"} {
		for name, values := range got {
			for _, value := range values {
				if contains(value, leaked) {
					t.Errorf("probe_headers 里的假 key 漏进了出站请求头 %s: %q", name, value)
				}
			}
		}
	}
}

// auth_style 经 Endpoint 的 auth profile 决定发哪一种认证头。
//
// 这条覆盖的是「旧字段 → auth profile → ApplyAuth」这整条翻译链：只测
// ApplyAuth 的话，翻译那一段错了照样全绿，而症状是「配了 bearer 却发
// x-api-key」。
func TestProbe_AuthStyleDecidesSingleAuthHeader(t *testing.T) {
	tests := []struct {
		style      model.AuthStyle
		wantXKey   string
		wantBearer string
	}{
		{model.AuthXAPIKey, "sk-test-key-123456", ""},
		{model.AuthBearer, "", "Bearer sk-test-key-123456"},
	}
	for _, tc := range tests {
		t.Run(string(tc.style), func(t *testing.T) {
			var got http.Header
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.Header.Clone()
				w.WriteHeader(200)
			}))
			defer srv.Close()

			up := upstreamFor(srv.URL)
			up.AuthStyle = tc.style
			proberFor(up).L1(context.Background(), up, fastSettings())

			if v := got.Get("X-Api-Key"); v != tc.wantXKey {
				t.Errorf("X-Api-Key：期望 %q，得到 %q", tc.wantXKey, v)
			}
			if v := got.Get("Authorization"); v != tc.wantBearer {
				t.Errorf("Authorization：期望 %q，得到 %q", tc.wantBearer, v)
			}
		})
	}
}

// 探活请求里除 ApplyAuth 写的那一个之外没有别的认证头（§7.2）。
//
// 模板层与覆盖层都不该写认证：模板经 probetemplate 的凭据门禁（认证头必须是
// 占位符），probe_headers 经 applyUpstreamHeaderOverrides 的静默跳过。这条
// 走完整条路径，所以它同时覆盖那两道。
func TestProbeHeaders_OnlyApplyAuthWritesCredentials(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	up := upstreamFor(srv.URL)
	proberFor(up).L1(context.Background(), up, fastSettings())

	var present []string
	for _, name := range model.AuthHeaders {
		if got.Get(name) != "" {
			present = append(present, name)
		}
	}
	// upstreamFor 配的是 x_api_key，所以恰好一个头。
	if len(present) != 1 || present[0] != "X-Api-Key" {
		t.Errorf("应恰好一个认证头 X-Api-Key，实际带了 %v", present)
	}
}

// anthropic-version 缺失会直接 400，Anthropic 端点的模板必须带它。
//
// 断言实际发出去的请求，而不是某个默认表：版本头现在来自 manifest，
// 而「manifest 里有」与「真的发出去了」是两件事。
func TestProbeHeaders_AnthropicVersionIsSent(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		drainBody(r)
		got = r.Header.Clone()
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(aliveSSE))
	}))
	defer srv.Close()

	out := testProber().L2(context.Background(), upstreamFor(srv.URL),
		modelNameFor(model.ProtoAnthropic), &model.Route{ID: 1}, fastSettings())
	if out.Verdict != health.VerdictOK {
		t.Fatalf("探活未成功: %s（err=%v）", out.Verdict, out.Err)
	}
	if got.Get("Anthropic-Version") == "" {
		t.Error("Anthropic 端点必须带 anthropic-version（缺失直接 400）")
	}
}

// OpenAI 端点的模板不带 anthropic-version —— 跨协议串味。
func TestProbeHeaders_NoAnthropicVersionOnOpenAIEndpoints(t *testing.T) {
	set := loadBuiltins(t)
	for _, endpoint := range []model.EndpointKind{
		model.EndpointResponses, model.EndpointChatCompletions,
	} {
		template, err := set.Compact(endpoint)
		if err != nil {
			t.Fatal(err)
		}
		if value := template.Header("anthropic-version"); value != "" {
			t.Errorf("%s 的内置模板不该带 anthropic-version，得到 %q", endpoint, value)
		}
	}
}

// DefaultHeaderTemplate 返回新 map，改它不影响后续调用。
func TestDefaultHeaderTemplate_IsCopy(t *testing.T) {
	tpl := DefaultHeaderTemplate()
	if len(tpl) == 0 {
		t.Fatal("默认头模板是空的")
	}
	tpl["user-agent"] = "tampered"

	if again := DefaultHeaderTemplate(); again["user-agent"] == "tampered" {
		t.Error("修改返回值污染了后续调用")
	}
}
