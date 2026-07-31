package probe

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
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
	return &Prober{Transport: http.DefaultTransport}
}

func upstreamFor(url string) *model.Upstream {
	return &model.Upstream{
		ID: 1, Name: "test", BaseURL: url, APIKey: "sk-test-key-123456",
		AuthStyle: model.AuthAuto, L1Path: "/v1/models", Enabled: true,
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
	testProber().L1(context.Background(), up, fastSettings())

	if v := got.Get("X-Api-Key"); v != up.APIKey {
		t.Errorf("auto 模式应发 x-api-key，得到 %q", v)
	}
	if v := got.Get("Authorization"); v != "Bearer "+up.APIKey {
		t.Errorf("auto 模式应同时发 Bearer，得到 %q", v)
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

// 三种协议的参数名不同（§3.3.1），且必须 stream:true。
func TestBuildProbeBody_PerProtocol(t *testing.T) {
	tests := []struct {
		proto     model.Protocol
		wantField string
		wantVal   float64
	}{
		{model.ProtoAnthropic, "max_tokens", 1},
		{model.ProtoOpenAIChat, "max_tokens", 1},
		// Responses 协议实测 max_output_tokens=1 会被部分站直接拒绝
		{model.ProtoOpenAIResponses, "max_output_tokens", 16},
	}

	for _, tc := range tests {
		t.Run(string(tc.proto), func(t *testing.T) {
			mn := modelNameFor(tc.proto)
			body, err := buildProbeBody(mn, &model.Route{ID: 1})
			if err != nil {
				t.Fatal(err)
			}

			var got map[string]any
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatal(err)
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
		})
	}
}

// 配了映射就探映射后的名字。探的模型和真实请求打的不是同一个的话，
// 探活通过但真实请求 model_not_found。
func TestBuildProbeBody_UsesUpstreamModelMapping(t *testing.T) {
	mn := modelNameFor(model.ProtoAnthropic)
	rt := &model.Route{ID: 1, UpstreamModel: "claude-opus-5-20260514"}

	body, err := buildProbeBody(mn, rt)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got["model"] != "claude-opus-5-20260514" {
		t.Errorf("应探映射后的模型名，得到 %v", got["model"])
	}
}

func TestBuildProbeBody_RejectsUnknownProtocol(t *testing.T) {
	mn := &model.ModelName{Name: "x", Protocol: "telepathy", ProbeMaxTokens: 1, ProbePrompt: "1+1=?"}
	if _, err := buildProbeBody(mn, nil); err == nil {
		t.Error("未知协议应报错，而不是发一个上游看不懂的请求")
	}
}

// ── 探活头模板 ────────────────────────────────────────────

// Upstream 级 probe_headers 覆盖全局模板（§3.6.4），
// 给「按 UA 白名单拦截」这类站单独调指纹用。
func TestBuildHeaders_UpstreamOverride(t *testing.T) {
	up := upstreamFor("http://x")
	up.ProbeHeaders = map[string]string{
		"user-agent": "custom-agent/1.0",
		"x-custom":   "yes",
	}

	h := buildHeaders(up, model.ProtoAnthropic, false)
	if got := h.Get("User-Agent"); got != "custom-agent/1.0" {
		t.Errorf("Upstream 级应覆盖默认 UA，得到 %q", got)
	}
	if got := h.Get("X-Custom"); got != "yes" {
		t.Errorf("应能加新头，得到 %q", got)
	}
	// 没被覆盖的默认项要保留
	if got := h.Get("X-App"); got != "cli" {
		t.Errorf("未覆盖的默认头应保留，得到 %q", got)
	}
}

// 空值语义是「删掉这个头」。有站会因为多一个头而拒绝请求，
// 需要一个能减头的手段。
func TestBuildHeaders_EmptyValueDeletesHeader(t *testing.T) {
	up := upstreamFor("http://x")
	up.ProbeHeaders = map[string]string{"anthropic-beta": ""}

	h := buildHeaders(up, model.ProtoAnthropic, false)
	if got := h.Get("Anthropic-Beta"); got != "" {
		t.Errorf("空值应删掉该头，得到 %q", got)
	}
}

// probe_headers 里的鉴权头必须被忽略。放行的话就是给这个站开了
// 第二个 key 来源，而 probe_headers 是明文 JSON，不受加密存储保护。
// 配置层已拒绝这种输入（model.Validate），这里是纵深防御。
func TestBuildHeaders_IgnoresAuthHeaderOverride(t *testing.T) {
	up := upstreamFor("http://x")
	up.ProbeHeaders = map[string]string{
		"authorization": "Bearer leaked-key",
		"x-api-key":     "another-leaked-key",
	}

	h := buildHeaders(up, model.ProtoAnthropic, false)
	if got := h.Get("Authorization"); got != "Bearer "+up.APIKey {
		t.Errorf("鉴权头必须来自 api_key 字段，得到 %q", got)
	}
	if got := h.Get("X-Api-Key"); got != up.APIKey {
		t.Errorf("鉴权头必须来自 api_key 字段，得到 %q", got)
	}
}

func TestBuildHeaders_AuthStyles(t *testing.T) {
	tests := []struct {
		style      model.AuthStyle
		wantXKey   string
		wantBearer string
	}{
		{model.AuthXAPIKey, "sk-test-key-123456", ""},
		{model.AuthBearer, "", "Bearer sk-test-key-123456"},
		{model.AuthAuto, "sk-test-key-123456", "Bearer sk-test-key-123456"},
	}
	for _, tc := range tests {
		t.Run(string(tc.style), func(t *testing.T) {
			up := upstreamFor("http://x")
			up.AuthStyle = tc.style
			h := buildHeaders(up, model.ProtoAnthropic, false)

			if got := h.Get("X-Api-Key"); got != tc.wantXKey {
				t.Errorf("X-Api-Key：期望 %q，得到 %q", tc.wantXKey, got)
			}
			if got := h.Get("Authorization"); got != tc.wantBearer {
				t.Errorf("Authorization：期望 %q，得到 %q", tc.wantBearer, got)
			}
		})
	}
}

// anthropic-version 缺失会直接 400，只在 Anthropic 协议下发。
func TestBuildHeaders_AnthropicVersionOnlyForAnthropic(t *testing.T) {
	up := upstreamFor("http://x")

	if got := buildHeaders(up, model.ProtoAnthropic, false).Get("Anthropic-Version"); got == "" {
		t.Error("Anthropic 协议必须带 anthropic-version（缺失直接 400）")
	}
	if got := buildHeaders(up, model.ProtoOpenAIChat, false).Get("Anthropic-Version"); got != "" {
		t.Errorf("OpenAI 协议不该带 anthropic-version，得到 %q", got)
	}
}

func TestBuildHeaders_StreamChangesAccept(t *testing.T) {
	up := upstreamFor("http://x")
	if got := buildHeaders(up, model.ProtoAnthropic, true).Get("Accept"); got != "text/event-stream" {
		t.Errorf("流式请求的 accept 应为 text/event-stream，得到 %q", got)
	}
	if got := buildHeaders(up, model.ProtoAnthropic, false).Get("Accept"); got != "application/json" {
		t.Errorf("非流式应为 application/json，得到 %q", got)
	}
}

// DefaultHeaderTemplate 是副本，改它不能污染全局默认。
func TestDefaultHeaderTemplate_IsCopy(t *testing.T) {
	tpl := DefaultHeaderTemplate()
	tpl["user-agent"] = "tampered"

	if defaultProbeHeaders["user-agent"] == "tampered" {
		t.Error("修改返回值污染了全局默认模板")
	}
	if tpl2 := DefaultHeaderTemplate(); tpl2["user-agent"] == "tampered" {
		t.Error("修改返回值污染了后续调用")
	}
}
