package probe

// Recipe 解析结果真的被用来发请求（P0-05 第 11 条的后半）。
//
// 为什么这一组必须存在：四级解析在 P0-05 就交付了，但直到本轮之前
// **没有任何生产调用方** —— Prober 仍在硬拼 body 与头。那种状态下 recipe
// 的全部测试都是绿的，而用户配的配方对探活毫无影响。这里的断言全部落在
// 「上游实际收到了什么」上，所以它证明的是那条链路接通了。

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probetemplate"
)

// recordUpstream 起一个记录请求并回一个判活响应的假上游。
func recordUpstream(t *testing.T) (*httptest.Server, func() (*http.Request, []byte)) {
	t.Helper()

	var got *http.Request
	var body []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		got = r.Clone(context.Background())
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(aliveSSE))
	}))
	t.Cleanup(server.Close)
	return server, func() (*http.Request, []byte) { return got, body }
}

// proberWithRecipes 造一个装配了指定解析来源的 Prober。
func proberWithRecipes(source *fakeRecipeSource, secrets *fakeSecretSource) *Prober {
	prober := &Prober{
		Transport: http.DefaultTransport,
		Targets:   testTargets(),
		Recipes:   testResolver(source),
	}
	if secrets != nil {
		prober.Secrets = secrets
	}
	return prober
}

// messagesBinding 造一份 messages 端点的已发布配方。
//
// 不复用 testBinding：那个默认 TimeoutL1，而模型端点必须用 l2 档
// （model.ProbeRecipeVersion.ValidateForEndpoint 会拒）。头与 body 由各用例
// 自己填 —— 每条断言要的那个标记不同。
func messagesBinding() *model.PublishedRecipeBinding {
	binding := testBinding(7, 70, 3, "POST")
	binding.Recipe.Endpoint = model.EndpointMessages
	binding.Version.TimeoutProfile = model.TimeoutL2Standard
	binding.Version.StreamExpected = true
	binding.Version.Body = []byte(`{"model":"{{UPSTREAM_MODEL}}","max_tokens":1,` +
		`"stream":true,"messages":[{"role":"user","content":"{{PROBE_PROMPT}}"}]}`)
	return binding
}

// 已发布的 Route 配方胜过内置模板，并且它的内容真的发了出去。
//
// 断言一个只可能来自那份配方的头：内置模板不带 X-Recipe-Layer，所以
// 收到它就证明解析结果参与了请求构造，而不是「解析了但没用」。
func TestL2_UsesPublishedRouteRecipeContent(t *testing.T) {
	server, taken := recordUpstream(t)

	binding := messagesBinding()
	binding.Version.Headers = []model.HeaderTemplate{
		{Name: "X-Recipe-Layer", Values: []string{"route"}},
		{Name: "Content-Type", Values: []string{"application/json"}},
	}
	binding.Version.Body = []byte(`{"model":"{{UPSTREAM_MODEL}}","max_tokens":1,` +
		`"stream":true,"messages":[{"role":"user","content":"{{PROBE_PROMPT}}"}],` +
		`"probe_marker":"route-recipe"}`)
	source := &fakeRecipeSource{routeBinding: binding}

	out := proberWithRecipes(source, nil).L2(context.Background(), upstreamFor(server.URL),
		modelNameFor(model.ProtoAnthropic), &model.Route{ID: 2}, fastSettings())
	if out.Verdict != health.VerdictOK {
		t.Fatalf("探活未成功: %s（err=%v）", out.Verdict, out.Err)
	}

	request, body := taken()
	if request == nil {
		t.Fatal("上游没收到请求")
	}
	if got := request.Header.Get("X-Recipe-Layer"); got != "route" {
		t.Errorf("Route 配方的头没发出去（解析结果没被用）：X-Recipe-Layer=%q", got)
	}
	if !bytes.Contains(body, []byte(`"probe_marker":"route-recipe"`)) {
		t.Errorf("Route 配方的 body 没发出去: %s", body)
	}
	// 内置模板的痕迹不该出现：那说明解析结果被忽略了。
	if bytes.Contains(body, []byte(`"type":"text"`)) {
		t.Errorf("发出去的是内置模板的 body，而不是 Route 配方: %s", body)
	}
	// 占位符必须已渲染。
	if bytes.Contains(body, []byte("{{")) {
		t.Errorf("body 里还有未渲染的占位符: %s", body)
	}
}

// 配方引用的 Probe Secret 经 BindSecrets 校验后渲染进请求。
func TestL2_RendersBoundProbeSecret(t *testing.T) {
	server, taken := recordUpstream(t)

	binding := messagesBinding()
	binding.Version.Headers = []model.HeaderTemplate{
		{Name: "X-Tenant", Values: []string{"{{SECRET:tenant}}"}},
	}
	source := &fakeRecipeSource{
		routeBinding: binding,
		refs: map[int64][]model.RequiredSecretRef{
			70: {{Name: "tenant", BoundSecretID: 11}},
		},
	}
	secrets := &fakeSecretSource{values: map[string]probetemplate.ResolvedSecret{
		"tenant": {ID: 11, Plain: []byte("tenant-value"), Revision: 4},
	}}

	out := proberWithRecipes(source, secrets).L2(context.Background(), upstreamFor(server.URL),
		modelNameFor(model.ProtoAnthropic), &model.Route{ID: 2}, fastSettings())
	if out.Verdict != health.VerdictOK {
		t.Fatalf("探活未成功: %s（err=%v）", out.Verdict, out.Err)
	}

	request, _ := taken()
	if got := request.Header.Get("X-Tenant"); got != "tenant-value" {
		t.Errorf("Secret 没渲染进请求头，得到 %q", got)
	}
}

// 同名重建过的 Secret 不满足旧引用，且**一个请求都不发**（§4.5）。
//
// 这条是 §4.5 那道边界在生产路径上的验收：BindSecrets 自己的单测证明它会
// 拒绝，而这里证明探活真的调了它 —— 不调的话，那个新 Secret 会被静默用上，
// 而发出去的请求看起来完全正常。
func TestL2_RejectsRecreatedSecretWithoutSendingRequest(t *testing.T) {
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	binding := messagesBinding()
	binding.Version.Headers = []model.HeaderTemplate{
		{Name: "X-Tenant", Values: []string{"{{SECRET:tenant}}"}},
	}
	source := &fakeRecipeSource{
		routeBinding: binding,
		// 绑定时是 11。
		refs: map[int64][]model.RequiredSecretRef{
			70: {{Name: "tenant", BoundSecretID: 11}},
		},
	}
	// 现在按名字查到的是 12 —— 删掉再建一个同名的就是这个形态。
	secrets := &fakeSecretSource{values: map[string]probetemplate.ResolvedSecret{
		"tenant": {ID: 12, Plain: []byte("new-value"), Revision: 1},
	}}

	out := proberWithRecipes(source, secrets).L2(context.Background(), upstreamFor(server.URL),
		modelNameFor(model.ProtoAnthropic), &model.Route{ID: 2}, fastSettings())
	if out.Verdict == health.VerdictOK {
		t.Error("身份不匹配的 Secret 不该判成功")
	}
	if hits != 0 {
		t.Errorf("必须在出网之前失败，上游收到了 %d 个请求", hits)
	}
	if out.Err == nil {
		t.Fatal("应带上原因")
	}
	// 明文一个字节都不能进错误：它会落进 route_health.last_error 并显示在 UI 上。
	if bytes.Contains([]byte(out.Err.Error()), []byte("new-value")) {
		t.Errorf("错误泄露了 Secret 明文: %v", out.Err)
	}
}

// 未装配 Secret 源时，引用 Secret 的配方以 config_error 失败而不发请求。
func TestL2_MissingSecretSourceFailsClosed(t *testing.T) {
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	binding := messagesBinding()
	binding.Version.Headers = []model.HeaderTemplate{
		{Name: "X-Tenant", Values: []string{"{{SECRET:tenant}}"}},
	}
	source := &fakeRecipeSource{routeBinding: binding}

	out := proberWithRecipes(source, nil).L2(context.Background(), upstreamFor(server.URL),
		modelNameFor(model.ProtoAnthropic), &model.Route{ID: 2}, fastSettings())
	if out.Verdict == health.VerdictOK {
		t.Error("拿不到 Secret 不该判成功")
	}
	if hits != 0 {
		t.Errorf("必须在出网之前失败，上游收到了 %d 个请求", hits)
	}
}

// L1 也走解析：Upstream 作用域的 models 配方会被用上。
//
// 旧路径的 L1 完全不看 Recipe（它只拼一个 GET），所以这条钉的是
// 「两级探活都接了解析」，而不只是 L2。
func TestL1_UsesPublishedUpstreamModelsRecipe(t *testing.T) {
	var got http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	binding := testBinding(8, 80, 4, "GET")
	binding.Recipe.Endpoint = model.EndpointModels
	binding.Version.Headers = []model.HeaderTemplate{
		{Name: "X-Recipe-Layer", Values: []string{"upstream-models"}},
	}
	binding.Version.TimeoutProfile = model.TimeoutL1
	source := &fakeRecipeSource{upstreamBinding: binding}

	out := proberWithRecipes(source, nil).L1(context.Background(),
		upstreamFor(server.URL), fastSettings())
	if out.Verdict != health.VerdictOK {
		t.Fatalf("L1 未成功: %s（err=%v）", out.Verdict, out.Err)
	}
	if value := got.Get("X-Recipe-Layer"); value != "upstream-models" {
		t.Errorf("Upstream 的 models 配方没被用上：X-Recipe-Layer=%q", value)
	}
}

// L1 用不到 MODEL_NAME，引用它的 models 配方在渲染时失败而不发请求。
//
// 为什么这是对的行为而不是缺陷：Upstream 作用域的 models 端点上没有唯一的
// 模型名（该站可能挂着好几个 Route）。静默填一个会让探活打的模型与任何
// Route 都无关，于是「这个站的 /v1/models 通不通」这个结论对不上任何东西。
func TestL1_RejectsModelPlaceholderWithoutSendingRequest(t *testing.T) {
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	binding := testBinding(8, 80, 4, "GET")
	binding.Recipe.Endpoint = model.EndpointModels
	binding.Version.Headers = []model.HeaderTemplate{
		{Name: "X-Model", Values: []string{"{{MODEL_NAME}}"}},
	}
	binding.Version.TimeoutProfile = model.TimeoutL1
	source := &fakeRecipeSource{upstreamBinding: binding}

	out := proberWithRecipes(source, nil).L1(context.Background(),
		upstreamFor(server.URL), fastSettings())
	if out.Verdict == health.VerdictOK {
		t.Error("L1 没有模型上下文，引用 MODEL_NAME 的配方不该判成功")
	}
	if hits != 0 {
		t.Errorf("必须在出网之前失败，上游收到了 %d 个请求", hits)
	}
}

// 探活不装配解析器时仍能用内置模板发请求。
//
// 这条保护的是「退化路径仍然正确」：Prober.Recipes 为 nil 时不该 panic、
// 也不该发一个空请求，而是走 embedded 那一级。
func TestL2_WithoutResolverFallsBackToBuiltin(t *testing.T) {
	server, taken := recordUpstream(t)

	prober := &Prober{Transport: http.DefaultTransport, Targets: testTargets()}
	out := prober.L2(context.Background(), upstreamFor(server.URL),
		modelNameFor(model.ProtoAnthropic), &model.Route{ID: 1}, fastSettings())
	if out.Verdict != health.VerdictOK {
		t.Fatalf("未装配解析器时应用内置模板: %s（err=%v）", out.Verdict, out.Err)
	}
	_, body := taken()
	if !bytes.Contains(body, []byte(`"type":"text"`)) {
		t.Errorf("应发内置 compact 模板的 body，得到 %s", body)
	}
}

// SESSION_ID 每次探活都不同（§8.3 禁止写死会话 ID）。
func TestProbeSessionIDDiffersPerProbe(t *testing.T) {
	server, taken := recordUpstream(t)

	binding := messagesBinding()
	binding.Version.Headers = []model.HeaderTemplate{
		{Name: "X-Session", Values: []string{"{{SESSION_ID}}"}},
	}
	source := &fakeRecipeSource{routeBinding: binding}
	prober := proberWithRecipes(source, nil)

	seen := map[string]bool{}
	for range 3 {
		out := prober.L2(context.Background(), upstreamFor(server.URL),
			modelNameFor(model.ProtoAnthropic), &model.Route{ID: 2}, fastSettings())
		if out.Verdict != health.VerdictOK {
			t.Fatalf("探活未成功: %s（err=%v）", out.Verdict, out.Err)
		}
		request, _ := taken()
		session := request.Header.Get("X-Session")
		if session == "" {
			t.Fatal("SESSION_ID 没渲染进请求")
		}
		if seen[session] {
			t.Errorf("SESSION_ID 在两次探活间重复了：%q —— 上游会把它们看成同一个会话", session)
		}
		seen[session] = true
	}
}

// fakeSecretSource 是可控的 Probe Secret 来源。
type fakeSecretSource struct {
	values map[string]probetemplate.ResolvedSecret
}

func (source *fakeSecretSource) ResolveProbeSecret(_ context.Context,
	name string) (probetemplate.ResolvedSecret, error) {

	secret, ok := source.values[name]
	if !ok {
		return probetemplate.ResolvedSecret{}, errTestNotFound
	}
	return secret, nil
}
