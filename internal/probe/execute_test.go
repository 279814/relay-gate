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

// executorWithRecipes 造一个装配了指定解析来源的 Executor。
func executorWithRecipes(source *fakeRecipeSource, secrets *fakeSecretSource) *executorProbeHarness {
	prober := &executorProbeHarness{
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

	out := executorWithRecipes(source, nil).L2(context.Background(), upstreamFor(server.URL),
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

	out := executorWithRecipes(source, secrets).L2(context.Background(), upstreamFor(server.URL),
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

	out := executorWithRecipes(source, secrets).L2(context.Background(), upstreamFor(server.URL),
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

	out := executorWithRecipes(source, nil).L2(context.Background(), upstreamFor(server.URL),
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

	out := executorWithRecipes(source, nil).L1(context.Background(),
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

	out := executorWithRecipes(source, nil).L1(context.Background(),
		upstreamFor(server.URL), fastSettings())
	if out.Verdict == health.VerdictOK {
		t.Error("L1 没有模型上下文，引用 MODEL_NAME 的配方不该判成功")
	}
	if hits != 0 {
		t.Errorf("必须在出网之前失败，上游收到了 %d 个请求", hits)
	}
}

// A missing recipe resolver is an assembly error and must fail before I/O.
func TestL2_WithoutResolverFailsClosed(t *testing.T) {
	server, taken := recordUpstream(t)
	executor := &executorProbeHarness{Transport: http.DefaultTransport, Targets: testTargets()}
	out := executor.L2(context.Background(), upstreamFor(server.URL), modelNameFor(model.ProtoAnthropic), &model.Route{ID: 1}, fastSettings())
	request, _ := taken()
	if out.Err == nil || out.Sent || request != nil {
		t.Fatalf("missing resolver sent or succeeded: outcome=%+v request=%v", out, request)
	}
}

// 未装配出站目标解析器时，两级探活都以配置错误结束而**不是 panic**。
//
// Prober.Targets 的文档承诺「为 nil 时探活直接失败而不是自己拼一个」，理由是
// 探活打的地址必须与真实请求完全一致。P0-06 之前这道检查在 Prober.resolve 里，
// 随那个函数一起被删掉了 —— 于是承诺变成了一次空指针解引用。
//
// 为什么这条值得单独钉：探活跑在 Scheduler 起的 goroutine 里，那里没有
// recover，一个 nil Targets 会**带崩整个网关进程**。而它是可达的 ——
// probe.Prober 是导出类型，字段也是导出的（crosspath_test 就直接构造它），
// 装配时漏一个 WithTargets 就是这个形态。
func TestProbeWithoutTargetsFailsAsConfigErrorNotPanic(t *testing.T) {
	prober := &executorProbeHarness{Transport: http.DefaultTransport, Recipes: builtinOnlyResolver()}
	upstream := upstreamFor("http://127.0.0.1:1")

	t.Run("L1", func(t *testing.T) {
		out := prober.L1(context.Background(), upstream, fastSettings())
		if out.Verdict == health.VerdictOK {
			t.Error("没有出站解析器不该判成功")
		}
		if out.Err == nil {
			t.Fatal("应带上原因，否则用户看不出漏配了什么")
		}
	})

	t.Run("L2", func(t *testing.T) {
		out := prober.L2(context.Background(), upstream,
			modelNameFor(model.ProtoAnthropic), &model.Route{ID: 1}, fastSettings())
		if out.Verdict == health.VerdictOK {
			t.Error("没有出站解析器不该判成功")
		}
		if out.Err == nil {
			t.Fatal("应带上原因")
		}
	})
}

// The immutable recipe alone selects the method. HTTP failure remains reachable.
func TestL1_HeadRecipeClassifiesStatusIndependentlyOfLegacyPath(t *testing.T) {
	var method string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { method = r.Method; w.WriteHeader(500) }))
	defer server.Close()
	binding := testBinding(8, 80, 4, "HEAD")
	binding.Recipe.Endpoint = model.EndpointModels
	executor := executorWithRecipes(&fakeRecipeSource{upstreamBinding: binding}, nil)
	out := executor.L1(context.Background(), upstreamFor(server.URL), fastSettings())
	if method != "HEAD" || out.Verdict == health.VerdictOK || !executor.Last.Execution.Reachable || executor.Last.Execution.StatusCode != 500 {
		t.Fatalf("HEAD recipe/status evidence: method=%s outcome=%+v execution=%+v", method, out, executor.Last.Execution)
	}
}

func TestL1_EmptyLegacyPathCannotOverrideGetRecipe(t *testing.T) {
	var method, path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { method, path = r.Method, r.URL.Path; w.WriteHeader(500) }))
	defer server.Close()
	binding := testBinding(8, 80, 4, "GET")
	binding.Recipe.Endpoint = model.EndpointModels
	up := upstreamFor(server.URL)
	up.L1Path = ""
	executor := executorWithRecipes(&fakeRecipeSource{upstreamBinding: binding}, nil)
	out := executor.L1(context.Background(), up, fastSettings())
	if method != "GET" || path != "/v1/models" || out.Verdict == health.VerdictOK || !executor.Last.Execution.Reachable || executor.Last.Execution.ErrorClass != model.ErrorTransient {
		t.Fatalf("legacy field changed recipe or status: method=%s path=%s outcome=%+v execution=%+v", method, path, out, executor.Last.Execution)
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
	prober := executorWithRecipes(source, nil)

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
