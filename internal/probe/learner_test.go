package probe

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probetemplate"
)

type captureLearnerStore struct {
	profile *model.ClientProbeProfile
}

func (c *captureLearnerStore) UpsertClientProbeProfile(_ context.Context, profile *model.ClientProbeProfile) error {
	cp := *profile
	cp.SafeHeaders = append([]model.HeaderTemplate(nil), profile.SafeHeaders...)
	cp.BodyTemplate = append([]byte(nil), profile.BodyTemplate...)
	cp.BodyShapeJSON = append([]byte(nil), profile.BodyShapeJSON...)
	c.profile = &cp
	return nil
}

// 非认证头的值仍须过 §8.5 高置信前缀门禁：头名不是 AuthHeaders 不能成为
// 明文 key 旁路。占位符与 anthropic-beta 等协议常量必须保留。
func TestLearner_ObserveSuccessfulDropsLiteralCredentialOnNonAuthHeader(t *testing.T) {
	store := &captureLearnerStore{}
	learner := NewLearner(store)

	// 与 probetemplate.TestScanRejectsHighConfidenceCredentialsAnywhere 同一前缀形。
	const literalKey = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	shape := model.ClientRequestShape{
		SafeHeaders: []model.HeaderTemplate{
			{Name: "X-Custom", Values: []string{literalKey}},
			{Name: "X-Upstream-Key", Values: []string{"{{UPSTREAM_API_KEY}}"}},
			{Name: "X-Tenant-Secret", Values: []string{"{{SECRET:tenant}}"}},
			{Name: "anthropic-beta", Values: []string{"prompt-caching-2024-07-31"}},
		},
	}
	if err := learner.ObserveSuccessful(context.Background(), 7, model.EndpointMessages, shape); err != nil {
		t.Fatalf("ObserveSuccessful: %v", err)
	}
	if store.profile == nil {
		t.Fatal("应持久化 candidate profile")
	}
	if got := headerValue(store.profile.SafeHeaders, "X-Custom"); got != "" {
		t.Fatalf("非认证头上的高置信字面 key 不得入库，得到 %q", got)
	}
	if got := headerValue(store.profile.SafeHeaders, "X-Upstream-Key"); got != "{{UPSTREAM_API_KEY}}" {
		t.Fatalf("UPSTREAM_API_KEY 占位符应保留，得到 %q", got)
	}
	if got := headerValue(store.profile.SafeHeaders, "X-Tenant-Secret"); got != "{{SECRET:tenant}}" {
		t.Fatalf("SECRET 占位符应保留，得到 %q", got)
	}
	if got := headerValue(store.profile.SafeHeaders, "anthropic-beta"); got != "prompt-caching-2024-07-31" {
		t.Fatalf("anthropic-beta 应仍被学习，得到 %q", got)
	}
}

// §8.4：学到的 fingerprint 不得保存 / 回放客户端 relay key、上游 key、管理会话 Cookie。
// anthropic-beta 等安全协议头仍可学。
func TestLearner_ObserveSuccessfulDropsSecretsKeepsSafeHeaders(t *testing.T) {
	store := &captureLearnerStore{}
	learner := NewLearner(store)

	shape := model.ClientRequestShape{
		SafeHeaders: []model.HeaderTemplate{
			{Name: "Authorization", Values: []string{"Bearer rk-client-relay-key-value"}},
			{Name: "X-Api-Key", Values: []string{"rk-client-relay-key-value"}},
			{Name: "Api-Key", Values: []string{"rk-client-relay-key-value"}},
			{Name: "Cookie", Values: []string{gatewaySessionCookieName + "=admin-session-tok; theme=dark"}},
			{Name: "anthropic-beta", Values: []string{"prompt-caching-2024-07-31"}},
		},
		FixedRawQuery: "beta=1&key=sk-ant-abcdefghijklmnopqrstuv&flag=ok",
		BodyShapeJSON: []byte(`{"stream":"bool"}`),
	}
	if err := learner.ObserveSuccessful(context.Background(), 7, model.EndpointMessages, shape); err != nil {
		t.Fatalf("ObserveSuccessful: %v", err)
	}
	if store.profile == nil {
		t.Fatal("应持久化 candidate profile")
	}

	assertNoSecretHeaders(t, store.profile.SafeHeaders)
	if got := headerValue(store.profile.SafeHeaders, "anthropic-beta"); got != "prompt-caching-2024-07-31" {
		t.Fatalf("anthropic-beta 应仍被学习，得到 %q", got)
	}
	if strings.Contains(store.profile.FixedRawQuery, "sk-ant-") {
		t.Fatalf("纯凭据 query 不得入库，得到 %q", store.profile.FixedRawQuery)
	}
	if !strings.Contains(store.profile.FixedRawQuery, "beta=1") ||
		!strings.Contains(store.profile.FixedRawQuery, "flag=ok") {
		t.Fatalf("非凭据 query 应保留，得到 %q", store.profile.FixedRawQuery)
	}
}

// 旧 profile 行即使仍带凭据头，解析成探活请求时也不得回放；认证走 Endpoint auth。
func TestLearner_ProfileProbeOmitsSecretsKeepsAnthropicBeta(t *testing.T) {
	source := &fakeRecipeSource{
		profile: &model.ClientProbeProfile{
			ID: 9, Revision: 5, Status: model.ProfileTested,
			Endpoint: model.EndpointMessages,
			SafeHeaders: []model.HeaderTemplate{
				{Name: "Authorization", Values: []string{"Bearer {{UPSTREAM_API_KEY}}"}},
				{Name: "Cookie", Values: []string{gatewaySessionCookieName + "=admin-session-tok"}},
				{Name: "anthropic-beta", Values: []string{"prompt-caching-2024-07-31"}},
			},
			FixedRawQuery: "beta=1",
		},
	}

	resolved, err := testResolver(source).Resolve(context.Background(), RecipeQuery{
		UpstreamID: 1, Endpoint: model.EndpointMessages,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved.Layer != model.ResolvedProfile {
		t.Fatalf("layer want profile got %q", resolved.Layer)
	}

	rendered, err := resolved.Compiled.Render(context.Background(), TemplateValues{
		UpstreamAPIKey: probetemplate.ResolvedValue{Plain: []byte("sk-upstream-must-not-appear-from-learned-auth")},
		UpstreamModel:  probetemplate.ResolvedValue{Plain: []byte("m")},
		ModelName:      probetemplate.ResolvedValue{Plain: []byte("m")},
		ProbePrompt:    probetemplate.ResolvedValue{Plain: []byte("1+1=?")},
		SessionID:      probetemplate.ResolvedValue{Plain: []byte("probe-test")},
		Timestamp:      time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	if got := rendered.Header.Get("Authorization"); got != "" {
		t.Fatalf("探活不得回放学到的 Authorization，得到 %q", got)
	}
	if cookie := rendered.Header.Get("Cookie"); strings.Contains(cookie, gatewaySessionCookieName) ||
		strings.Contains(cookie, "admin-session-tok") {
		t.Fatalf("探活不得回放 relay_session，得到 %q", cookie)
	}
	if got := rendered.Header.Get("anthropic-beta"); got != "prompt-caching-2024-07-31" {
		t.Fatalf("anthropic-beta 应出现在探活请求，得到 %q", got)
	}
	if strings.Contains(rendered.RawQuery, "sk-upstream") {
		t.Fatalf("学到的形状不得经 query 带出上游 key，得到 %q", rendered.RawQuery)
	}
}

// §8.4：不得保存 messages / system / tools 内容与认证值。
// 即便入站 BodyTemplate 是整份客户端 JSON，入库与探活 body 也必须是紧凑探活体。
func TestLearner_ProbeBodyOmitsClientMessagesSystemToolsAndCredentials(t *testing.T) {
	const uniqueMessage = "UNIQUE_CLIENT_SENTENCE_zephyr-orchid-918273"
	const uniqueSystem = "UNIQUE_SYSTEM_PROMPT_maple-quartz-445566"
	const uniqueTool = "UNIQUE_TOOL_SCHEMA_cobalt-ember-778899"
	const bodyCredential = "sk-ant-body-only-credential-ABCDEFGHijklmnop"

	clientBody := []byte(`{` +
		`"model":"claude-opus-5",` +
		`"system":"` + uniqueSystem + `",` +
		`"tools":[{"name":"` + uniqueTool + `","description":"leak","input_schema":{"type":"object"}}],` +
		`"api_key":"` + bodyCredential + `",` +
		`"stream":true,` +
		`"messages":[{"role":"user","content":"` + uniqueMessage + `"}]` +
		`}`)

	store := &captureLearnerStore{}
	learner := NewLearner(store)
	shape := model.ClientRequestShape{
		BodyTemplate:  append([]byte(nil), clientBody...),
		BodyShapeJSON: []byte(`{"stream":"bool","model":"string","messages":"array"}`),
	}
	if err := learner.ObserveSuccessful(context.Background(), 7, model.EndpointMessages, shape); err != nil {
		t.Fatalf("ObserveSuccessful: %v", err)
	}
	if store.profile == nil {
		t.Fatal("应持久化 candidate profile")
	}
	assertLearnedBodyOmitsPrivateContent(t, store.profile.BodyTemplate,
		uniqueMessage, uniqueSystem, uniqueTool, bodyCredential)
	if !strings.Contains(string(store.profile.BodyTemplate), "{{PROBE_PROMPT}}") {
		t.Fatalf("探活 body 应使用 PROBE_PROMPT 占位符，得到 %s", store.profile.BodyTemplate)
	}
	if !strings.Contains(string(store.profile.BodyTemplate), "{{UPSTREAM_MODEL}}") {
		t.Fatalf("探活 body 应使用 UPSTREAM_MODEL 占位符，得到 %s", store.profile.BodyTemplate)
	}

	// 旧 profile 行即使仍存着整份客户端 body，解析探活时也不得回放私密内容。
	source := &fakeRecipeSource{
		profile: &model.ClientProbeProfile{
			ID: 11, Revision: 2, Status: model.ProfileTested,
			Endpoint:      model.EndpointMessages,
			BodyTemplate:  append([]byte(nil), clientBody...),
			BodyShapeJSON: []byte(`{"stream":"bool"}`),
			SafeHeaders:   []model.HeaderTemplate{{Name: "anthropic-beta", Values: []string{"prompt-caching-2024-07-31"}}},
		},
	}
	resolved, err := testResolver(source).Resolve(context.Background(), RecipeQuery{
		UpstreamID: 1, Endpoint: model.EndpointMessages,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	rendered, err := resolved.Compiled.Render(context.Background(), TemplateValues{
		UpstreamAPIKey: probetemplate.ResolvedValue{Plain: []byte("sk-upstream")},
		UpstreamModel:  probetemplate.ResolvedValue{Plain: []byte("mapped-model")},
		ModelName:      probetemplate.ResolvedValue{Plain: []byte("alias")},
		ProbePrompt:    probetemplate.ResolvedValue{Plain: []byte("1+1=?")},
		SessionID:      probetemplate.ResolvedValue{Plain: []byte("probe-test")},
		Timestamp:      time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	assertLearnedBodyOmitsPrivateContent(t, rendered.Body,
		uniqueMessage, uniqueSystem, uniqueTool, bodyCredential)
	if !strings.Contains(string(rendered.Body), "1+1=?") {
		t.Fatalf("探活应渲染 PROBE_PROMPT，得到 %s", rendered.Body)
	}
	if !strings.Contains(string(rendered.Body), "mapped-model") {
		t.Fatalf("探活应渲染 UPSTREAM_MODEL，得到 %s", rendered.Body)
	}
}

func assertLearnedBodyOmitsPrivateContent(t *testing.T, body []byte, forbidden ...string) {
	t.Helper()
	text := string(body)
	for _, item := range forbidden {
		if item != "" && strings.Contains(text, item) {
			t.Fatalf("learned/probe body 不得含私密片段 %q，得到 %s", item, body)
		}
	}
	for _, key := range []string{`"system"`, `"tools"`, `"metadata"`, `"api_key"`} {
		if strings.Contains(text, key) {
			t.Fatalf("紧凑探活 body 不得含字段 %s，得到 %s", key, body)
		}
	}
}

func assertNoSecretHeaders(t *testing.T, headers []model.HeaderTemplate) {
	t.Helper()
	for _, header := range headers {
		name := strings.ToLower(strings.TrimSpace(header.Name))
		switch name {
		case "authorization", "x-api-key", "api-key", "cookie", "proxy-authorization":
			t.Fatalf("profile 不得保存敏感头 %q", header.Name)
		}
		for _, value := range header.Values {
			if strings.Contains(value, gatewaySessionCookieName) {
				t.Fatalf("profile 不得保存 relay_session，头 %q 值含会话名", header.Name)
			}
		}
	}
}

func headerValue(headers []model.HeaderTemplate, name string) string {
	for _, header := range headers {
		if strings.EqualFold(header.Name, name) && len(header.Values) > 0 {
			return header.Values[0]
		}
	}
	return ""
}
