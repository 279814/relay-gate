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
	c.profile = &cp
	return nil
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
