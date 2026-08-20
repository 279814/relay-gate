package outbound

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probetemplate"
)

type fakeEndpoints struct {
	byKind map[model.EndpointKind]*model.UpstreamEndpoint
	err    error
	asked  []model.EndpointKind
}

func (source *fakeEndpoints) Endpoint(_ context.Context, upstreamID int64,
	kind model.EndpointKind) (*model.UpstreamEndpoint, error) {

	source.asked = append(source.asked, kind)
	if source.err != nil {
		return nil, source.err
	}
	endpoint, ok := source.byKind[kind]
	if !ok {
		return nil, errors.New("endpoint not found")
	}
	if endpoint.UpstreamID != upstreamID {
		return nil, errors.New("upstream mismatch")
	}
	return endpoint, nil
}

func newTestProvider(source *fakeEndpoints, legacy LegacyURLResolver) *Provider {
	return NewProvider(source, legacy, newTestResolver())
}

// Provider 取对那一条 Endpoint 并把结果交给 Resolver —— 不复制 URL 规则。
func TestProvider_ResolvesPerEndpoint(t *testing.T) {
	source := &fakeEndpoints{byKind: map[model.EndpointKind]*model.UpstreamEndpoint{}}
	for _, kind := range []model.EndpointKind{
		model.EndpointMessages, model.EndpointCountTokens, model.EndpointModels,
	} {
		source.byKind[kind] = canonicalEndpoint(kind)
	}
	provider := newTestProvider(source, nil)

	cases := []struct {
		kind model.EndpointKind
		want string
	}{
		{model.EndpointMessages, "https://a.example/v1/messages"},
		{model.EndpointCountTokens, "https://a.example/v1/messages/count_tokens"},
		{model.EndpointModels, "https://a.example/v1/models"},
	}
	for _, c := range cases {
		t.Run(string(c.kind), func(t *testing.T) {
			got, err := provider.ResolveTarget(context.Background(), TargetInput{
				Upstream: testUpstream(), Endpoint: c.kind, Use: ResolveRealForward,
			})
			if err != nil {
				t.Fatal(err)
			}
			if got.RawURL != c.want {
				t.Errorf("want %q got %q", c.want, got.RawURL)
			}
		})
	}
}

// 读不到 Endpoint 时必须报错，绝不能回落到「按 base_url 猜一个」。
func TestProvider_FailsWhenEndpointMissing(t *testing.T) {
	provider := newTestProvider(&fakeEndpoints{err: errors.New("db down")}, nil)
	_, err := provider.ResolveTarget(context.Background(), TargetInput{
		Upstream: testUpstream(), Endpoint: model.EndpointMessages, Use: ResolveRealForward,
	})
	if err == nil {
		t.Fatal("取不到 Endpoint 配置时不能静默解析出一个 URL")
	}
	if !strings.Contains(err.Error(), "db down") {
		t.Errorf("应保留底层错误，得到 %v", err)
	}
}

func TestProvider_RejectsBadInput(t *testing.T) {
	provider := newTestProvider(&fakeEndpoints{byKind: map[model.EndpointKind]*model.UpstreamEndpoint{}}, nil)

	if _, err := provider.ResolveTarget(context.Background(), TargetInput{
		Endpoint: model.EndpointMessages, Use: ResolveRealForward,
	}); err == nil {
		t.Error("缺 upstream 应失败")
	}
	if _, err := provider.ResolveTarget(context.Background(), TargetInput{
		Upstream: testUpstream(), Endpoint: "bogus", Use: ResolveRealForward,
	}); err == nil {
		t.Error("非法 endpoint 应失败")
	}
	if _, err := (*Provider)(nil).ResolveTarget(context.Background(), TargetInput{
		Upstream: testUpstream(), Endpoint: model.EndpointMessages, Use: ResolveRealForward,
	}); err == nil {
		t.Error("未装配的 provider 应失败而不是 panic")
	}
}

// legacy 记录经 Provider 也要 fail closed，用途区分不能在这一层丢掉。
func TestProvider_PropagatesLegacyFailClosed(t *testing.T) {
	source := &fakeEndpoints{byKind: map[model.EndpointKind]*model.UpstreamEndpoint{
		model.EndpointMessages: legacyEndpoint(model.EndpointMessages, true),
	}}
	legacy := &fakeLegacy{id: 55, revision: 2, plain: "https://a.example/legacy"}
	provider := newTestProvider(source, legacy)

	if _, err := provider.ResolveTarget(context.Background(), TargetInput{
		Upstream: testUpstream(), Endpoint: model.EndpointMessages, Use: ResolveSyntheticProbe,
	}); !errors.Is(err, ErrLegacyNeedsReview) {
		t.Fatalf("合成探活应 fail closed，得到 %v", err)
	}

	got, err := provider.ResolveTarget(context.Background(), TargetInput{
		Upstream: testUpstream(), Endpoint: model.EndpointMessages, Use: ResolveRealForward,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.RawURL != "https://a.example/legacy" {
		t.Errorf("真实流量应走 exact URL，得到 %q", got.RawURL)
	}
}

// ── Values ──────────────────────────────────────────────────

type fakeSecrets struct {
	byName map[string]probetemplate.ResolvedSecret
}

func (secrets fakeSecrets) ResolveProbeSecret(_ context.Context,
	name string) (probetemplate.ResolvedSecret, error) {

	secret, ok := secrets.byName[name]
	if !ok {
		return probetemplate.ResolvedSecret{}, errors.New("no such secret")
	}
	return secret, nil
}

func TestValues_ResolvesURLPlaceholders(t *testing.T) {
	values := Values{
		UpstreamAPIKey:     []byte("sk-up"),
		CredentialRevision: 5,
		Secrets: fakeSecrets{byName: map[string]probetemplate.ResolvedSecret{
			"site-token": {ID: 1, Plain: []byte("tok"), Revision: 9},
		}},
	}

	key, err := values.ResolveValue(context.Background(), "UPSTREAM_API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if string(key.Plain) != "sk-up" || key.Revision != 5 {
		t.Errorf("api key 应带 credential revision，得到 %q@%d", key.Plain, key.Revision)
	}

	secret, err := values.ResolveValue(context.Background(), "SECRET:site-token")
	if err != nil {
		t.Fatal(err)
	}
	if string(secret.Plain) != "tok" || secret.Revision != 9 {
		t.Errorf("secret 应带自己的 revision，得到 %q@%d", secret.Plain, secret.Revision)
	}
}

// URL 只支持这两类占位符。模型名、prompt 属于 body 模板（P0-05），
// 在这里放行会让「谁提供什么」变得模糊，也会让一个拼错的占位符静默渲染成空。
func TestValues_RejectsNonURLPlaceholders(t *testing.T) {
	values := Values{UpstreamAPIKey: []byte("sk-up"), CredentialRevision: 1}
	for _, name := range []string{"UPSTREAM_MODEL", "PROBE_PROMPT", "SESSION_ID", "TIMESTAMP", "", "SECRET:"} {
		if _, err := values.ResolveValue(context.Background(), name); err == nil {
			t.Errorf("占位符 %q 不该被 URL 层接受", name)
		}
	}
}

func TestValues_FailsWhenKeyOrSourceMissing(t *testing.T) {
	if _, err := (Values{}).ResolveValue(context.Background(), "UPSTREAM_API_KEY"); err == nil {
		t.Error("未配置 api_key 时不能渲染出空值")
	}
	if _, err := (Values{}).ResolveValue(context.Background(), "SECRET:x"); err == nil {
		t.Error("没有 Secret 源时应报错")
	}
}
