package outbound

import (
	"context"
	"fmt"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probetemplate"
)

// TargetInput 是调用方视角的一次解析请求：它只知道「哪个站的哪个端点」，
// 不需要自己去取 Endpoint 记录。
type TargetInput struct {
	Upstream         *model.ProbeUpstreamConfig
	Endpoint         model.EndpointKind
	IncomingRawQuery string
	Values           ValueResolver
	Use              ResolveUse
}

// EndpointConfigSource 取一条已物化的 Endpoint 配置。
//
// P0-03 由 Store 直接实现；P0-10 换成同代 ConfigBundle 的 snapshot adapter。
// 两者共享同一个 Provider 与 Resolver —— 换实现不复制一份 URL 规则。
type EndpointConfigSource interface {
	Endpoint(ctx context.Context, upstreamID int64, endpoint model.EndpointKind) (*model.UpstreamEndpoint, error)
}

// TargetProvider 是三条出站路径（真实转发、探活、count_tokens）共用的入口。
type TargetProvider interface {
	ResolveTarget(ctx context.Context, in TargetInput) (ResolvedTarget, error)
}

// Provider 是 TargetProvider 的过渡实现。
//
// 刻意很窄：取一条 Endpoint、把调用方固定的 Upstream/Values 与统一的
// LegacyURLResolver 交给 Resolver。它不选 Route、不挑 Recipe、不解析模型或
// 认证，也**不缓存第二份 URL 规则** —— 缓存了就等于又有了两套真相。
type Provider struct {
	endpoints EndpointConfigSource
	legacy    LegacyURLResolver
	resolver  *Resolver
}

func NewProvider(endpoints EndpointConfigSource, legacy LegacyURLResolver, resolver *Resolver) *Provider {
	return &Provider{endpoints: endpoints, legacy: legacy, resolver: resolver}
}

func (provider *Provider) ResolveTarget(ctx context.Context, in TargetInput) (ResolvedTarget, error) {
	if provider == nil || provider.endpoints == nil || provider.resolver == nil {
		return ResolvedTarget{}, model.WrapValidation("target provider 未装配")
	}
	if in.Upstream == nil {
		return ResolvedTarget{}, model.WrapValidation("target input 缺少 upstream 配置")
	}
	if !in.Endpoint.Valid() {
		return ResolvedTarget{}, model.WrapValidation("endpoint 无效: %q", in.Endpoint)
	}
	endpoint, err := provider.endpoints.Endpoint(ctx, in.Upstream.ID, in.Endpoint)
	if err != nil {
		return ResolvedTarget{}, fmt.Errorf("读取 upstream %d 的 %s endpoint: %w",
			in.Upstream.ID, in.Endpoint, err)
	}
	return provider.resolver.Resolve(ctx, ResolveInput{
		Upstream:         in.Upstream,
		Endpoint:         endpoint,
		LegacyURLs:       provider.legacy,
		IncomingRawQuery: in.IncomingRawQuery,
		Values:           in.Values,
		Use:              in.Use,
	})
}

// SecretSource 按名字解析一个 Probe Secret。由 store.Store 实现。
type SecretSource interface {
	ResolveProbeSecret(ctx context.Context, name string) (probetemplate.ResolvedSecret, error)
}

// Values 把「这次出站可用的值」组装成 ValueResolver。
//
// 每次 Attempt 由调用方现造一个：Secret 明文不该常驻在任何长生命周期对象里。
// 只实现 URL 需要的两类占位符 —— 模型名、prompt 这些属于 body 模板，
// 由 P0-05 的 Recipe 渲染负责，混进来只会让「谁该提供什么」变得模糊。
type Values struct {
	UpstreamAPIKey     []byte
	CredentialRevision int64
	Secrets            SecretSource
}

func (values Values) ResolveValue(ctx context.Context, name string) (ResolvedValue, error) {
	if name == "UPSTREAM_API_KEY" {
		if len(values.UpstreamAPIKey) == 0 {
			return ResolvedValue{}, model.WrapValidation("upstream api_key 未配置")
		}
		return ResolvedValue{Plain: values.UpstreamAPIKey, Revision: values.CredentialRevision}, nil
	}
	const prefix = "SECRET:"
	if len(name) > len(prefix) && name[:len(prefix)] == prefix {
		if values.Secrets == nil {
			return ResolvedValue{}, model.WrapValidation("未配置 Probe Secret 源")
		}
		secret, err := values.Secrets.ResolveProbeSecret(ctx, name[len(prefix):])
		if err != nil {
			// 错误里只带占位符名，不带值：这条错误会流进 last_error 并显示在
			// 管理界面上（§4.3 的 config_error 路径）。
			return ResolvedValue{}, fmt.Errorf("Probe Secret %q 不可用: %w", name[len(prefix):], err)
		}
		return ResolvedValue{Plain: secret.Plain, Revision: secret.Revision}, nil
	}
	return ResolvedValue{}, model.WrapValidation("URL 不支持占位符 %q", name)
}
