package probe

// 按解析出的 Recipe 发探活请求（§8.6 的 ProbeExecutor 前半）。
//
// 这个文件替掉的是 buildProbeBody + buildHeaders 那条硬拼路径。为什么必须替：
// 硬拼路径下「探活到底发了什么」由 Go 代码回答，而用户配的 Recipe 完全没有
// 消费方 —— 也就是说 P0-05 交付的四级解析在生产里从未被调用过。更要紧的是
// 那条路径绕过了模板层的全部校验（受保护头、凭据门禁、CR/LF 拒绝），
// 于是「探活请求」与「用户可配置的请求」是两套语义。
//
// 现在只有一条路径：解析 → 渲染 → 装配认证 → 发送。四级解析的最后一级是
// 内置 manifest，所以「没有任何用户配置」也走同一条路。

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/probetemplate"
	"github.com/279814/relay-gate/internal/sample"
)

// preparedProbe 是一次探活「已经准备好、还没发出去」的全部内容。
//
// 准备与发送分开是 §8.6 的要求（「模板、URL、Secret 或头校验失败为
// config_error，不发送请求，不改变健康」）：任何一步失败都必须在出网之前
// 结束，而把两件事写在一个函数里迟早会出现「已经拨了连接才发现 Secret 没装配」。
type preparedProbe struct {
	recipe  ResolvedRecipe
	request *http.Request

	// connectionOnly 表示这次 L1 只探连接层，任何响应都算通（§4.1）。
	//
	// 在这里定而不是让 L1 去看请求方法：那个判据会被一份 method=HEAD 的
	// models 配方冒充。两者本来就会分开 —— 迁移在 l1_path 为空时物化了一份
	// HEAD 配方（store/migrate_backfill.go 的 backfillLegacyModelsRecipe），
	// 而用户之后把 l1_path 改回 /v1/models 时只有 url_override 被重译，
	// 那份不可变的配方仍是 HEAD。于是「看方法」会让这个站的 L1 对 500 判通，
	// 站级门禁放行、L2 继续往一个已死的站上烧 token，而界面显示健康。
	connectionOnly bool
}

// prepare 解析并渲染出一次探活请求。
//
// mn 与 rt 可以为 nil（L1 打的是站级 /v1/models，没有模型上下文）。那种情况下
// 引用 {{MODEL_NAME}} 的模板会以「未装配」失败 —— 这是对的：一个 upstream 作用域
// 的 endpoint 上没有唯一的模型名，静默填一个会让探活打的模型与任何 Route 都无关。
func (p *Prober) prepare(ctx context.Context, up *model.Upstream, mn *model.ModelName,
	rt *model.Route, endpoint model.EndpointKind) (*preparedProbe, error) {

	// 没有出站解析器就地失败，**不自己拼一个地址**：探活打的地址必须与真实
	// 请求完全一致，各拼一套的话「探活通过」不代表真实请求能通，而那个差异
	// 只在生产流量上显形。
	//
	// 这道检查不能省成「反正装配时会传」：Prober 与它的字段都是导出的，
	// 而这里跑在 Scheduler 起的 goroutine 里 —— 那里没有 recover，
	// 一次 nil 解引用会带崩整个网关进程。
	if p.Targets == nil {
		return nil, errors.New("探活未装配出站目标解析器")
	}

	var routeID int64
	if rt != nil {
		routeID = rt.ID
	}
	resolved, err := p.recipes().Resolve(ctx, RecipeQuery{
		UpstreamID: up.ID, RouteID: routeID, Endpoint: endpoint,
	})
	if err != nil {
		return nil, err
	}

	values, err := p.templateValues(ctx, up, mn, rt, resolved)
	if err != nil {
		return nil, err
	}
	rendered, err := resolved.Compiled.Render(ctx, values)
	if err != nil {
		// 不复述下层文本：probetemplate.Render 用 %w 包了 ValueResolver 的错误，
		// 而那条错误会落进 route_health.last_error（**落库**）并显示在管理界面上。
		// TemplateValues 自己的错误只带占位符名，不带值，所以这里可以带上 ——
		// 但 Secret 解析失败的那条来自 store，不保证同样克制。
		return nil, fmt.Errorf("渲染 %s 层 recipe: %w", resolved.Layer, err)
	}

	// 渲染出的 RawQuery 当作「入站 query」交给 Resolver：Endpoint 的固定 query
	// （认证参数那类）与 Recipe 的固定 query（?beta=true）是两个来源，拼接顺序
	// 由 Resolver 独占（§7.1）。在这里自己拼一次就是第二份 URL 规则。
	target, err := p.Targets.ResolveTarget(ctx, outbound.TargetInput{
		Upstream:         up.ProbeConfig(),
		Endpoint:         endpoint,
		IncomingRawQuery: rendered.RawQuery,
		Values:           p.values(up),
		Use:              outbound.ResolveSyntheticProbe,
	})
	if err != nil {
		return nil, err
	}

	method := rendered.Method
	// 空 l1_path 的语义是「只探连接层」，也就是 HEAD base_url。这一项 URL 层
	// 表达不了（EndpointURLOverride 只能给出地址），而 Recipe 里写死 HEAD
	// 也不行 —— 同一份内置模板要服务两种 l1_path 配置。
	connectionOnly := endpoint == model.EndpointModels && strings.TrimSpace(up.L1Path) == ""
	if connectionOnly {
		method = http.MethodHead
	}

	var bodyReader *strings.Reader
	if len(rendered.Body) > 0 {
		bodyReader = strings.NewReader(string(rendered.Body))
	}
	request, err := newProbeRequest(ctx, method, target.RawURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("构造 %s 探活请求: %w", endpoint, err)
	}
	request.Header = rendered.Header
	if err := p.applyProbeHeaders(ctx, request.Header, up, target); err != nil {
		return nil, err
	}
	if target.RequestHost != "" {
		request.Host = target.RequestHost
	}
	request.ContentLength = int64(len(rendered.Body))

	return &preparedProbe{recipe: resolved, request: request, connectionOnly: connectionOnly}, nil
}

// estimatedTokens 是这次探活的估算 token 上界（§5.2d）。
//
// 命中内置层时用 manifest 的声明值：那是这份模板的作者按它实际的 body 写的，
// 比在这里数一遍字节更准。其余三层回落到按 ModelName 粗算 —— 用户配的 recipe
// 里没有「预计多少 token」这一项，而要求他填一个会让创建 recipe 多一道
// 没人能填准的坎（P0-14 的 API 层若加上这一项，这里跟着改）。
//
// mn 为 nil（L1）时回 0：models 端点零 token。
func (prepared *preparedProbe) estimatedTokens(mn *model.ModelName) int {
	if prepared == nil {
		return 0
	}
	if builtin := prepared.recipe.Builtin; builtin != nil {
		return int(builtin.EstimatedCost())
	}
	if mn == nil {
		return 0
	}
	return estimateL2Tokens(mn)
}

// newProbeRequest 包一层只为处理「没有 body 时必须传 nil」。
//
// 传一个空的 strings.Reader 会让 http 库发出 `Content-Length: 0`，而 GET/HEAD
// 带 Content-Length 会被一部分站当成畸形请求拒掉 —— 那是一个由我们自己
// 造出来的 400，却会被归类成「这个站不支持 /v1/models」。
func newProbeRequest(ctx context.Context, method, url string, body *strings.Reader) (*http.Request, error) {
	if body == nil {
		return http.NewRequestWithContext(ctx, method, url, nil)
	}
	return http.NewRequestWithContext(ctx, method, url, body)
}

// recipes 返回本次探活用的解析器。
//
// 未装配时退化成「只有内置模板」的解析器，而不是报错：内置 manifest 是
// embed 的，零配置可用，所以这个退化仍然发得出一个正确的请求。它服务两类
// 调用方 —— 只关心传输行为的测试，以及 P0-14 之前（用户还无法创建 Recipe）
// 的运行时。
//
// 生产装配仍要显式传（main.go）：漏传的后果是用户已发布的 Recipe 被忽略，
// 而那不会报错。端到端测试
// （internal/outbound/recipe_resolution_test.go）盯的正是这条。
func (p *Prober) recipes() *RecipeResolver {
	if p.Recipes != nil {
		return p.Recipes
	}
	return builtinOnlyResolver()
}

// templateValues 装配六个内置占位符（§8.5）。
//
// 每次探活现造一个：Secret 与 key 的明文不该常驻在任何长生命周期对象里。
func (p *Prober) templateValues(ctx context.Context, up *model.Upstream, mn *model.ModelName,
	rt *model.Route, resolved ResolvedRecipe) (TemplateValues, error) {

	values := TemplateValues{
		UpstreamAPIKey: probetemplate.ResolvedValue{
			Plain: []byte(up.APIKey), Revision: up.CredentialRevision,
		},
		// SESSION_ID 每次现生成。§8.3 明确禁止把某次抓包的会话 ID 写进模板，
		// 而复用一个固定值等价于写死 —— 上游可以据此把连续多次探活看成
		// 同一个会话，而那不是我们要表达的东西。
		SessionID: probetemplate.ResolvedValue{Plain: []byte("probe-" + sample.NewReqID())},
		Timestamp: time.Now(),
	}
	if mn != nil {
		values.ModelName = probetemplate.ResolvedValue{Plain: []byte(mn.Name)}
		values.ProbePrompt = probetemplate.ResolvedValue{Plain: []byte(probePrompt(mn))}
		// UPSTREAM_MODEL 是映射后的名字：配了映射就探映射后的，没配用原名。
		// 与转发路径同一条规则（§3.3.2）—— 两边不一致的话，探活通过而真实
		// 请求 model_not_found，而那种故障看起来像「上游偶发」。
		values.UpstreamModel = probetemplate.ResolvedValue{Plain: []byte(upstreamModel(mn, rt))}
	}

	secrets, err := p.resolveSecrets(ctx, resolved)
	if err != nil {
		return TemplateValues{}, err
	}
	values.Secrets = secrets
	return values, nil
}

// resolveSecrets 解析并按 §4.5 校验模板要的 Probe Secret。
//
// 按**编译结果**要的名字去解析，再交给 BindSecrets 与 ref 快照对齐。反过来
// （按 ref 清单解析）会漏掉「模板引用了但 ref 里没有」这种不同源的情况 ——
// 而那正是 BindSecrets 的「多余」分支要报的。
func (p *Prober) resolveSecrets(ctx context.Context,
	resolved ResolvedRecipe) (map[string]probetemplate.ResolvedValue, error) {

	required := resolved.Compiled.RequiredSecrets()
	if len(required) == 0 && len(resolved.SecretRefs) == 0 {
		return nil, nil
	}
	if p.Secrets == nil {
		return nil, fmt.Errorf("%w: recipe 引用了 Probe Secret %v，但未装配 Secret 源",
			ErrTemplateValue, required)
	}

	resolvedSecrets := make(map[string]probetemplate.ResolvedSecret, len(required))
	for _, name := range required {
		secret, err := p.Secrets.ResolveProbeSecret(ctx, name)
		if err != nil {
			// 只带名字。这条错误会落库并显示在界面上。
			return nil, fmt.Errorf("%w: Probe Secret %q 不可用", ErrTemplateValue, name)
		}
		resolvedSecrets[name] = secret
	}
	return BindSecrets(resolved.SecretRefs, resolvedSecrets)
}

// applyProbeHeaders 在渲染出的头上叠加 Upstream 级覆盖，再装配认证。
//
// 顺序是不变量：覆盖先、认证后。反过来的话，probe_headers 里的一个
// Authorization 会盖掉 ApplyAuth 刚写的那个 —— 而 probe_headers 是明文 JSON，
// 等于给这个站开了第二个不受加密保护的 key 来源。
func (p *Prober) applyProbeHeaders(ctx context.Context, header http.Header, up *model.Upstream,
	target outbound.ResolvedTarget) error {

	applyUpstreamHeaderOverrides(header, up)
	return outbound.ApplyAuth(ctx, header, outbound.AuthInput{
		Profile: target.AuthProfile,
		Values:  p.values(up),
		Use:     outbound.ResolveSyntheticProbe,
	})
}

// probePrompt 取探活 prompt，空则回落。
//
// 与 estimateL2Tokens 用同一个回落值：两处不一致会让成本估算算的是
// 另一个 prompt 的长度。
func probePrompt(mn *model.ModelName) string {
	if prompt := mn.ProbePrompt; prompt != "" {
		return prompt
	}
	return defaultProbePrompt
}

// upstreamModel 是要发给上游的模型名（§3.3.2）。
func upstreamModel(mn *model.ModelName, rt *model.Route) string {
	if rt != nil && rt.UpstreamModel != "" {
		return rt.UpstreamModel
	}
	return mn.Name
}

// defaultProbePrompt 是 probe_prompt 为空时的回落值，与 model.Defaults 一致。
const defaultProbePrompt = "1+1=?"

// builtinOnlyResolverInstance 是那个「只有内置模板」的解析器。
//
// 全局一份而不是每次现造：它没有任何 per-probe 状态，而 Resolver 会被并发的
// 探活共用（Resolve 只读自己的字段）。
var builtinOnlyResolverInstance = NewRecipeResolver(noRecipeSource{}).
	WithNotFound(func(err error) bool { return errors.Is(err, errNoRecipeSource) })

func builtinOnlyResolver() *RecipeResolver { return builtinOnlyResolverInstance }

// errNoRecipeSource 是 noRecipeSource 的「这一级没有」。
var errNoRecipeSource = errors.New("未装配 Recipe 数据源")

// noRecipeSource 让三个数据库层一律「没有」，于是解析直落内置模板。
//
// 用一个显式的空实现而不是让 Resolve 容忍 nil source：nil 容忍会让
// 「忘了装配」与「刻意只用内置模板」在 Resolver 内部长得一样，而前者是
// 需要被发现的装配错误。
type noRecipeSource struct{}

func (noRecipeSource) PublishedRouteRecipe(context.Context, int64,
	model.EndpointKind) (*model.PublishedRecipeBinding, error) {
	return nil, errNoRecipeSource
}

func (noRecipeSource) PublishedUpstreamRecipe(context.Context, int64,
	model.EndpointKind) (*model.PublishedRecipeBinding, error) {
	return nil, errNoRecipeSource
}

func (noRecipeSource) TestedClientProfile(context.Context, int64,
	model.EndpointKind) (*model.ClientProbeProfile, error) {
	return nil, errNoRecipeSource
}

func (noRecipeSource) RecipeVersionSecretRefs(context.Context, int64) ([]model.RequiredSecretRef, error) {
	return nil, nil
}
