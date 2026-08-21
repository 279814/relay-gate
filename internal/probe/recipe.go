package probe

// Recipe 四级解析（§8.2）。
//
// 优先级从高到低：
//
//  1. Route 对该 Endpoint 的已发布配方
//  2. Upstream 对该 Endpoint 的已发布配方
//  3. ClientFingerprintLearner 产出的**已测试** profile
//  4. 内置协议模板（P0-06 的 manifest）
//
// 为什么解析要单独一层而不是让探活自己挑：解析结果要连同「凭哪一层选中的」
// 一起进 ProbeExecution，而 Store 会在写回时按那份记录重读并比较（§计划
// 1436 行）。挑选逻辑散在调用点的话，那份记录与实际选择迟早不一致，
// 而不一致的表现是 Capability 无法归因地反复 stale。

import (
	"context"
	"errors"
	"fmt"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probetemplate"
)

// ErrNoRecipe 表示四级全无可用配方。
//
// 接上内置模板（第 4 级）之后，这个错误只在**该 endpoint 连内置模板都没有**
// 时出现 —— 也就是说它从「常规兜底路径」变成了「manifest 缺了一个 endpoint」
// 这种发布事故。留着它而不是 panic：探活失败该报成一次 config_error，
// 不该拖垮进程。
//
// 单独一个哨兵而不是返回 nil：nil 会让「没有配方」与「解析出错」在调用点
// 长得一样，而后者必须报出来 —— 一份编译不过的 published recipe 静默改用
// 内置模板的话，用户看不到任何提示，而他配的那份其实是坏的。
var ErrNoRecipe = errors.New("该 endpoint 没有已发布配方、已测试 profile 或内置模板")

// RecipeSource 是四级解析要读的三个来源，由 store.Store 实现。
//
// 定义成接口而不是直接收 *store.Store：probe 依赖 store 会成环
// （store 侧要用 probe 的 reducer）。三个方法的「没有」都用各自实现的
// not-found 错误表达，由 WithNotFound 注入判据。
type RecipeSource interface {
	PublishedRouteRecipe(ctx context.Context, routeID int64, endpoint model.EndpointKind) (*model.PublishedRecipeBinding, error)
	PublishedUpstreamRecipe(ctx context.Context, upstreamID int64, endpoint model.EndpointKind) (*model.PublishedRecipeBinding, error)
	TestedClientProfile(ctx context.Context, upstreamID int64, endpoint model.EndpointKind) (*model.ClientProbeProfile, error)
	RecipeVersionSecretRefs(ctx context.Context, versionID int64) ([]model.RequiredSecretRef, error)
}

// RecipeQuery 是一次解析的输入。
//
// RouteID 为 0 表示没有 Route 上下文（L1 打的是站级 /v1/models），
// 此时跳过第 1 级 —— 那是正常调用，不是错误。
type RecipeQuery struct {
	UpstreamID int64
	RouteID    int64
	Endpoint   model.EndpointKind
}

// ResolvedRecipe 是解析结果：可执行内容 + 它的身份与选择依据。
type ResolvedRecipe struct {
	Layer    model.RecipeResolvedLayer
	Identity model.RecipeIdentity
	// Facts 只编码**实际影响选择**的层（§计划 1436 行）。
	Facts model.RecipeBindingFacts
	// Compiled 已编译好。解析时就编译是刻意的：编译不过的配方应该在这里
	// 报错，而不是等到发请求前 —— 后者会把 config_error 的归因落在探活执行上，
	// 而真正的问题在那份配置里。
	Compiled *probetemplate.CompiledRecipe
	// SecretRefs 是该版本绑定时的 Secret 快照，交给 BindSecrets 校验。
	SecretRefs []model.RequiredSecretRef
	// StreamExpected 与 TimeoutProfile 是执行这份配方所需的两项，随解析一起
	// 带出来 —— 它们存在 recipe version 里，而调用方拿不到那条记录。
	//
	// 与 Compiled 出自同一条记录，所以必须一起带出：分两次读会让
	// 「用新模板配旧超时档」成为可能。
	//
	// profile 层没有这两项：learner 学的是请求形状，而超时档按 endpoint 推。
	StreamExpected bool
	TimeoutProfile model.ProbeTimeoutProfile

	// Builtin 只在命中第 4 级时非 nil，带出 token 估算与最小输出说明。
	//
	// 单独一个字段而不是把估算值抬到 ResolvedRecipe 上：前三级的成本要按
	// ModelName 的 probe_max_tokens 估（那是用户配的），而内置模板的估算写在
	// manifest 里。抬上来就得给前三级填一个「算出来的」值，于是两种来源在
	// 同一个字段里，读的人无从知道手上这个是哪种。
	Builtin *BuiltinTemplate
}

// RecipeResolver 按 §8.2 的优先级解析配方。
type RecipeResolver struct {
	source   RecipeSource
	notFound func(error) bool
	// builtins 是第 4 级。为 nil 表示用 embed 的那一份（LoadBuiltinTemplates
	// 自带 sync.Once 缓存）。不在构造时加载是为了让 NewRecipeResolver 不返回
	// error：manifest 是 embed 的常量数据，加载失败是发布事故，而把它变成
	// 构造函数的 error 会让每个调用点都要处理一个生产里不可能出现的分支。
	//
	// 只在 WithBuiltins 里写，之后只读 —— Resolver 被并发探活共用。
	builtins *BuiltinSet
}

func NewRecipeResolver(source RecipeSource) *RecipeResolver {
	return &RecipeResolver{source: source, notFound: func(error) bool { return false }}
}

// WithNotFound 注入「这一级没有」的判据。
//
// 由调用方给而不是在这里 import store：那会让 probe → store → probe 成环。
// main 装配时传 func(err error) bool { return errors.Is(err, store.ErrNotFound) }。
func (resolver *RecipeResolver) WithNotFound(isNotFound func(error) bool) *RecipeResolver {
	if isNotFound != nil {
		resolver.notFound = isNotFound
	}
	return resolver
}

// WithBuiltins 换掉第 4 级用的内置模板集合，供测试注入。
//
// 生产不用调它：Resolve 会自己加载 embed 的那一份。
func (resolver *RecipeResolver) WithBuiltins(set *BuiltinSet) *RecipeResolver {
	resolver.builtins = set
	return resolver
}

// Resolve 按优先级取第一个可用的配方。
//
// 命中高优先级就**不查**低优先级：那既是省一次库查询，也是为了让
// BindingFacts 不可能记进被遮蔽的层 —— 没查过的东西填不进去。
func (resolver *RecipeResolver) Resolve(ctx context.Context, query RecipeQuery) (ResolvedRecipe, error) {
	if resolver == nil || resolver.source == nil {
		return ResolvedRecipe{}, model.WrapValidation("recipe resolver 未装配来源")
	}
	if query.UpstreamID < 1 {
		return ResolvedRecipe{}, model.WrapValidation("recipe 解析缺少 upstream")
	}
	if !query.Endpoint.Valid() {
		return ResolvedRecipe{}, model.WrapValidation("recipe 解析的 endpoint 无效: %q", query.Endpoint)
	}

	// 第 1 级：Route published。RouteID 为 0 时整层跳过。
	if query.RouteID > 0 {
		binding, err := resolver.source.PublishedRouteRecipe(ctx, query.RouteID, query.Endpoint)
		switch {
		case err == nil:
			return resolver.fromBinding(ctx, query, binding, model.ResolvedRoute)
		case !resolver.notFound(err):
			return ResolvedRecipe{}, fmt.Errorf("读取 Route %d 的已发布配方: %w", query.RouteID, err)
		}
	}

	// 第 2 级：Upstream published。
	binding, err := resolver.source.PublishedUpstreamRecipe(ctx, query.UpstreamID, query.Endpoint)
	switch {
	case err == nil:
		return resolver.fromBinding(ctx, query, binding, model.ResolvedUpstream)
	case !resolver.notFound(err):
		return ResolvedRecipe{}, fmt.Errorf("读取 Upstream %d 的已发布配方: %w", query.UpstreamID, err)
	}

	// 第 3 级：已测试的 learned profile。
	profile, err := resolver.source.TestedClientProfile(ctx, query.UpstreamID, query.Endpoint)
	switch {
	case err == nil:
		return resolver.fromProfile(query, profile)
	case !resolver.notFound(err):
		return ResolvedRecipe{}, fmt.Errorf("读取 Upstream %d 的已测试 profile: %w", query.UpstreamID, err)
	}

	// 第 4 级：内置模板（P0-06 的 manifest）。
	return resolver.fromBuiltin(query)
}

// fromBuiltin 取该 endpoint 的内置 compact 模板（第 4 级、§8.3）。
//
// 取 compact 而不是遍历全部候选：周期探活优先 compact-native（§8.3 明文），
// 而带 requires 的候选（如 context-1m）不该被自动选中 —— 那会让所有站都发
// 一个真实客户端不发的开关。挑选那些候选是 CalibrationRun 的事（§8.7）。
func (resolver *RecipeResolver) fromBuiltin(query RecipeQuery) (ResolvedRecipe, error) {
	// 不在这里把加载结果写回 resolver：一个 Resolver 被并发的探活共用
	// （Scheduler 持有它），写字段就是数据竞争。LoadBuiltinTemplates 自己用
	// sync.Once 缓存，重复调用只是一次 map 读。
	set := resolver.builtins
	if set == nil {
		loaded, err := LoadBuiltinTemplates()
		if err != nil {
			// 不包成 ErrNoRecipe：manifest 坏了是发布事故，而 ErrNoRecipe
			// 的语义是「这个 endpoint 本就没有兜底」。混起来会让一个数据文件
			// 的问题看起来像配置缺失。
			return ResolvedRecipe{}, fmt.Errorf("加载内置模板: %w", err)
		}
		set = loaded
	}

	template, err := set.Compact(query.Endpoint)
	if err != nil {
		return ResolvedRecipe{}, fmt.Errorf("%w: upstream=%d route=%d endpoint=%s: %v",
			ErrNoRecipe, query.UpstreamID, query.RouteID, query.Endpoint, err)
	}

	identity := template.Identity()
	if err := identity.Validate(); err != nil {
		return ResolvedRecipe{}, fmt.Errorf("内置模板 %q 的 identity 不合法: %w", template.ID, err)
	}

	return ResolvedRecipe{
		Layer:    model.ResolvedEmbedded,
		Identity: identity,
		Facts: model.RecipeBindingFacts{
			Use:           model.BindingResolved,
			ResolvedLayer: model.ResolvedEmbedded,
			// 三个高优先级层都查过且都不存在，全部留零值 —— 「查过、不存在」
			// 由 ResolvedLayer 表达（§8.2：高优先级的 absence 是受验证的事实）。
		},
		Compiled: template.Compiled(),
		// 内置模板不引用 Secret（加载时已拒绝），所以没有 ref 可带。
		SecretRefs:     nil,
		StreamExpected: template.StreamExpected,
		TimeoutProfile: template.TimeoutProfile,
		Builtin:        template,
	}, nil
}

// fromBinding 把一条 DB binding 变成可执行的解析结果。
func (resolver *RecipeResolver) fromBinding(ctx context.Context, query RecipeQuery,
	binding *model.PublishedRecipeBinding, layer model.RecipeResolvedLayer) (ResolvedRecipe, error) {

	if binding == nil {
		return ResolvedRecipe{}, model.WrapValidation("%s 层返回了空 binding", layer)
	}
	compiled, err := probetemplate.Compile(query.Endpoint, binding.Version)
	if err != nil {
		// 不包成 ErrNoRecipe：那会让调用方静默改用内置模板，而用户配的
		// 这份配方其实是坏的，没有任何提示。
		return ResolvedRecipe{}, fmt.Errorf("编译 %s 层配方 recipe=%d version=%d: %w",
			layer, binding.Recipe.ID, binding.Version.ID, err)
	}
	refs, err := resolver.source.RecipeVersionSecretRefs(ctx, binding.Version.ID)
	if err != nil {
		return ResolvedRecipe{}, fmt.Errorf("读取 version %d 的 Secret 引用: %w", binding.Version.ID, err)
	}

	identity := model.RecipeIdentity{
		Storage:     model.RecipeStorageDB,
		Origin:      binding.Version.Origin,
		DBVersionID: binding.Version.ID,
	}
	if err := identity.Validate(); err != nil {
		return ResolvedRecipe{}, fmt.Errorf("%s 层 recipe identity 不合法: %w", layer, err)
	}

	// facts 只填选中的那一层。被遮蔽的层留零值 —— 见 ResolvedRecipe.Facts
	// 的说明与 §计划 1436 行。
	facts := model.RecipeBindingFacts{Use: model.BindingResolved, ResolvedLayer: layer}
	switch layer {
	case model.ResolvedRoute:
		facts.RouteRecipeID = binding.Recipe.ID
		facts.RoutePublishedVersionID = binding.Version.ID
		facts.RouteBindingRevision = binding.Recipe.ActiveBindingRevision
	case model.ResolvedUpstream:
		facts.UpstreamRecipeID = binding.Recipe.ID
		facts.UpstreamPublishedVersionID = binding.Version.ID
		facts.UpstreamBindingRevision = binding.Recipe.ActiveBindingRevision
	default:
		return ResolvedRecipe{}, model.WrapValidation("DB binding 不该出现在 %s 层", layer)
	}

	return ResolvedRecipe{
		Layer: layer, Identity: identity, Facts: facts,
		Compiled: compiled, SecretRefs: refs,
		StreamExpected: binding.Version.StreamExpected,
		TimeoutProfile: binding.Version.TimeoutProfile,
	}, nil
}

// fromProfile 把一个已测试的 learned profile 变成可执行的解析结果。
//
// 只接受 status=tested。candidate 是学习器刚生成、还没经过一次测试的形状，
// 拿它去探活等于用一份没人验证过的请求形状判断站点健康 —— §8.4 明确要求
// 「经脱敏差异预览和一次测试后才能用于自动探活」。
func (resolver *RecipeResolver) fromProfile(query RecipeQuery,
	profile *model.ClientProbeProfile) (ResolvedRecipe, error) {

	if profile == nil {
		return ResolvedRecipe{}, model.WrapValidation("profile 层返回了空 profile")
	}
	if profile.Status != model.ProfileTested {
		// 与「这一级没有」同义：未测试的 profile 不参与解析，落到内置模板。
		return ResolvedRecipe{}, fmt.Errorf("%w: profile %d 状态为 %s，未经测试",
			ErrNoRecipe, profile.ID, profile.Status)
	}

	// profile 存的是 shape，不含 method 与超时档 —— 它是从真实请求学来的，
	// 而真实请求的方法由 endpoint 决定。
	compiled, err := probetemplate.CompileContent(query.Endpoint, probetemplate.TemplateContent{
		Method:   query.Endpoint.Method(),
		RawQuery: profile.FixedRawQuery,
		Headers:  profile.SafeHeaders,
		Body:     profile.BodyTemplate,
	})
	if err != nil {
		// 同 fromBinding：不包成 ErrNoRecipe。读取后要再校验一次是
		// §计划 1440 行的明文要求（「数据库约束无法独自证明安全，
		// 写入前必须经 learner sanitizer，读取后再次校验再参与 Recipe 解析」）。
		return ResolvedRecipe{}, fmt.Errorf("编译 profile %d 的 shape: %w", profile.ID, err)
	}
	// profile 层不带 SecretRefs，所以它也不能引用 Secret。
	//
	// 引用了的话，编译结果要求那个 Secret 而 SecretRefs 是 nil —— BindSecrets
	// 收不到任何 ref 可校验，于是这个 Secret 绕过了 §4.5 的「同名新建的 Secret
	// 不自动满足旧引用」。那道边界靠的正是「绑定时的 secret_id 与当下解析出的
	// 比对」，而 profile 从来没有过绑定这一步。
	//
	// 不给 profile 补一份 ref 表：learner 学的是**客户端发来的**请求形状，
	// 认证由 Endpoint 的 auth profile 提供（§7.2）—— 一个从真实流量里学来的
	// shape 本就不该声明凭据来源。
	if secrets := compiled.RequiredSecrets(); len(secrets) > 0 {
		return ResolvedRecipe{}, model.WrapValidation(
			"profile %d 的 shape 引用了 Probe Secret %v，而 profile 层没有绑定快照可校验；"+
				"需要 Secret 的请求形状请建成 Recipe 并发布（§4.5、§7.2）", profile.ID, secrets)
	}

	identity := model.RecipeIdentity{
		Storage:         model.RecipeStorageProfile,
		Origin:          model.RecipeLearned,
		ClientProfileID: profile.ID,
		Revision:        profile.Revision,
	}
	if err := identity.Validate(); err != nil {
		return ResolvedRecipe{}, fmt.Errorf("profile recipe identity 不合法: %w", err)
	}

	return ResolvedRecipe{
		Layer:    model.ResolvedProfile,
		Identity: identity,
		Facts: model.RecipeBindingFacts{
			Use:                   model.BindingResolved,
			ResolvedLayer:         model.ResolvedProfile,
			TestedProfileID:       profile.ID,
			TestedProfileRevision: profile.Revision,
		},
		Compiled: compiled,
		// profile 层没有 Secret 快照，上面也已拒绝引用 Secret 的 shape：
		// 认证由 Endpoint 的 auth profile 提供（§7.2）。
		SecretRefs: nil,
		// 超时档按 endpoint 推：profile 不存这一项。
		TimeoutProfile: defaultTimeoutProfile(query.Endpoint),
	}, nil
}

// defaultTimeoutProfile 按 endpoint 给出超时档。
//
// 与 model.ProbeRecipeVersion.ValidateForEndpoint 的约束一致：models 用 l1，
// count_tokens 用 count_tokens，模型端点用 l2_standard。两处不一致的话，
// profile 层解析出的配方会在校验时被拒 —— 而那时错误指向的是超时档，
// 不是真正的原因。
func defaultTimeoutProfile(endpoint model.EndpointKind) model.ProbeTimeoutProfile {
	switch endpoint {
	case model.EndpointModels:
		return model.TimeoutL1
	case model.EndpointCountTokens:
		return model.TimeoutCountTokens
	default:
		return model.TimeoutL2Standard
	}
}
