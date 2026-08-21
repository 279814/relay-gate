package probe

// Recipe 四级解析（§8.2、计划第 11 条）。
//
// 优先级：Route published → Upstream published → 已测试 learned profile →
// 内置模板。前三级来自数据库，第四级属 P0-06。

import (
	"context"
	"errors"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

// *store.Store 必须满足 RecipeSource。
//
// 编译期断言，为的是让「改了 store 的方法签名而忘了这边」立刻编译失败，
// 而不是等到 main 装配时才发现。
//
// 断言放在 probe 侧而不是 store 侧：probe 已经 import store
// （scheduler.go 用 store.RunState），反向 import 会成环 —— 连测试文件
// 也不行，Go 的 import cycle 检查覆盖测试包。
var _ RecipeSource = (*store.Store)(nil)

// fakeRecipeSource 是可控的四级来源。
//
// 用假实现而不是真 Store：这里要验的是「优先级与 BindingFacts 怎么填」，
// 而那需要精确控制「哪一级有、哪一级没有」的全部组合 —— 用真库造这些组合
// 要写一堆发布流程，而发布本身有自己的测试。
type fakeRecipeSource struct {
	routeBinding    *model.PublishedRecipeBinding
	upstreamBinding *model.PublishedRecipeBinding
	profile         *model.ClientProbeProfile
	refs            map[int64][]model.RequiredSecretRef

	// 记录实际查了哪几级，用于断言「命中高优先级就不查低的」。
	queried []string
}

func (source *fakeRecipeSource) PublishedRouteRecipe(_ context.Context, _ int64,
	_ model.EndpointKind) (*model.PublishedRecipeBinding, error) {

	source.queried = append(source.queried, "route")
	if source.routeBinding == nil {
		return nil, errTestNotFound
	}
	return source.routeBinding, nil
}

func (source *fakeRecipeSource) PublishedUpstreamRecipe(_ context.Context, _ int64,
	_ model.EndpointKind) (*model.PublishedRecipeBinding, error) {

	source.queried = append(source.queried, "upstream")
	if source.upstreamBinding == nil {
		return nil, errTestNotFound
	}
	return source.upstreamBinding, nil
}

func (source *fakeRecipeSource) TestedClientProfile(_ context.Context, _ int64,
	_ model.EndpointKind) (*model.ClientProbeProfile, error) {

	source.queried = append(source.queried, "profile")
	if source.profile == nil {
		return nil, errTestNotFound
	}
	return source.profile, nil
}

func (source *fakeRecipeSource) RecipeVersionSecretRefs(_ context.Context,
	versionID int64) ([]model.RequiredSecretRef, error) {

	return source.refs[versionID], nil
}

// errTestNotFound 模拟 store.ErrNotFound。
//
// 不 import store：probe 已经依赖它会成环（store 侧要用 probe 的 reducer）。
// Resolver 靠 RecipeNotFound 判据识别「这一级没有」，见它的说明。
var errTestNotFound = errors.New("not found")

func testBinding(recipeID, versionID int64, bindingRevision int64,
	method string) *model.PublishedRecipeBinding {

	return &model.PublishedRecipeBinding{
		Recipe: model.ProbeRecipe{
			ID: recipeID, Status: model.RecipePublished,
			PublishedVersionID: versionID, ActiveBindingRevision: bindingRevision,
			Endpoint: model.EndpointModels,
		},
		Version: model.ProbeRecipeVersion{
			ID: versionID, RecipeID: recipeID, Version: 1,
			Origin: model.RecipeManual, Method: method,
			TimeoutProfile: model.TimeoutL1,
		},
	}
}

func testResolver(source *fakeRecipeSource) *RecipeResolver {
	return NewRecipeResolver(source).WithNotFound(func(err error) bool {
		return errors.Is(err, errTestNotFound)
	})
}

// Route published 胜过其余三级。
func TestRecipeResolver_RoutePublishedWins(t *testing.T) {
	source := &fakeRecipeSource{
		routeBinding:    testBinding(7, 70, 3, "GET"),
		upstreamBinding: testBinding(8, 80, 4, "HEAD"),
		profile:         &model.ClientProbeProfile{ID: 9, Revision: 5, Status: model.ProfileTested},
	}

	resolved, err := testResolver(source).Resolve(context.Background(), RecipeQuery{
		UpstreamID: 1, RouteID: 2, Endpoint: model.EndpointModels,
	})
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if resolved.Layer != model.ResolvedRoute {
		t.Errorf("layer want route got %q", resolved.Layer)
	}
	if resolved.Identity.DBVersionID != 70 {
		t.Errorf("应用 Route 的 version 70，得到 %d", resolved.Identity.DBVersionID)
	}
	// 命中 Route 就不该再查下面两级：那是白做的库查询，而且
	// 「查过」会诱使将来有人把低优先级的信息也记进 BindingFacts。
	if len(source.queried) != 1 || source.queried[0] != "route" {
		t.Errorf("命中 Route 后不该再查低优先级，实际查了 %v", source.queried)
	}
}

// Route 缺失时落到 Upstream published。
func TestRecipeResolver_FallsBackToUpstreamPublished(t *testing.T) {
	source := &fakeRecipeSource{
		upstreamBinding: testBinding(8, 80, 4, "HEAD"),
		profile:         &model.ClientProbeProfile{ID: 9, Revision: 5, Status: model.ProfileTested},
	}

	resolved, err := testResolver(source).Resolve(context.Background(), RecipeQuery{
		UpstreamID: 1, RouteID: 2, Endpoint: model.EndpointModels,
	})
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if resolved.Layer != model.ResolvedUpstream {
		t.Errorf("layer want upstream got %q", resolved.Layer)
	}
	if resolved.Identity.DBVersionID != 80 {
		t.Errorf("应用 Upstream 的 version 80，得到 %d", resolved.Identity.DBVersionID)
	}
}

// 两级 published 都缺时落到已测试的 learned profile。
func TestRecipeResolver_FallsBackToTestedProfile(t *testing.T) {
	source := &fakeRecipeSource{
		profile: &model.ClientProbeProfile{
			ID: 9, Revision: 5, Status: model.ProfileTested,
			Endpoint: model.EndpointModels,
			SafeHeaders: []model.HeaderTemplate{
				{Name: "X-Learned", Values: []string{"v"}},
			},
		},
	}

	resolved, err := testResolver(source).Resolve(context.Background(), RecipeQuery{
		UpstreamID: 1, RouteID: 2, Endpoint: model.EndpointModels,
	})
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if resolved.Layer != model.ResolvedProfile {
		t.Errorf("layer want profile got %q", resolved.Layer)
	}
	if resolved.Identity.Storage != model.RecipeStorageProfile {
		t.Errorf("storage want profile got %q", resolved.Identity.Storage)
	}
	if resolved.Identity.ClientProfileID != 9 || resolved.Identity.Revision != 5 {
		t.Errorf("profile identity = %d@%d，want 9@5",
			resolved.Identity.ClientProfileID, resolved.Identity.Revision)
	}
	// profile 的 identity 判别要求 DBVersionID 为 0（model.RecipeIdentity.Validate）。
	if err := resolved.Identity.Validate(); err != nil {
		t.Errorf("identity 不合法: %v", err)
	}
}

// 四级全无时返回 ErrNoRecipe，供调用方走内置模板（P0-06）。
//
// 不在这里造一个内置模板：那会让「内置模板长什么样」有两份定义，
// 而 P0-06 的 manifest 才是唯一来源。
func TestRecipeResolver_ReturnsErrNoRecipeWhenAllLayersAbsent(t *testing.T) {
	source := &fakeRecipeSource{}

	_, err := testResolver(source).Resolve(context.Background(), RecipeQuery{
		UpstreamID: 1, RouteID: 2, Endpoint: model.EndpointModels,
	})
	if !errors.Is(err, ErrNoRecipe) {
		t.Fatalf("四级全无时应回 ErrNoRecipe（调用方据此走内置模板），得到 %v", err)
	}
	// 三级都要查过才能断定「全无」。
	want := []string{"route", "upstream", "profile"}
	if len(source.queried) != 3 {
		t.Errorf("应依次查完三级，实际 %v（want %v）", source.queried, want)
	}
}

// BindingFacts 只编码**实际影响选择**的层（§计划 1436 行）。
//
// 这条是本文件最要紧的一条。规格原文：「被更高层遮蔽的低优先级 binding
// 完全忽略，因此编辑它不会误使当前 Capability stale；高优先级 absence
// 则是受验证的事实，新 publish 会让旧 fallback 立即 stale。」
//
// 也就是说命中 Upstream 时，Route 的 binding 字段必须是零 —— 不是「记下来
// 备查」。记了的话，改一个被遮蔽的 Route draft 就会让这个站的 Capability
// 失效并重探，而那次重探的结果与改动无关。
func TestRecipeResolver_BindingFactsOnlyEncodeDecidingLayers(t *testing.T) {
	t.Run("命中 Route", func(t *testing.T) {
		source := &fakeRecipeSource{
			routeBinding:    testBinding(7, 70, 3, "GET"),
			upstreamBinding: testBinding(8, 80, 4, "HEAD"),
		}
		resolved, err := testResolver(source).Resolve(context.Background(), RecipeQuery{
			UpstreamID: 1, RouteID: 2, Endpoint: model.EndpointModels,
		})
		if err != nil {
			t.Fatal(err)
		}
		facts := resolved.Facts
		if facts.RouteRecipeID != 7 || facts.RoutePublishedVersionID != 70 || facts.RouteBindingRevision != 3 {
			t.Errorf("Route 层应完整记录，得到 %+v", facts)
		}
		// Upstream 层被遮蔽，必须全零。
		if facts.UpstreamRecipeID != 0 || facts.UpstreamPublishedVersionID != 0 ||
			facts.UpstreamBindingRevision != 0 {
			t.Errorf("被遮蔽的 Upstream binding 不该进 facts（否则编辑它会误使 "+
				"Capability stale），得到 %+v", facts)
		}
		if facts.TestedProfileID != 0 {
			t.Errorf("被遮蔽的 profile 不该进 facts，得到 %d", facts.TestedProfileID)
		}
	})

	t.Run("命中 Upstream", func(t *testing.T) {
		source := &fakeRecipeSource{
			upstreamBinding: testBinding(8, 80, 4, "HEAD"),
			profile:         &model.ClientProbeProfile{ID: 9, Revision: 5, Status: model.ProfileTested},
		}
		resolved, err := testResolver(source).Resolve(context.Background(), RecipeQuery{
			UpstreamID: 1, RouteID: 2, Endpoint: model.EndpointModels,
		})
		if err != nil {
			t.Fatal(err)
		}
		facts := resolved.Facts
		// Route absence 是「受验证的事实」：它必须以零值表达，而 ResolvedLayer
		// 说明这个零值意味着「查过、不存在」而不是「没查」。
		if facts.RouteRecipeID != 0 || facts.RoutePublishedVersionID != 0 {
			t.Errorf("Route 不存在时该层必须为零，得到 %+v", facts)
		}
		if facts.UpstreamRecipeID != 8 || facts.UpstreamPublishedVersionID != 80 ||
			facts.UpstreamBindingRevision != 4 {
			t.Errorf("Upstream 层应完整记录，得到 %+v", facts)
		}
		if facts.TestedProfileID != 0 {
			t.Errorf("被遮蔽的 profile 不该进 facts，得到 %d", facts.TestedProfileID)
		}
	})

	t.Run("命中 profile", func(t *testing.T) {
		source := &fakeRecipeSource{
			profile: &model.ClientProbeProfile{ID: 9, Revision: 5, Status: model.ProfileTested},
		}
		resolved, err := testResolver(source).Resolve(context.Background(), RecipeQuery{
			UpstreamID: 1, RouteID: 2, Endpoint: model.EndpointModels,
		})
		if err != nil {
			t.Fatal(err)
		}
		facts := resolved.Facts
		if facts.RouteRecipeID != 0 || facts.UpstreamRecipeID != 0 {
			t.Errorf("两级 published 不存在时都必须为零，得到 %+v", facts)
		}
		if facts.TestedProfileID != 9 || facts.TestedProfileRevision != 5 {
			t.Errorf("profile 层应完整记录，得到 %+v", facts)
		}
	})
}

// Use 与 ResolvedLayer 都要填。
//
// resolved 模式必须填 ResolvedLayer（规格明文）。少了它，Store 侧
// 无法按层重读并比较 facts —— 它不知道该比哪几个字段。
func TestRecipeResolver_SetsBindingUseAndLayer(t *testing.T) {
	source := &fakeRecipeSource{routeBinding: testBinding(7, 70, 3, "GET")}

	resolved, err := testResolver(source).Resolve(context.Background(), RecipeQuery{
		UpstreamID: 1, RouteID: 2, Endpoint: model.EndpointModels,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Facts.Use != model.BindingResolved {
		t.Errorf("use want resolved got %q", resolved.Facts.Use)
	}
	if resolved.Facts.ResolvedLayer != model.ResolvedRoute {
		t.Errorf("facts.ResolvedLayer 必须与 Layer 一致，得到 %q", resolved.Facts.ResolvedLayer)
	}
}

// 解析出的 Recipe 必须已编译好，且带上它需要的 Secret 引用。
//
// 编译在解析时做而不是留给调用方：一个编译不过的 published recipe 应该
// 在解析阶段就报错，而不是等到发请求前 —— 后者会让 config_error 的归因
// 落在探活执行上，而真正的问题在那份配置里。
func TestRecipeResolver_ReturnsCompiledRecipeWithSecretRefs(t *testing.T) {
	binding := testBinding(7, 70, 3, "GET")
	binding.Version.Headers = []model.HeaderTemplate{
		{Name: "X-Custom", Values: []string{"{{SECRET:tenant}}"}},
	}
	source := &fakeRecipeSource{
		routeBinding: binding,
		refs: map[int64][]model.RequiredSecretRef{
			70: {{Name: "tenant", BoundSecretID: 11}},
		},
	}

	resolved, err := testResolver(source).Resolve(context.Background(), RecipeQuery{
		UpstreamID: 1, RouteID: 2, Endpoint: model.EndpointModels,
	})
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if resolved.Compiled == nil {
		t.Fatal("应返回已编译的 recipe")
	}
	if got := resolved.Compiled.RequiredSecrets(); len(got) != 1 || got[0] != "tenant" {
		t.Errorf("required secrets = %v", got)
	}
	if len(resolved.SecretRefs) != 1 || resolved.SecretRefs[0].BoundSecretID != 11 {
		t.Errorf("应带上 snapshot ref（BindSecrets 要用），得到 %+v", resolved.SecretRefs)
	}
}

// 编译不过的 published recipe 在解析阶段就要失败。
func TestRecipeResolver_FailsOnUncompilableBinding(t *testing.T) {
	binding := testBinding(7, 70, 3, "GET")
	// models endpoint 的 GET 不能带 body —— ValidateForEndpoint 会拒。
	binding.Version.Body = []byte("x")
	source := &fakeRecipeSource{routeBinding: binding}

	if _, err := testResolver(source).Resolve(context.Background(), RecipeQuery{
		UpstreamID: 1, RouteID: 2, Endpoint: model.EndpointModels,
	}); err == nil {
		t.Fatal("编译不过的 published recipe 必须在解析阶段报错")
	} else if errors.Is(err, ErrNoRecipe) {
		t.Error("编译失败不能报成 ErrNoRecipe —— 那会让调用方静默改用内置模板，" +
			"而用户配的那份 recipe 其实是坏的，没有任何提示")
	}
}

// RouteID 为 0 时跳过 Route 级，不当成错误。
//
// Upstream 作用域的探活（L1 打 /v1/models）没有 Route 上下文，
// 而那是完全正常的调用。
func TestRecipeResolver_SkipsRouteLayerWithoutRouteID(t *testing.T) {
	source := &fakeRecipeSource{upstreamBinding: testBinding(8, 80, 4, "GET")}

	resolved, err := testResolver(source).Resolve(context.Background(), RecipeQuery{
		UpstreamID: 1, Endpoint: model.EndpointModels,
	})
	if err != nil {
		t.Fatalf("无 RouteID 应正常落到 Upstream 级: %v", err)
	}
	if resolved.Layer != model.ResolvedUpstream {
		t.Errorf("layer want upstream got %q", resolved.Layer)
	}
	for _, queried := range source.queried {
		if queried == "route" {
			t.Error("没有 RouteID 时不该查 Route 级")
		}
	}
}

// 非 tested 的 profile 不参与解析。
//
// candidate 是学习器刚生成、还没经过一次测试的形状。拿它去探活等于用一份
// 没人验证过的请求形状判断站点健康 —— 而 §8.4 明确要求「经脱敏差异预览和
// 一次测试后才能用于自动探活」。
func TestRecipeResolver_IgnoresUntestedProfile(t *testing.T) {
	for _, status := range []model.ProbeProfileStatus{model.ProfileCandidate, model.ProfileDisabled} {
		t.Run(string(status), func(t *testing.T) {
			source := &fakeRecipeSource{
				profile: &model.ClientProbeProfile{ID: 9, Revision: 5, Status: status},
			}
			_, err := testResolver(source).Resolve(context.Background(), RecipeQuery{
				UpstreamID: 1, RouteID: 2, Endpoint: model.EndpointModels,
			})
			if !errors.Is(err, ErrNoRecipe) {
				t.Errorf("status=%s 的 profile 不该参与解析，得到 %v", status, err)
			}
		})
	}
}

// profile 层不接受 Secret 占位符。
//
// profile 层不带 SecretRefs（learner 学的是安全头，认证由 Endpoint 的
// auth profile 提供，§7.2）。若它的 shape 里混进 {{SECRET:x}}，编译结果会
// 要求那个 Secret，而 SecretRefs 是 nil —— 于是 BindSecrets 收不到任何 ref
// 可校验，那个 Secret 就绕过了 §4.5 的「同名新建不满足旧引用」这道边界。
//
// 症状还会往后拖：解析成功、渲染时才以「未装配」失败，而那时归因落在探活
// 执行上，不在这份 profile 上。所以在解析阶段就拒。
func TestRecipeResolver_RejectsSecretPlaceholderInProfile(t *testing.T) {
	source := &fakeRecipeSource{
		profile: &model.ClientProbeProfile{
			ID: 9, Revision: 5, Status: model.ProfileTested,
			Endpoint: model.EndpointModels,
			SafeHeaders: []model.HeaderTemplate{
				{Name: "X-Tenant", Values: []string{"{{SECRET:sneaky}}"}},
			},
		},
	}

	_, err := testResolver(source).Resolve(context.Background(), RecipeQuery{
		UpstreamID: 1, Endpoint: model.EndpointModels,
	})
	if err == nil {
		t.Fatal("引用 Secret 的 profile 必须在解析阶段拒绝：" +
			"profile 层不带 SecretRefs，BindSecrets 无从校验那个引用")
	}
	if errors.Is(err, ErrNoRecipe) {
		t.Error("不能报成 ErrNoRecipe —— 那会让调用方静默改用内置模板，" +
			"而这份 profile 里的问题没有任何提示")
	}
}

// 查询参数不合法时报错，不静默落到低优先级。
func TestRecipeResolver_RejectsInvalidQuery(t *testing.T) {
	cases := []struct {
		name  string
		query RecipeQuery
	}{
		{"无 UpstreamID", RecipeQuery{Endpoint: model.EndpointModels}},
		{"endpoint 无效", RecipeQuery{UpstreamID: 1, Endpoint: model.EndpointKind("nope")}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			source := &fakeRecipeSource{}
			if _, err := testResolver(source).Resolve(context.Background(), testCase.query); err == nil {
				t.Error("不合法的查询必须报错")
			} else if errors.Is(err, ErrNoRecipe) {
				t.Error("参数错误不能报成 ErrNoRecipe —— 那会静默改用内置模板")
			}
			if len(source.queried) != 0 {
				t.Errorf("参数不合法时不该查库，实际 %v", source.queried)
			}
		})
	}
}
