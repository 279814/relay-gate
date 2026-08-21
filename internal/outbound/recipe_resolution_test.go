// Recipe 四级解析对着**真实数据库**的端到端验收（P0-05 第 11 条）。
//
// 为什么要这一份而不是只有 probe 包里的假实现测试：那边验的是「优先级与
// BindingFacts 怎么填」，用假 source 精确控制每一级的有无。而这里验的是
// 另一件事 —— 解析器对 store 的**语义假设**是否成立：
//
//   - store 用什么错误表达「这一级没有」（notFound 判据靠它）
//   - draft / disabled / archived 的 recipe 会不会被 published 查询看到
//   - 发布之后 ActiveBindingRevision 是不是解析器记进 facts 的那个值
//   - Secret 快照读出来的是绑定时的 ID，而不是现在按名字查到的
//
// 这几条都只能对着真库验。假实现里它们是我写的假设，而假设写错时
// 两边会一起错成一样。
//
// 放在外部测试包是为了同时 import probe 与 store 而不成环。
package outbound_test

import (
	"context"
	"errors"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probe"
	"github.com/279814/relay-gate/internal/probetemplate"
	"github.com/279814/relay-gate/internal/store"
)

// recipeStoreFixture 是一个真库 + 一个站 + 一条 Route。
type recipeStoreFixture struct {
	store    *store.Store
	upstream *model.Upstream
	routeID  int64
}

func newRecipeStoreFixture(t *testing.T) *recipeStoreFixture {
	t.Helper()

	cipher, err := store.NewCipher("recipe-resolution-test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	opened, err := store.Open(t.TempDir()+"/recipe.db", cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })

	upstream := &model.Upstream{
		Name: "recipe-site", BaseURL: "https://example.invalid",
		APIKey: "sk-upstream-value", AuthStyle: model.AuthXAPIKey, Enabled: true,
	}
	if err := opened.CreateUpstream(upstream); err != nil {
		t.Fatal(err)
	}
	modelName := &model.ModelName{
		Name: "claude-opus-5", Protocol: model.ProtoAnthropic,
		MatchMode: model.MatchExact, Enabled: true,
	}
	modelName.Defaults()
	if err := opened.CreateModelName(modelName); err != nil {
		t.Fatal(err)
	}
	route := &model.Route{
		ModelNameID: modelName.ID, UpstreamID: upstream.ID,
		Priority: 1, Weight: 100, Enabled: true,
	}
	if err := opened.CreateRoute(route); err != nil {
		t.Fatal(err)
	}
	return &recipeStoreFixture{store: opened, upstream: upstream, routeID: route.ID}
}

func (fixture *recipeStoreFixture) resolver() *probe.RecipeResolver {
	// 与 main 装配时同一个判据：store.ErrNotFound 表示「这一级没有」。
	return probe.NewRecipeResolver(fixture.store).WithNotFound(func(err error) bool {
		return errors.Is(err, store.ErrNotFound)
	})
}

// publishRecipe 建一个 recipe、加一个 version、并发布它。
func (fixture *recipeStoreFixture) publishRecipe(t *testing.T, scope model.RecipeScope,
	scopeID int64, headers []model.HeaderTemplate) (recipeID, versionID int64) {

	t.Helper()
	ctx := context.Background()

	recipeID, err := fixture.store.CreateRecipe(scope, scopeID, model.EndpointModels)
	if err != nil {
		t.Fatal(err)
	}
	version := &model.ProbeRecipeVersion{
		RecipeID: recipeID, Origin: model.RecipeManual, Method: "GET",
		Headers: headers, TimeoutProfile: model.TimeoutL1,
	}
	if err := fixture.store.AddRecipeVersion(version, 1); err != nil {
		t.Fatal(err)
	}
	recipe, err := fixture.store.GetRecipe(ctx, recipeID)
	if err != nil {
		t.Fatal(err)
	}

	// Route 作用域的发布要求 execution 带上同一个 RouteID —— 那是发布门禁
	// 的「同 target」检查（store.requireRecipeTestExecution）。
	routeID := int64(0)
	if scope == model.RecipeScopeRoute {
		routeID = scopeID
	}
	execution := fixture.testExecution(t, recipeID, version.ID, routeID)
	if err := fixture.store.InsertProbeExecution(ctx, &execution); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.PublishRecipeVersion(recipeID, version.ID,
		execution.ID, recipe.Revision, false); err != nil {
		t.Fatal(err)
	}
	return recipeID, version.ID
}

// testExecution 造一条能通过发布门禁的显式测试记录。
//
// routeID 为 0 表示 Upstream 作用域。Route 作用域必须带上它，否则
// 发布门禁会以「测的 Route 与 recipe scope 不一致」拒绝 —— 那条检查
// 正是防止「拿 A Route 的测试结果去发布 B Route 的配方」。
func (fixture *recipeStoreFixture) testExecution(t *testing.T,
	recipeID, versionID, routeID int64) model.ProbeExecution {

	t.Helper()
	page, err := fixture.store.ListEndpointsPage(context.Background(), model.EndpointFilter{
		UpstreamID: fixture.upstream.ID, Endpoint: model.EndpointModels,
	})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("models endpoint = %+v err=%v", page, err)
	}
	endpoint := page.Items[0]
	order := fixture.nextOrder(t)
	return model.ProbeExecution{
		ID:                         "exec-models-" + itoa(versionID),
		Trigger:                    model.TriggerManual,
		UpstreamID:                 fixture.upstream.ID,
		UpstreamNetworkRevision:    fixture.upstream.NetworkRevision,
		UpstreamCredentialRevision: fixture.upstream.CredentialRevision,
		EndpointID:                 endpoint.ID, EndpointRevision: endpoint.Revision,
		AuthProfileRevision: endpoint.AuthProfile.Revision,
		Endpoint:            model.EndpointModels,
		RouteID:             routeID,
		RecipeBindingUse:    model.BindingExplicitTest,
		RecipeStorage:       model.RecipeStorageDB,
		RecipeOrigin:        model.RecipeManual,
		RecipeID:            recipeID, RecipeVersionID: versionID,
		EvidenceHash: "evidence-" + itoa(versionID),
		ErrorClass:   model.ErrorNone,
		Capability:   model.CapabilityUnknown,
		Scope:        model.ScopeUpstreamEndpoint,
		Reachable:    true, Final: true, Success: true,
		ObservationOrder: order, SentAtMS: order, DoneAtMS: order + 1,
	}
}

func (fixture *recipeStoreFixture) nextOrder(t *testing.T) int64 {
	t.Helper()
	start, _, err := fixture.store.ReserveObservationOrders(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	return start
}

func itoa(value int64) string {
	if value == 0 {
		return "0"
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}

// Route published 胜过 Upstream published —— 对着真库。
func TestRecipeResolutionPrefersRoutePublishedInRealStore(t *testing.T) {
	fixture := newRecipeStoreFixture(t)

	_, upstreamVersionID := fixture.publishRecipe(t, model.RecipeScopeUpstream,
		fixture.upstream.ID, []model.HeaderTemplate{{Name: "X-Layer", Values: []string{"upstream"}}})
	routeRecipeID, routeVersionID := fixture.publishRecipe(t, model.RecipeScopeRoute,
		fixture.routeID, []model.HeaderTemplate{{Name: "X-Layer", Values: []string{"route"}}})

	resolved, err := fixture.resolver().Resolve(context.Background(), probe.RecipeQuery{
		UpstreamID: fixture.upstream.ID, RouteID: fixture.routeID,
		Endpoint: model.EndpointModels,
	})
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if resolved.Layer != model.ResolvedRoute {
		t.Errorf("layer want route got %q", resolved.Layer)
	}
	if resolved.Identity.DBVersionID != routeVersionID {
		t.Errorf("应选 Route 的 version %d，得到 %d", routeVersionID, resolved.Identity.DBVersionID)
	}
	if resolved.Identity.DBVersionID == upstreamVersionID {
		t.Error("选中了被遮蔽的 Upstream 版本")
	}

	// ActiveBindingRevision 必须是库里那个真实值，不是我猜的常量。
	recipe, err := fixture.store.GetRecipe(context.Background(), routeRecipeID)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Facts.RouteBindingRevision != recipe.ActiveBindingRevision {
		t.Errorf("facts 里的 binding revision = %d，库里是 %d",
			resolved.Facts.RouteBindingRevision, recipe.ActiveBindingRevision)
	}
	// 被遮蔽的 Upstream 层必须全零（§计划 1436 行）。
	if resolved.Facts.UpstreamRecipeID != 0 || resolved.Facts.UpstreamPublishedVersionID != 0 {
		t.Errorf("被遮蔽的 Upstream binding 不该进 facts，得到 %+v", resolved.Facts)
	}
}

// 没有任何 recipe 时落到内置模板 —— 也就是 store.ErrNotFound 判据成立。
//
// 这条钉的是 notFound 判据本身：判据写错的话，解析会把「这一级没有」
// 当成「读库出错」并直接返回错误，于是**永远落不到低优先级**。
// 那种 bug 在假实现里看不见。
//
// 断言落到 embedded 而不是断言 ErrNoRecipe：第 4 级接上之后，「三级全无」
// 的正确结果就是内置模板。仍然是同一条判据 —— 判据坏了会在这里变成一个
// 包了 store 错误的 error，而不是 embedded。
func TestRecipeResolutionFallsBackToBuiltinOnEmptyStore(t *testing.T) {
	fixture := newRecipeStoreFixture(t)

	resolved, err := fixture.resolver().Resolve(context.Background(), probe.RecipeQuery{
		UpstreamID: fixture.upstream.ID, RouteID: fixture.routeID,
		Endpoint: model.EndpointModels,
	})
	if err != nil {
		t.Fatalf("空库应落到内置模板（notFound 判据成立的证据），得到 %v", err)
	}
	if resolved.Layer != model.ResolvedEmbedded {
		t.Errorf("layer want embedded got %q", resolved.Layer)
	}
	if resolved.Identity.Storage != model.RecipeStorageEmbedded || resolved.Identity.TemplateID == "" {
		t.Errorf("identity 应自述来自内置模板，得到 %+v", resolved.Identity)
	}
}

// draft 不参与解析 —— 对着真库确认 publishedBinding 的 status 过滤。
//
// 断言落到内置层：draft 被误当成 published 的话，选中的会是那份 draft
// （storage=db），而那是这条要挡的事。
func TestRecipeResolutionIgnoresDraftInRealStore(t *testing.T) {
	fixture := newRecipeStoreFixture(t)

	// 只建 draft，不发布。
	recipeID, err := fixture.store.CreateRecipe(model.RecipeScopeRoute,
		fixture.routeID, model.EndpointModels)
	if err != nil {
		t.Fatal(err)
	}
	version := &model.ProbeRecipeVersion{
		RecipeID: recipeID, Origin: model.RecipeManual, Method: "GET",
		TimeoutProfile: model.TimeoutL1,
	}
	if err := fixture.store.AddRecipeVersion(version, 1); err != nil {
		t.Fatal(err)
	}

	resolved, err := fixture.resolver().Resolve(context.Background(), probe.RecipeQuery{
		UpstreamID: fixture.upstream.ID, RouteID: fixture.routeID,
		Endpoint: model.EndpointModels,
	})
	if err != nil {
		t.Fatalf("只有 draft 时应落到内置模板，得到 %v", err)
	}
	if resolved.Layer != model.ResolvedEmbedded {
		t.Errorf("draft 不该参与解析，实际选中了 %s 层（version=%d）",
			resolved.Layer, resolved.Identity.DBVersionID)
	}
	if resolved.Identity.DBVersionID == version.ID {
		t.Error("选中了未发布的 draft version")
	}
}

// archive 之后解析立刻忽略它，并落到下一级。
func TestRecipeResolutionFallsBackAfterArchive(t *testing.T) {
	fixture := newRecipeStoreFixture(t)
	ctx := context.Background()

	_, upstreamVersionID := fixture.publishRecipe(t, model.RecipeScopeUpstream,
		fixture.upstream.ID, []model.HeaderTemplate{{Name: "X-Layer", Values: []string{"upstream"}}})
	routeRecipeID, _ := fixture.publishRecipe(t, model.RecipeScopeRoute,
		fixture.routeID, []model.HeaderTemplate{{Name: "X-Layer", Values: []string{"route"}}})

	recipe, err := fixture.store.GetRecipe(ctx, routeRecipeID)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.ArchiveRecipe(ctx, routeRecipeID, recipe.Revision); err != nil {
		t.Fatal(err)
	}

	resolved, err := fixture.resolver().Resolve(ctx, probe.RecipeQuery{
		UpstreamID: fixture.upstream.ID, RouteID: fixture.routeID,
		Endpoint: model.EndpointModels,
	})
	if err != nil {
		t.Fatalf("archive 之后应落到 Upstream 级: %v", err)
	}
	if resolved.Layer != model.ResolvedUpstream {
		t.Errorf("layer want upstream got %q", resolved.Layer)
	}
	if resolved.Identity.DBVersionID != upstreamVersionID {
		t.Errorf("应选 Upstream 的 version %d，得到 %d",
			upstreamVersionID, resolved.Identity.DBVersionID)
	}
}

// Secret 快照读出来的是**绑定时**的 ID。
//
// 这条与 BindSecrets 合起来构成那道安全边界：删掉 Secret 再建同名的会拿到
// 新 ID，而解析给出的 ref 仍是旧 ID —— 于是渲染前的校验会拒绝，
// 而不是静默改用一份没为这个 recipe 审核过的凭据。
func TestRecipeResolutionCarriesBoundSecretSnapshot(t *testing.T) {
	fixture := newRecipeStoreFixture(t)

	secret, err := fixture.store.CreateProbeSecret("tenant_key", []byte("tenant-secret-value"))
	if err != nil {
		t.Fatal(err)
	}
	_, versionID := fixture.publishRecipe(t, model.RecipeScopeRoute, fixture.routeID,
		[]model.HeaderTemplate{{Name: "X-Tenant", Values: []string{"{{SECRET:tenant_key}}"}}})

	resolved, err := fixture.resolver().Resolve(context.Background(), probe.RecipeQuery{
		UpstreamID: fixture.upstream.ID, RouteID: fixture.routeID,
		Endpoint: model.EndpointModels,
	})
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(resolved.SecretRefs) != 1 {
		t.Fatalf("应带一条 Secret 引用，得到 %+v", resolved.SecretRefs)
	}
	if resolved.SecretRefs[0].Name != "tenant_key" ||
		resolved.SecretRefs[0].BoundSecretID != secret.ID {
		t.Errorf("ref = %+v，want tenant_key@%d", resolved.SecretRefs[0], secret.ID)
	}
	// 编译结果也要认得这个 Secret，否则 BindSecrets 会因「多余」而拒绝。
	if got := resolved.Compiled.RequiredSecrets(); len(got) != 1 || got[0] != "tenant_key" {
		t.Errorf("compiled required secrets = %v", got)
	}
	_ = versionID
}

// 解析 + BindSecrets 端到端：同名新建的 Secret 不满足旧引用。
//
// 这条把 P0-05 的两半接起来验：解析给出的是**绑定时**的 secret_id，
// 而 BindSecrets 拿它与当下解析出的 Secret 比对。删掉再建同名的会拿到新 ID，
// 于是渲染前就被拒 —— 而不是静默改用一份没为这个 recipe 审核过的凭据。
func TestRecipeResolutionRejectsRecreatedSecretByName(t *testing.T) {
	fixture := newRecipeStoreFixture(t)
	ctx := context.Background()

	secret, err := fixture.store.CreateProbeSecret("rotating", []byte("first-value"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.publishRecipe(t, model.RecipeScopeRoute, fixture.routeID,
		[]model.HeaderTemplate{{Name: "X-Rot", Values: []string{"{{SECRET:rotating}}"}}})

	resolved, err := fixture.resolver().Resolve(ctx, probe.RecipeQuery{
		UpstreamID: fixture.upstream.ID, RouteID: fixture.routeID,
		Endpoint: model.EndpointModels,
	})
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	// 先确认正常情形能通过，否则下面的「拒绝」证明不了是 ID 比对起了作用。
	current, err := fixture.store.ResolveProbeSecret(ctx, "rotating")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probe.BindSecrets(resolved.SecretRefs,
		map[string]probetemplate.ResolvedSecret{"rotating": current}); err != nil {
		t.Fatalf("当前 Secret 应能满足引用: %v", err)
	}

	// 「删掉再建同名」会拿到不同的 ID。published 引用挡住了真的删除
	// （见 store 侧的 active ref 测试），所以这里直接构造重建后的形态。
	recreated := probetemplate.ResolvedSecret{
		ID: secret.ID + 1000, Plain: []byte("second-value"), Revision: 1,
	}
	if _, err := probe.BindSecrets(resolved.SecretRefs,
		map[string]probetemplate.ResolvedSecret{"rotating": recreated}); err == nil {
		t.Error("同名但 secret_id 不同必须拒绝：那份凭据没有被这个 recipe 审核过")
	}
}
