package store

// Recipe 发布的仓储测试。核心是「陈旧绿灯不能推配置上线」：
// 发布必须凭一次身份完全对得上、且当时配置仍然有效的显式测试。

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

// mkDraftRecipe 建一个 upstream 作用域的 models recipe 并加一个 draft version。
func mkDraftRecipe(t *testing.T, store *Store, upstream *model.Upstream) (recipeID int64, version *model.ProbeRecipeVersion) {
	t.Helper()
	recipeID, err := store.CreateRecipe(model.RecipeScopeUpstream, upstream.ID, model.EndpointModels)
	if err != nil {
		t.Fatal(err)
	}
	version = &model.ProbeRecipeVersion{
		RecipeID: recipeID, Origin: model.RecipeManual, Method: "GET",
		TimeoutProfile: model.TimeoutL1,
	}
	if err := store.AddRecipeVersion(version, 1); err != nil {
		t.Fatal(err)
	}
	return recipeID, version
}

// recipeTestExecution 造一条针对该 recipe version 的显式测试 execution。
func recipeTestExecution(t *testing.T, store *Store, upstream *model.Upstream, recipeID, versionID int64, id string) model.ProbeExecution {
	t.Helper()
	page, err := store.ListEndpointsPage(context.Background(), model.EndpointFilter{
		UpstreamID: upstream.ID, Endpoint: model.EndpointModels,
	})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("models endpoint = %+v err=%v", page, err)
	}
	endpoint := page.Items[0]
	order := nextTestObservationOrder(t, store)
	return model.ProbeExecution{
		ID: id, Trigger: model.TriggerManual, UpstreamID: upstream.ID,
		UpstreamNetworkRevision:    upstream.NetworkRevision,
		UpstreamCredentialRevision: upstream.CredentialRevision,
		EndpointID:                 endpoint.ID, EndpointRevision: endpoint.Revision,
		AuthProfileRevision: endpoint.AuthProfile.Revision,
		Endpoint:            model.EndpointModels,
		RecipeBindingUse:    model.BindingExplicitTest,
		RecipeStorage:       model.RecipeStorageDB,
		RecipeOrigin:        model.RecipeManual,
		RecipeID:            recipeID, RecipeVersionID: versionID,
		EvidenceHash: "evidence-" + id,
		ErrorClass:   model.ErrorNone,
		Capability:   model.CapabilityUnknown,
		Scope:        model.ScopeUpstreamEndpoint,
		Reachable:    true, Final: true, Success: true,
		ObservationOrder: order, SentAtMS: order, DoneAtMS: order + 1,
	}
}

func TestPublishRecipeVersionRequiresMatchingExplicitTest(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	upstream := mkUpstream(t, store, "publish-site")
	recipeID, version := mkDraftRecipe(t, store, upstream)
	// AddRecipeVersion 已把 recipe revision 推到 2。
	recipe, err := store.GetRecipe(ctx, recipeID)
	if err != nil {
		t.Fatal(err)
	}

	if err := store.PublishRecipeVersion(recipeID, version.ID, "missing-exec", recipe.Revision, false); err == nil {
		t.Error("不存在的 execution 应被拒绝")
	}

	// resolved execution：走的是当前已发布 binding，不能当新版本的证据。
	resolved := recipeTestExecution(t, store, upstream, recipeID, version.ID, "exec-resolved")
	resolved.RecipeBindingUse = model.BindingResolved
	resolved.RecipeStorage = model.RecipeStorageEmbedded
	resolved.RecipeOrigin = model.RecipeBasic
	resolved.TemplateID = "builtin:models"
	resolved.RecipeID, resolved.RecipeVersionID = 0, 0
	resolved.RecipeIdentityRevision = 1
	if err := store.InsertProbeExecution(ctx, &resolved); err != nil {
		t.Fatal(err)
	}
	if err := store.PublishRecipeVersion(recipeID, version.ID, resolved.ID, recipe.Revision, false); err == nil {
		t.Error("resolved execution 不能作为发布依据")
	}

	// 测的是别的 version。
	other := &model.ProbeRecipeVersion{
		RecipeID: recipeID, Origin: model.RecipeManual, Method: "HEAD", TimeoutProfile: model.TimeoutL1,
	}
	if err := store.AddRecipeVersion(other, recipe.Revision); err != nil {
		t.Fatal(err)
	}
	recipe, err = store.GetRecipe(ctx, recipeID)
	if err != nil {
		t.Fatal(err)
	}
	mismatched := recipeTestExecution(t, store, upstream, recipeID, other.ID, "exec-other-version")
	if err := store.InsertProbeExecution(ctx, &mismatched); err != nil {
		t.Fatal(err)
	}
	if err := store.PublishRecipeVersion(recipeID, version.ID, mismatched.ID, recipe.Revision, false); err == nil {
		t.Error("测的是别的 version，应被拒绝")
	}

	// 测试时配置已过期（config_stale）：必须要求重测，不能凭它发布。
	stale := recipeTestExecution(t, store, upstream, recipeID, version.ID, "exec-stale")
	stale.ReachabilityDisposition = model.ApplyConfigStale
	if err := store.InsertProbeExecution(ctx, &stale); err != nil {
		t.Fatal(err)
	}
	if err := store.PublishRecipeVersion(recipeID, version.ID, stale.ID, recipe.Revision, false); err == nil {
		t.Error("config_stale 的测试应要求重测")
	}

	// 失败的测试：默认拒绝，force 才放行。
	failed := recipeTestExecution(t, store, upstream, recipeID, version.ID, "exec-failed")
	failed.Success, failed.Reachable = false, false
	failed.ErrorClass = model.ErrorTransient
	if err := store.InsertProbeExecution(ctx, &failed); err != nil {
		t.Fatal(err)
	}
	if err := store.PublishRecipeVersion(recipeID, version.ID, failed.ID, recipe.Revision, false); err == nil {
		t.Error("失败的测试默认不能发布")
	}

	// 正常发布。
	good := recipeTestExecution(t, store, upstream, recipeID, version.ID, "exec-good")
	if err := store.InsertProbeExecution(ctx, &good); err != nil {
		t.Fatal(err)
	}
	if err := store.PublishRecipeVersion(recipeID, version.ID, good.ID, recipe.Revision+99, false); !errors.Is(err, ErrRevisionConflict) {
		t.Errorf("错的 expectedRevision error = %v, want ErrRevisionConflict", err)
	}
	beforeBinding := recipe.ActiveBindingRevision
	if err := store.PublishRecipeVersion(recipeID, version.ID, good.ID, recipe.Revision, false); err != nil {
		t.Fatalf("发布应成功: %v", err)
	}
	published, err := store.PublishedUpstreamRecipe(ctx, upstream.ID, model.EndpointModels)
	if err != nil {
		t.Fatal(err)
	}
	if published.Version.ID != version.ID || published.Recipe.Status != model.RecipePublished {
		t.Errorf("published binding = %+v", published)
	}
	if published.Recipe.LastPublishForced {
		t.Error("正常发布不应标记 forced")
	}
	// 换了在服务的模板，active_binding_revision 必须递增，
	// 否则引用旧 binding 的 Capability 不会失效。
	if published.Recipe.ActiveBindingRevision <= beforeBinding {
		t.Errorf("active_binding_revision = %d, want > %d",
			published.Recipe.ActiveBindingRevision, beforeBinding)
	}
	// Route 作用域没有发布过，不能被 Upstream 的 binding 顶替。
	if _, err := store.PublishedRouteRecipe(ctx, 1, model.EndpointModels); !errors.Is(err, ErrNotFound) {
		t.Errorf("未发布的 Route binding error = %v, want ErrNotFound", err)
	}
}

func TestPublishRecipeVersionForceOnlyBypassesSuccess(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	upstream := mkUpstream(t, store, "force-site")
	recipeID, version := mkDraftRecipe(t, store, upstream)
	recipe, err := store.GetRecipe(ctx, recipeID)
	if err != nil {
		t.Fatal(err)
	}

	// force 放行「上游没回 200」，但不放行身份不一致。
	failed := recipeTestExecution(t, store, upstream, recipeID, version.ID, "exec-force")
	failed.Success, failed.Reachable = false, false
	failed.ErrorClass = model.ErrorUnsupported
	if err := store.InsertProbeExecution(ctx, &failed); err != nil {
		t.Fatal(err)
	}
	if err := store.PublishRecipeVersion(recipeID, version.ID, failed.ID, recipe.Revision, true); err != nil {
		t.Fatalf("force 发布应成功: %v", err)
	}
	published, err := store.PublishedUpstreamRecipe(ctx, upstream.ID, model.EndpointModels)
	if err != nil {
		t.Fatal(err)
	}
	if !published.Recipe.LastPublishForced {
		t.Error("force 发布应留下 last_publish_forced 痕迹")
	}

	// force 不能跳过 config_stale：那是安全边界，不是「用户确认可用」能覆盖的。
	other := mkUpstream(t, store, "force-other")
	otherRecipeID, otherVersion := mkDraftRecipe(t, store, other)
	otherRecipe, err := store.GetRecipe(ctx, otherRecipeID)
	if err != nil {
		t.Fatal(err)
	}
	stale := recipeTestExecution(t, store, other, otherRecipeID, otherVersion.ID, "exec-force-stale")
	stale.ReachabilityDisposition = model.ApplyConfigStale
	if err := store.InsertProbeExecution(ctx, &stale); err != nil {
		t.Fatal(err)
	}
	if err := store.PublishRecipeVersion(otherRecipeID, otherVersion.ID, stale.ID,
		otherRecipe.Revision, true); err == nil {
		t.Error("force 不应跳过 config_stale")
	}

	// force 也不能跨 recipe 发布别人的 version。
	crossVersion := recipeTestExecution(t, store, other, otherRecipeID, version.ID, "exec-cross")
	if err := store.InsertProbeExecution(ctx, &crossVersion); err != nil {
		t.Fatal(err)
	}
	if err := store.PublishRecipeVersion(otherRecipeID, version.ID, crossVersion.ID,
		otherRecipe.Revision, true); err == nil {
		t.Error("force 不应允许发布不属于本 recipe 的 version")
	}
}

func TestArchivedRecipeCannotBePublished(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	upstream := mkUpstream(t, store, "archived-publish")
	recipeID, version := mkDraftRecipe(t, store, upstream)
	recipe, err := store.GetRecipe(ctx, recipeID)
	if err != nil {
		t.Fatal(err)
	}
	execution := recipeTestExecution(t, store, upstream, recipeID, version.ID, "exec-archived")
	if err := store.InsertProbeExecution(ctx, &execution); err != nil {
		t.Fatal(err)
	}
	if err := store.ArchiveRecipe(ctx, recipeID, recipe.Revision); err != nil {
		t.Fatal(err)
	}
	archived, err := store.GetRecipe(ctx, recipeID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PublishRecipeVersion(recipeID, version.ID, execution.ID,
		archived.Revision, false); err == nil {
		t.Error("archived recipe 不能发布")
	}
}

func TestListRecipesAndVersionsPageContract(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	upstream := mkUpstream(t, store, "recipe-page")
	recipeID, first := mkDraftRecipe(t, store, upstream)
	recipe, err := store.GetRecipe(ctx, recipeID)
	if err != nil {
		t.Fatal(err)
	}
	// 同一 recipe 下再加两个 version，验证 (version,id) keyset。
	for index := 0; index < 2; index++ {
		next := &model.ProbeRecipeVersion{
			RecipeID: recipeID, Origin: model.RecipeManual, Method: "HEAD",
			TimeoutProfile: model.TimeoutL1,
		}
		if err := store.AddRecipeVersion(next, recipe.Revision); err != nil {
			t.Fatal(err)
		}
		if recipe, err = store.GetRecipe(ctx, recipeID); err != nil {
			t.Fatal(err)
		}
	}
	// 另一个 endpoint 的 recipe，验证 endpoint filter。
	if _, err := store.CreateRecipe(model.RecipeScopeUpstream, upstream.ID, model.EndpointMessages); err != nil {
		t.Fatal(err)
	}

	recipes := pageOf(t, func(request model.PageRequest) (model.Page[*model.ProbeRecipe], error) {
		return store.ListRecipesPage(ctx, model.RecipeFilter{PageRequest: request})
	}, func(item *model.ProbeRecipe) string { return strconv.FormatInt(item.ID, 10) })
	fullRecipes, _, err := recipes("", maximumPageLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(fullRecipes) != 2 {
		t.Fatalf("recipe 全量 = %v, want 2 项", fullRecipes)
	}
	assertNoDuplicateOrGap(t, "recipes", walkAll(t, recipes, 1), fullRecipes)
	byEndpoint, err := store.ListRecipesPage(ctx, model.RecipeFilter{Endpoint: model.EndpointMessages})
	if err != nil {
		t.Fatal(err)
	}
	if len(byEndpoint.Items) != 1 {
		t.Errorf("endpoint filter 得到 %d 项, want 1", len(byEndpoint.Items))
	}
	byStatus, err := store.ListRecipesPage(ctx, model.RecipeFilter{Status: model.RecipeDraft})
	if err != nil {
		t.Fatal(err)
	}
	if len(byStatus.Items) != 2 {
		t.Errorf("status=draft 得到 %d 项, want 2", len(byStatus.Items))
	}
	if _, err := store.ListRecipesPage(ctx, model.RecipeFilter{Status: "bogus"}); err == nil {
		t.Error("非法 status filter 应报错")
	}

	versions := pageOf(t, func(request model.PageRequest) (model.Page[*model.ProbeRecipeVersion], error) {
		return store.ListRecipeVersionsPage(ctx,
			model.RecipeVersionFilter{PageRequest: request, RecipeID: recipeID})
	}, func(item *model.ProbeRecipeVersion) string { return strconv.Itoa(item.Version) })
	fullVersions, _, err := versions("", maximumPageLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(fullVersions) != 3 {
		t.Fatalf("version 全量 = %v, want 3 项", fullVersions)
	}
	for _, limit := range []int{1, 2, 3} {
		assertNoDuplicateOrGap(t, "recipe-versions", walkAll(t, versions, limit), fullVersions)
	}
	byOrigin, err := store.ListRecipeVersionsPage(ctx,
		model.RecipeVersionFilter{RecipeID: recipeID, Origin: model.RecipeLearned})
	if err != nil {
		t.Fatal(err)
	}
	if len(byOrigin.Items) != 0 || byOrigin.NextCursor != "" {
		t.Errorf("origin=learned 得到 %d 项 next=%q, want 空页", len(byOrigin.Items), byOrigin.NextCursor)
	}

	// GetRecipeVersion round-trip：headers/body 要能原样读回。
	fetched, err := store.GetRecipeVersion(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fetched.RecipeID != recipeID || fetched.Version != 1 || fetched.Method != "GET" {
		t.Errorf("GetRecipeVersion = %+v", fetched)
	}
	if _, err := store.GetRecipeVersion(ctx, 99999); !errors.Is(err, ErrNotFound) {
		t.Errorf("不存在的 version error = %v, want ErrNotFound", err)
	}

	changed := pageOf(t, func(request model.PageRequest) (model.Page[*model.ProbeRecipeVersion], error) {
		return store.ListRecipeVersionsPage(ctx,
			model.RecipeVersionFilter{PageRequest: request, RecipeID: recipeID, Origin: model.RecipeManual})
	}, func(item *model.ProbeRecipeVersion) string { return strconv.Itoa(item.Version) })
	assertCursorRejections(t, "recipe-versions", versions, crossResourceCursor(t, store), changed)
}
