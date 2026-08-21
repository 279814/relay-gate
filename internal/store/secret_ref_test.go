package store

// Probe Secret 与 published Recipe 的引用关系（P0-05 第 9、12a 条）。
//
// 表 recipe_active_secret_ref 在 schema 2 就已建好（secret_id 是
// ON DELETE RESTRICT），但一直没有任何 Go 代码往里写 —— 于是那个 FK 约束
// 在 recipe 路径上是死的，DeleteProbeSecret 里的 FOREIGN KEY 分支永远走不到。

import (
	"context"
	"errors"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

// mkPublishedRecipeWithSecret 造一个引用 Secret 的 **published** recipe。
func mkPublishedRecipeWithSecret(t *testing.T, store *Store,
	upstream *model.Upstream, secretName string) (recipeID int64, versionID int64) {

	t.Helper()
	recipeID, err := store.CreateRecipe(model.RecipeScopeUpstream, upstream.ID, model.EndpointModels)
	if err != nil {
		t.Fatal(err)
	}
	version := &model.ProbeRecipeVersion{
		RecipeID: recipeID, Origin: model.RecipeManual, Method: "GET",
		Headers: []model.HeaderTemplate{
			{Name: "X-Custom-Auth", Values: []string{"{{SECRET:" + secretName + "}}"}},
		},
		TimeoutProfile: model.TimeoutL1,
	}
	if err := store.AddRecipeVersion(version, 1); err != nil {
		t.Fatal(err)
	}

	recipe, err := store.GetRecipe(context.Background(), recipeID)
	if err != nil {
		t.Fatal(err)
	}
	execution := recipeTestExecution(t, store, upstream, recipeID, version.ID, "exec-secret-ref")
	if err := store.InsertProbeExecution(context.Background(), &execution); err != nil {
		t.Fatal(err)
	}
	if err := store.PublishRecipeVersion(recipeID, version.ID, execution.ID, recipe.Revision, false); err != nil {
		t.Fatal(err)
	}
	return recipeID, version.ID
}

// 被 published recipe 引用的 Secret 不能删。
//
// 为什么这条是安全边界：删掉它之后，那个 recipe 的模板仍然引用
// {{SECRET:name}}，而渲染会失败 —— 探活因此把一个好站报成 config_error。
// 更糟的是「删掉再建一个同名的」：ID 变了，而 BindSecrets 会拒绝，
// 于是站点看起来是配置错误，实际原因是三步之前的一次删除。
//
// 与「draft 引用不阻塞删除」并存（见
// TestRecipeVersionIsImmutableAndSecretBindingDoesNotReattachByName）：
// draft 还没生效，拦它只会让用户没法清理试错留下的草稿。
func TestDeleteProbeSecretRejectedWhilePublishedRecipeReferencesIt(t *testing.T) {
	store := testStore(t)
	upstream := mkUpstream(t, store, "secret-ref-site")

	secret, err := store.CreateProbeSecret("published_auth", []byte("secret-value"))
	if err != nil {
		t.Fatal(err)
	}
	mkPublishedRecipeWithSecret(t, store, upstream, "published_auth")

	err = store.DeleteProbeSecret(secret.ID, secret.Revision)
	if !errors.Is(err, ErrDependencyConflict) {
		t.Fatalf("被 published recipe 引用的 Secret 必须拒绝删除（否则那个站的探活会"+
			"变成无法归因的 config_error），得到 %v", err)
	}

	// 确认真的没删掉 —— 报错但仍删除是最坏的结果。
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM probe_secret WHERE id=?`, secret.ID).
		Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Error("报了冲突却仍把 Secret 删掉了")
	}
}

// published recipe 的 active ref 必须真的写进表里。
//
// 直接查表而不是只看删除行为：ref 表是 FK 生效的载体，空表时
// DeleteProbeSecret 会「意外通过」，而那种通过看起来与正确行为一样。
func TestPublishRecipeVersionRecordsActiveSecretRefs(t *testing.T) {
	store := testStore(t)
	upstream := mkUpstream(t, store, "active-ref-site")

	secret, err := store.CreateProbeSecret("active_auth", []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	recipeID, _ := mkPublishedRecipeWithSecret(t, store, upstream, "active_auth")

	var refSecretID, refRevision int64
	var refName string
	if err := store.db.QueryRow(`SELECT secret_id,name,revision FROM recipe_active_secret_ref
		WHERE recipe_id=?`, recipeID).Scan(&refSecretID, &refName, &refRevision); err != nil {
		t.Fatalf("published recipe 应有 active secret ref: %v", err)
	}
	if refSecretID != secret.ID || refName != "active_auth" || refRevision != secret.Revision {
		t.Errorf("ref = %d/%q/%d，want %d/active_auth/%d",
			refSecretID, refName, refRevision, secret.ID, secret.Revision)
	}
}

// draft 阶段**不**建 active ref。
//
// 这条与上一条一起把边界钉住：draft 不参与解析（publishedBinding 的 status
// 过滤），所以它不该锁住 Secret —— 否则用户没法删掉试错留下的草稿引用的
// Secret，而那个草稿永远不会生效。
func TestDraftRecipeDoesNotLockSecret(t *testing.T) {
	store := testStore(t)
	upstream := mkUpstream(t, store, "draft-ref-site")

	secret, err := store.CreateProbeSecret("draft_auth", []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	recipeID, err := store.CreateRecipe(model.RecipeScopeUpstream, upstream.ID, model.EndpointModels)
	if err != nil {
		t.Fatal(err)
	}
	version := &model.ProbeRecipeVersion{
		RecipeID: recipeID, Origin: model.RecipeManual, Method: "GET",
		Headers:        []model.HeaderTemplate{{Name: "X-A", Values: []string{"{{SECRET:draft_auth}}"}}},
		TimeoutProfile: model.TimeoutL1,
	}
	if err := store.AddRecipeVersion(version, 1); err != nil {
		t.Fatal(err)
	}

	var refs int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM recipe_active_secret_ref WHERE recipe_id=?`,
		recipeID).Scan(&refs); err != nil {
		t.Fatal(err)
	}
	if refs != 0 {
		t.Errorf("draft 不该建 active ref（它不参与解析），得到 %d 条", refs)
	}
	if err := store.DeleteProbeSecret(secret.ID, secret.Revision); err != nil {
		t.Errorf("只被 draft 引用的 Secret 应可删除: %v", err)
	}
}

// archive 之后释放 active ref，Secret 随即可删（第 12a 条）。
//
// 不释放的话，一个已归档的 recipe 会永久锁住它引用过的 Secret —— 而归档
// 的语义正是「这份配置不再参与任何解析」。
func TestArchiveRecipeReleasesActiveSecretRefs(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	upstream := mkUpstream(t, store, "archive-ref-site")

	secret, err := store.CreateProbeSecret("archive_auth", []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	recipeID, _ := mkPublishedRecipeWithSecret(t, store, upstream, "archive_auth")

	// 先确认它确实被锁住了，否则下面的「解锁」证明不了任何东西。
	if err := store.DeleteProbeSecret(secret.ID, secret.Revision); !errors.Is(err, ErrDependencyConflict) {
		t.Fatalf("前提不成立：published 阶段就该锁住，得到 %v", err)
	}

	recipe, err := store.GetRecipe(ctx, recipeID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ArchiveRecipe(ctx, recipeID, recipe.Revision); err != nil {
		t.Fatal(err)
	}

	var refs int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM recipe_active_secret_ref WHERE recipe_id=?`,
		recipeID).Scan(&refs); err != nil {
		t.Fatal(err)
	}
	if refs != 0 {
		t.Errorf("archive 必须释放 active ref，仍有 %d 条", refs)
	}
	if err := store.DeleteProbeSecret(secret.ID, secret.Revision); err != nil {
		t.Errorf("archive 之后 Secret 应可删除: %v", err)
	}
}

// disable 同样释放 active ref。
//
// 与 archive 同理：disabled 的 recipe 不参与解析（publishedBinding 只认
// published 与 legacy_compat），所以它也不该继续锁住 Secret。
func TestDisableRecipeReleasesActiveSecretRefs(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	upstream := mkUpstream(t, store, "disable-ref-site")

	secret, err := store.CreateProbeSecret("disable_auth", []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	recipeID, _ := mkPublishedRecipeWithSecret(t, store, upstream, "disable_auth")

	recipe, err := store.GetRecipe(ctx, recipeID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DisableRecipe(ctx, recipeID, recipe.Revision); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteProbeSecret(secret.ID, secret.Revision); err != nil {
		t.Errorf("disable 之后 Secret 应可删除: %v", err)
	}
}
