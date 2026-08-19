package store

// Recipe 的发布与已发布 binding 查询。
//
// 发布是 P0 里最需要「重验」的写入：测试成功只证明**当时**那套配置能用。
// 从测试到点发布之间，Endpoint、API Key、Route 模型映射、Secret 值或 Settings
// 任一改变，这次测试就不再代表将要发布的东西 —— 此时必须要求重测，而不是
// 让一个陈旧的绿灯把配置推上去。

import (
	"context"
	"database/sql"
	"errors"

	"github.com/279814/relay-gate/internal/model"
)

// publishedBinding 把 loadPublishedBinding 的行拼成完整的 Recipe+Version。
// Resolver 需要整份可执行内容，不只是 ID。
func (store *Store) publishedBinding(ctx context.Context, scope model.RecipeScope, scopeID int64, endpoint model.EndpointKind) (*model.PublishedRecipeBinding, error) {
	if scopeID < 1 || !endpoint.Valid() {
		return nil, model.WrapValidation("published binding 查询参数无效")
	}
	column := "upstream_id"
	if scope == model.RecipeScopeRoute {
		column = "route_id"
	}
	recipe, err := scanProbeRecipe(store.db.QueryRowContext(ctx, `SELECT `+recipeCols+
		` FROM probe_recipe WHERE `+column+`=? AND endpoint=? AND status IN ('published','legacy_compat')`,
		scopeID, endpoint))
	if err != nil {
		return nil, err
	}
	if recipe.PublishedVersionID == 0 {
		return nil, ErrNotFound
	}
	version, err := store.GetRecipeVersion(ctx, recipe.PublishedVersionID)
	if err != nil {
		return nil, err
	}
	return &model.PublishedRecipeBinding{Recipe: *recipe, Version: *version}, nil
}

func (store *Store) PublishedRouteRecipe(ctx context.Context, routeID int64, endpoint model.EndpointKind) (*model.PublishedRecipeBinding, error) {
	return store.publishedBinding(ctx, model.RecipeScopeRoute, routeID, endpoint)
}

func (store *Store) PublishedUpstreamRecipe(ctx context.Context, upstreamID int64, endpoint model.EndpointKind) (*model.PublishedRecipeBinding, error) {
	return store.publishedBinding(ctx, model.RecipeScopeUpstream, upstreamID, endpoint)
}

// PublishRecipeVersion 把一个 draft version 设为该 scope+endpoint 的 published binding。
//
// testExecutionID 必须是一次针对 (recipeID, versionID) 的显式测试且成功。
// force=true 只跳过「测试必须成功」这一条 —— 用于上游返回非 200 但用户确认
// 该形状可用的情形；它不跳过身份一致性与 token 新鲜度检查，那些是安全边界。
func (store *Store) PublishRecipeVersion(recipeID, versionID int64, testExecutionID string, expectedRecipeRevision int64, force bool) (err error) {
	if recipeID < 1 || versionID < 1 || testExecutionID == "" || expectedRecipeRevision < 1 {
		return model.WrapValidation("publish 参数无效")
	}
	ctx := context.Background()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	recipe, err := scanProbeRecipe(tx.QueryRowContext(ctx, `SELECT `+recipeCols+
		` FROM probe_recipe WHERE id=?`, recipeID))
	if err != nil {
		return err
	}
	switch recipe.Status {
	case model.RecipeArchived:
		return model.WrapValidation("archived recipe 不能发布")
	case model.RecipeQuarantined:
		return model.WrapValidation("legacy_quarantined recipe 必须先人工审核，不能直接发布")
	}
	// version 必须属于本 recipe。跨 recipe 发布会让 binding 指向别人的内容。
	var versionRecipeID int64
	if err = tx.QueryRowContext(ctx, `SELECT recipe_id FROM probe_recipe_version WHERE id=?`,
		versionID).Scan(&versionRecipeID); errors.Is(err, sql.ErrNoRows) {
		return model.WrapValidation("recipe version %d 不存在", versionID)
	} else if err != nil {
		return err
	}
	if versionRecipeID != recipeID {
		return model.WrapValidation("version %d 不属于 recipe %d", versionID, recipeID)
	}
	if err = requireRecipeTestExecution(ctx, tx, recipe, versionID, testExecutionID, force); err != nil {
		return err
	}
	now := nowMS()
	// active_binding_revision 递增即让引用旧 binding 的 Capability 立刻 stale：
	// 换了在服务的模板，旧探活结论不再代表现在发出去的请求。
	result, err := tx.ExecContext(ctx, `UPDATE probe_recipe SET status='published',
		published_version_id=?,last_test_execution_id=?,last_publish_forced=?,published_at=?,
		revision=revision+1,active_binding_revision=active_binding_revision+1,updated_at=?
		WHERE id=? AND revision=?`, versionID, testExecutionID, force, now, now,
		recipeID, expectedRecipeRevision)
	if err != nil {
		return wrapConstraint(err, "probe_recipe")
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrRevisionConflict
	}
	return tx.Commit()
}

// requireRecipeTestExecution 重验这次测试打的就是要发布的这份内容。
//
// 只认 BindingExplicitTest：resolved 的 execution 走的是当前已发布 binding，
// 拿它当新版本的证据等于用旧模板的结果发布新模板。
func requireRecipeTestExecution(ctx context.Context, tx *sql.Tx, recipe *model.ProbeRecipe, versionID int64, executionID string, force bool) error {
	var upstreamID, routeID, execRecipeID, execVersionID int64
	var endpoint, storage, bindingUse, reachDisposition, capDisposition string
	var success bool
	if err := tx.QueryRowContext(ctx, `SELECT upstream_id,COALESCE(route_id,0),COALESCE(recipe_id,0),
		COALESCE(recipe_version_id,0),endpoint,recipe_storage,recipe_binding_use,success,
		reachability_disposition,capability_disposition FROM probe_execution WHERE id=?`,
		executionID).Scan(&upstreamID, &routeID, &execRecipeID, &execVersionID, &endpoint,
		&storage, &bindingUse, &success, &reachDisposition, &capDisposition); errors.Is(err, sql.ErrNoRows) {
		return model.WrapValidation("测试用的 execution %q 不存在", executionID)
	} else if err != nil {
		return err
	}
	if bindingUse != string(model.BindingExplicitTest) || storage != string(model.RecipeStorageDB) {
		return model.WrapValidation("execution %q 不是针对该 recipe version 的显式测试", executionID)
	}
	if execRecipeID != recipe.ID || execVersionID != versionID {
		return model.WrapValidation("execution %q 测的是 recipe %d/version %d，与要发布的 %d/%d 不一致",
			executionID, execRecipeID, execVersionID, recipe.ID, versionID)
	}
	if endpoint != string(recipe.Endpoint) {
		return model.WrapValidation("execution %q 的 endpoint 与 recipe 不一致", executionID)
	}
	// scope 也要对得上：upstream 作用域的 recipe 不能拿某条 Route 的测试来发布。
	if recipe.ScopeType == model.RecipeScopeRoute {
		if routeID != recipe.ScopeID {
			return model.WrapValidation("execution %q 测的 Route 与 recipe scope 不一致", executionID)
		}
	} else if upstreamID != recipe.ScopeID {
		return model.WrapValidation("execution %q 测的 Upstream 与 recipe scope 不一致", executionID)
	}
	// 显式测试的 Capability 固定 not_applicable（它不改在服务的能力状态），
	// 所以只能查 Reachability 侧有没有 config_stale/superseded。
	if reachDisposition == string(model.ApplyConfigStale) || capDisposition == string(model.ApplyConfigStale) {
		return model.WrapValidation("execution %q 测试时的配置已过期，请重测", executionID)
	}
	if reachDisposition == string(model.ApplySuperseded) || capDisposition == string(model.ApplySuperseded) {
		return model.WrapValidation("execution %q 已被更新的观察结果取代，请重测", executionID)
	}
	if !success && !force {
		return model.WrapValidation("execution %q 未成功；确认该形状可用可用 force 发布", executionID)
	}
	return nil
}
