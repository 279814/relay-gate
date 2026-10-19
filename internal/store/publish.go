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
	"sort"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
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

// RecipeVersionSecretRefs 取该版本绑定时的 Secret 快照。
//
// 供 probe.RecipeResolver 交给 BindSecrets 校验用。返回的是**绑定时**的
// secret_id，不是现在按名字查到的那个 —— 删掉一个 Secret 再建同名的会拿到
// 不同 ID，而 §4.5 要求同名新 Secret 不能自动满足旧引用。
//
// 用 bound_secret_id_snapshot 而不是 resolved_secret_id：后者是
// ON DELETE SET NULL 的，Secret 被删后会变成 NULL，而我们要的正是
// 「原来绑的是哪一个」这个事实，好让 BindSecrets 报出身份不匹配。
func (store *Store) RecipeVersionSecretRefs(ctx context.Context, versionID int64) ([]model.RequiredSecretRef, error) {
	if versionID < 1 {
		return nil, model.WrapValidation("recipe version id 无效")
	}
	rows, err := store.db.QueryContext(ctx, `SELECT name,bound_secret_id_snapshot
		FROM recipe_version_required_secret WHERE recipe_version_id=? ORDER BY name`, versionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var refs []model.RequiredSecretRef
	for rows.Next() {
		var ref model.RequiredSecretRef
		if err := rows.Scan(&ref.Name, &ref.BoundSecretID); err != nil {
			return nil, err
		}
		// 与 replaceRecipeSecretRefs 同一条判断：snapshot 为 0 的行没经过绑定
		// （迁移遗留）。放过去的话 BindSecrets 会以「secret_id 已变（绑定 0，
		// 当前 N）」失败，而那句话把用户引向「Secret 被重建过」这个错方向。
		if ref.BoundSecretID < 1 {
			return nil, model.WrapValidation("recipe version %d 的 Secret 引用 %q 没有绑定快照："+
				"这是 legacy 迁移遗留的配置，请先新增一个版本（会重新绑定 Secret）", versionID, ref.Name)
		}
		refs = append(refs, ref)
	}
	return refs, rows.Err()
}

// PublishRecipeVersion 把一个 draft version 设为该 scope+endpoint 的 published binding。
//
// testExecutionID 必须是一次针对 (recipeID, versionID) 的显式测试且成功。
// force=true 仅接受确实发送并失败的当前测试；成功、取消与未发送都不能强制发布。
// 身份一致性和 token 新鲜度在同一个发布事务里重验。
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
	if recipe.Revision != expectedRecipeRevision {
		return ErrRevisionConflict
	}
	switch recipe.Status {
	case model.RecipeArchived:
		return model.WrapValidation("archived recipe 不能发布")
	case model.RecipeQuarantined:
		return model.WrapValidation("legacy_quarantined recipe 必须先人工审核，不能直接发布")
	}
	// version 必须属于本 recipe。跨 recipe 发布会让 binding 指向别人的内容。
	var versionRecipeID int64
	var versionOrigin model.RecipeSource
	var versionTimeout model.ProbeTimeoutProfile
	if err = tx.QueryRowContext(ctx, `SELECT recipe_id,origin,timeout_profile FROM probe_recipe_version WHERE id=?`,
		versionID).Scan(&versionRecipeID, &versionOrigin, &versionTimeout); errors.Is(err, sql.ErrNoRows) {
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
	execution, err := scanProbeExecution(tx.QueryRowContext(ctx, `SELECT `+probeExecutionCols+` FROM probe_execution WHERE id=?`, testExecutionID))
	if err != nil {
		return err
	}
	facts := model.RecipeBindingFacts{Use: model.BindingExplicitTest, ExplicitRecipeID: recipe.ID, ExplicitVersionID: versionID, ExplicitRecipeRowRevision: recipe.Revision}
	if recipe.ScopeType == model.RecipeScopeRoute {
		facts.ResolvedLayer = model.ResolvedRoute
		facts.RouteRecipeID, facts.RoutePublishedVersionID, facts.RouteBindingRevision = recipe.ID, versionID, recipe.ActiveBindingRevision
	} else {
		facts.ResolvedLayer = model.ResolvedUpstream
		facts.UpstreamRecipeID, facts.UpstreamPublishedVersionID, facts.UpstreamBindingRevision = recipe.ID, versionID, recipe.ActiveBindingRevision
	}
	if execution.RecipeBindingFacts != facts {
		return ErrRevisionConflict
	}
	if execution.RecipeBindingRevision != recipe.ActiveBindingRevision {
		return ErrRevisionConflict
	}
	modelEndpoint := recipe.Endpoint != model.EndpointModels && recipe.Endpoint != model.EndpointCountTokens
	if execution.RecipeOrigin != versionOrigin || modelEndpoint && execution.CapabilityPolicySelector.TimeoutProfile != versionTimeout {
		return ErrRevisionConflict
	}
	if err = requireExplicitTestTargetCurrent(ctx, tx, execution); err != nil {
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
	// active ref 与 published 指针在**同一个事务**里换。分开做的话，中间那个
	// 瞬间要么是「已发布但 Secret 没锁」（能被删掉，探活随即 config_error），
	// 要么是「锁了但没发布」，两者都需要人来收拾。
	if err = replaceRecipeSecretRefs(ctx, tx, recipeID, versionID); err != nil {
		return err
	}
	if err = clearRecipeScopeHealthTx(ctx, tx, recipeID); err != nil {
		return err
	}
	return tx.Commit()
}

// replaceRecipeSecretRefs 让 recipe_active_secret_ref 与刚发布的那个版本一致。
//
// 这张表是 schema 2 就建好的（secret_id 为 ON DELETE RESTRICT），但在 P0-05
// 之前没有任何写入方 —— 于是那个 FK 约束在 recipe 路径上是死的，
// DeleteProbeSecret 里的 FOREIGN KEY 分支永远走不到。后果是被 published
// recipe 引用的 Secret 能被删掉，而那个站的探活随即变成无法归因的
// config_error：模板还引用着 {{SECRET:name}}，值却没了。
//
// 只对 **published** 的版本建 ref。draft 不参与解析（publishedBinding 只认
// published 与 legacy_compat），锁它只会让用户没法清理试错留下的草稿。
//
// 用 recipe_version_required_secret 的 snapshot 而不是重新编译模板：那张表
// 记的是 AddRecipeVersion 当时绑定的 secret_id，与 BindSecrets 在渲染前校验
// 的是同一份。重新编译再按名字查一次库的话，「同名新建」会悄悄绑上新 ID ——
// 而 §4.5 明确要求同名新 Secret 不能自动满足旧引用。
func replaceRecipeSecretRefs(ctx context.Context, tx *sql.Tx, recipeID, versionID int64) error {
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM recipe_active_secret_ref WHERE recipe_id=?`, recipeID); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT name,bound_secret_id_snapshot,bound_revision_snapshot
		FROM recipe_version_required_secret WHERE recipe_version_id=?`, versionID)
	if err != nil {
		return err
	}
	type secretRef struct {
		name     string
		id       int64
		revision int64
	}
	// 先全部读出来再写：SQLite 在同一连接上边遍历 rows 边 Exec 会锁住。
	var refs []secretRef
	for rows.Next() {
		var ref secretRef
		if err := rows.Scan(&ref.name, &ref.id, &ref.revision); err != nil {
			rows.Close()
			return err
		}
		refs = append(refs, ref)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	for _, ref := range refs {
		// snapshot 为 0 意味着这条引用从来没经过绑定：迁移路径
		// （migrate_backfill.go）只写 name 三列，其余落默认 0。拿 0 去建 ref
		// 会撞 CHECK (revision >= 1)，而那句「约束冲突」没人能看出问题在哪；
		// 就算 CHECK 松了，secret_id=0 也只是一条指向不存在 Secret 的引用 ——
		// 于是「删除受引用的 Secret 要报冲突」那道边界在这个 recipe 上是空的。
		if ref.id < 1 || ref.revision < 1 {
			return model.WrapValidation("recipe %d 的 Secret 引用 %q 没有绑定快照，"+
				"无法发布：这是 legacy 迁移遗留的配置，请先新增一个版本（会重新绑定 Secret）再发布",
				recipeID, ref.name)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO recipe_active_secret_ref
			(recipe_id,secret_id,name,revision) VALUES (?,?,?,?)`,
			recipeID, ref.id, ref.name, ref.revision); err != nil {
			return wrapConstraint(err, "recipe_active_secret_ref")
		}
	}
	return nil
}

// requireRecipeTestExecution 重验这次测试打的就是要发布的这份内容。
//
// 只认 BindingExplicitTest：resolved 的 execution 走的是当前已发布 binding，
// 拿它当新版本的证据等于用旧模板的结果发布新模板。
func requireRecipeTestExecution(ctx context.Context, tx *sql.Tx, recipe *model.ProbeRecipe, versionID int64, executionID string, force bool) error {
	var upstreamID, routeID, execRecipeID, execVersionID int64
	var endpoint, storage, bindingUse, reachDisposition, capDisposition string
	var success, final, expectedCancel bool
	var sentAt, doneAt int64
	var errorClass model.ErrorClass
	if err := tx.QueryRowContext(ctx, `SELECT upstream_id,COALESCE(route_id,0),COALESCE(recipe_id,0),
		COALESCE(recipe_version_id,0),endpoint,recipe_storage,recipe_binding_use,success,
		reachability_disposition,capability_disposition,final,sent_at_ms,done_at_ms,expected_cancel,error_class FROM probe_execution WHERE id=?`,
		executionID).Scan(&upstreamID, &routeID, &execRecipeID, &execVersionID, &endpoint,
		&storage, &bindingUse, &success, &reachDisposition, &capDisposition, &final, &sentAt, &doneAt, &expectedCancel, &errorClass); errors.Is(err, sql.ErrNoRows) {
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
	// Scope owner must match. An upstream model-endpoint test can additionally
	// carry its selected Route; publication also rechecks that Route and Model.
	if recipe.ScopeType == model.RecipeScopeRoute {
		if routeID != recipe.ScopeID {
			return model.WrapValidation("execution %q 测的 Route 与 recipe scope 不一致", executionID)
		}
	} else if upstreamID != recipe.ScopeID {
		return model.WrapValidation("execution %q 测的 Upstream 与 recipe scope 不一致", executionID)
	}
	// Explicit tests do not update live capability. Reject known stale evidence
	// first; PublishRecipeVersion additionally rechecks the current full token.
	if reachDisposition == string(model.ApplyConfigStale) || capDisposition == string(model.ApplyConfigStale) {
		return ErrRevisionConflict
	}
	if reachDisposition == string(model.ApplySuperseded) || capDisposition == string(model.ApplySuperseded) {
		return ErrRevisionConflict
	}
	if !success && !force {
		return model.WrapValidation("execution %q 未成功；确认该形状可用可以用 force 发布", executionID)
	}
	if !final || sentAt <= 0 || doneAt < sentAt || errorClass == model.ErrorIgnored || (!success && expectedCancel) {
		return model.WrapValidation("execution %q 不是已发送且完成的测试，请重测", executionID)
	}
	if force && (success || errorClass == model.ErrorNone) {
		return model.WrapValidation("force 只允许已发送且确实失败的测试")
	}
	return nil
}

// Explicit tests deliberately do not update live capability state. Their stored
// disposition therefore cannot prove freshness at publication time: rebuild the
// same semantic token from database-current rows in this write transaction.
func requireExplicitTestTargetCurrent(ctx context.Context, tx *sql.Tx, execution *model.ProbeExecution) error {
	if !execution.Final || !execution.Success && execution.ExpectedCancel || execution.ErrorClass == model.ErrorIgnored || execution.SentAtMS <= 0 || execution.DoneAtMS < execution.SentAtMS {
		return model.WrapValidation("测试尚未完成发送或已取消，请重测")
	}
	if execution.ReachabilityDisposition == model.ApplyConfigStale || execution.ReachabilityDisposition == model.ApplySuperseded || execution.CapabilityDisposition == model.ApplyConfigStale || execution.CapabilityDisposition == model.ApplySuperseded {
		return ErrRevisionConflict
	}
	selector := execution.CapabilityPolicySelector
	if selector.Validate() != nil || selector.Kind == model.EvidenceRealTraffic || execution.CapabilityToken == "" {
		return ErrRevisionConflict
	}
	identity := model.RecipeIdentity{Storage: execution.RecipeStorage, Origin: execution.RecipeOrigin, DBVersionID: execution.RecipeVersionID, ClientProfileID: execution.ClientProfileID, TemplateID: execution.TemplateID, Revision: execution.RecipeIdentityRevision}
	if identity.Validate() != nil {
		return ErrRevisionConflict
	}
	var enabled bool
	if err := tx.QueryRowContext(ctx, `SELECT enabled FROM upstream WHERE id=?`, execution.UpstreamID).Scan(&enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRevisionConflict
		}
		return err
	}
	if !enabled {
		return ErrRevisionConflict
	}
	target := model.SemanticTarget{Scope: model.RecipeScopeUpstream, UpstreamID: execution.UpstreamID, Endpoint: execution.Endpoint}
	if execution.RouteID > 0 {
		var routeEnabled, modelEnabled bool
		if err := tx.QueryRowContext(ctx, `SELECT r.enabled,m.enabled FROM route r JOIN model_name m ON m.id=r.model_name_id WHERE r.id=? AND r.upstream_id=?`, execution.RouteID, execution.UpstreamID).Scan(&routeEnabled, &modelEnabled); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrRevisionConflict
			}
			return err
		}
		if !routeEnabled || !modelEnabled {
			return ErrRevisionConflict
		}
		target.Scope, target.RouteID = model.RecipeScopeRoute, execution.RouteID
	}
	secrets, err := explicitTestSecretRevisions(ctx, tx, execution)
	if err != nil {
		return err
	}
	if revisioncodec.SecretRevisionSetHash(secrets) != execution.ProbeSecretRevisionsHash {
		return ErrRevisionConflict
	}
	revision := model.SemanticRevision{
		UpstreamNetwork: execution.UpstreamNetworkRevision, UpstreamCredential: execution.UpstreamCredentialRevision,
		EndpointID: execution.EndpointID, EndpointRevision: execution.EndpointRevision, AuthProfile: execution.AuthProfileRevision,
		RouteCapability: execution.RouteCapabilityRevision, ModelCapability: execution.ModelCapabilityRevision,
		RecipeIdentity: identity, RecipeBindingRevision: execution.RecipeBindingRevision,
		ProbeSettingsFingerprint: execution.ProbeSettingsFingerprint, ProbeSecrets: secrets, RequestTransform: execution.RequestTransformBindingRevision,
	}
	if revisioncodec.NewObservationToken(revision) != execution.CapabilityToken {
		return ErrRevisionConflict
	}
	current, err := currentSemanticRevision(ctx, tx, &model.SemanticExpectation{Target: target, PolicySelector: selector, Revision: revision})
	if errors.Is(err, ErrNotFound) || errors.Is(err, sql.ErrNoRows) {
		return ErrRevisionConflict
	}
	if err != nil {
		return err
	}
	if revisioncodec.NewObservationToken(current) != execution.CapabilityToken {
		return ErrRevisionConflict
	}
	return nil
}

func explicitTestSecretRevisions(ctx context.Context, tx *sql.Tx, execution *model.ProbeExecution) ([]model.SecretRevision, error) {
	query := `SELECT name,secret_id FROM endpoint_active_secret_ref WHERE endpoint_id=?`
	args := []any{execution.EndpointID}
	if execution.RecipeStorage == model.RecipeStorageDB {
		query += ` UNION ALL SELECT name,bound_secret_id_snapshot FROM recipe_version_required_secret WHERE recipe_version_id=?`
		args = append(args, execution.RecipeVersionID)
	} else {
		query += ` UNION ALL SELECT name,bound_secret_id_snapshot FROM client_profile_required_secret WHERE client_profile_id=?`
		args = append(args, execution.ClientProfileID)
	}
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	refs := map[string]int64{}
	for rows.Next() {
		var name string
		var id int64
		if err := rows.Scan(&name, &id); err != nil {
			rows.Close()
			return nil, err
		}
		if previous, exists := refs[name]; id < 1 || exists && previous != id {
			rows.Close()
			return nil, ErrRevisionConflict
		}
		refs[name] = id
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	secrets := make([]model.SecretRevision, 0, len(refs))
	for name, boundID := range refs {
		value := model.SecretRevision{Name: name, Resolved: true}
		if err := tx.QueryRowContext(ctx, `SELECT id,revision FROM probe_secret WHERE name=?`, name).Scan(&value.ID, &value.Revision); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrRevisionConflict
			}
			return nil, err
		}
		if value.ID != boundID {
			return nil, ErrRevisionConflict
		}
		secrets = append(secrets, value)
	}
	sort.Slice(secrets, func(i, j int) bool { return secrets[i].Name < secrets[j].Name })
	return secrets, nil
}
