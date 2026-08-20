package store

// ClientProbeProfile 是「从真实流量学到的请求形状」的仓储。
//
// 与 probe_recipe 的关键区别：Recipe 是人写的、可发布的配置，profile 是观察
// 到的候选。同一个 upstream+endpoint 下允许并存多个 family/shape 候选，但
// 只能有一个 tested —— 它是 Resolver 的 fallback，被 idx_client_profile_
// tested_endpoint 这个 partial unique index 约束住，不靠应用层自觉。

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probetemplate"
)

const clientProfileCols = `id,upstream_id,endpoint,status,safe_headers_json,fixed_raw_query,
	query_shape_json,body_template,body_shape_json,client_family,shape_hash,revision,
	last_seen_at,seen_count,COALESCE(tested_execution_id,''),created_at,updated_at`

func scanClientProfile(scanner interface{ Scan(...any) error }) (*model.ClientProbeProfile, error) {
	var profile model.ClientProbeProfile
	var headersJSON string
	if err := scanner.Scan(&profile.ID, &profile.UpstreamID, &profile.Endpoint, &profile.Status,
		&headersJSON, &profile.FixedRawQuery, &profile.QueryShapeJSON, &profile.BodyTemplate,
		&profile.BodyShapeJSON, &profile.ClientFamily, &profile.ShapeHash, &profile.Revision,
		&profile.LastSeenAt, &profile.SeenCount, &profile.TestedExecutionID,
		&profile.CreatedAt, &profile.UpdatedAt); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(headersJSON), &profile.SafeHeaders); err != nil {
		return nil, fmt.Errorf("client profile %d 的 safe_headers_json: %w", profile.ID, err)
	}
	return &profile, nil
}

// TestedClientProfile 取该 upstream+endpoint 唯一的 tested profile。
// 没有 tested 时回 ErrNotFound —— 调用方据此走内置模板，而不是拿候选去发请求。
func (store *Store) TestedClientProfile(ctx context.Context, upstreamID int64, endpoint model.EndpointKind) (*model.ClientProbeProfile, error) {
	if upstreamID < 1 || !endpoint.Valid() {
		return nil, model.WrapValidation("client profile 查询参数无效")
	}
	return scanClientProfile(store.db.QueryRowContext(ctx, `SELECT `+clientProfileCols+
		` FROM client_probe_profile WHERE upstream_id=? AND endpoint=? AND status='tested'`,
		upstreamID, endpoint))
}

func (store *Store) ListClientProfilesPage(ctx context.Context, filter model.ClientProfileFilter) (model.Page[*model.ClientProbeProfile], error) {
	limit, err := normalizePageLimit(filter.Limit)
	if err != nil {
		return model.Page[*model.ClientProbeProfile]{}, err
	}
	cursorFilter := filter
	cursorFilter.PageRequest = model.PageRequest{}
	keys, err := decodePageCursor(filter.Cursor, "client-profiles", cursorFilter, 1)
	if err != nil {
		return model.Page[*model.ClientProbeProfile]{}, err
	}
	conditions := []string{"1=1"}
	args := make([]any, 0, 6)
	if filter.UpstreamID > 0 {
		conditions = append(conditions, "upstream_id=?")
		args = append(args, filter.UpstreamID)
	}
	if filter.Endpoint != "" {
		if !filter.Endpoint.Valid() {
			return model.Page[*model.ClientProbeProfile]{}, model.WrapValidation("endpoint filter 无效")
		}
		conditions = append(conditions, "endpoint=?")
		args = append(args, filter.Endpoint)
	}
	if filter.Status != "" {
		if !validProfileStatus(filter.Status) {
			return model.Page[*model.ClientProbeProfile]{}, model.WrapValidation("profile status filter 无效")
		}
		conditions = append(conditions, "status=?")
		args = append(args, filter.Status)
	}
	if filter.ClientFamily != "" {
		conditions = append(conditions, "client_family=?")
		args = append(args, filter.ClientFamily)
	}
	if len(keys) == 1 {
		id, cursorErr := cursorID(keys[0])
		if cursorErr != nil {
			return model.Page[*model.ClientProbeProfile]{}, cursorErr
		}
		conditions = append(conditions, "id>?")
		args = append(args, id)
	}
	args = append(args, limit+1)
	rows, err := store.db.QueryContext(ctx, `SELECT `+clientProfileCols+` FROM client_probe_profile WHERE `+
		strings.Join(conditions, " AND ")+` ORDER BY id LIMIT ?`, args...)
	if err != nil {
		return model.Page[*model.ClientProbeProfile]{}, err
	}
	defer rows.Close()
	items := make([]*model.ClientProbeProfile, 0, limit+1)
	for rows.Next() {
		item, scanErr := scanClientProfile(rows)
		if scanErr != nil {
			return model.Page[*model.ClientProbeProfile]{}, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return model.Page[*model.ClientProbeProfile]{}, err
	}
	page := model.Page[*model.ClientProbeProfile]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextCursor, err = encodePageCursor("client-profiles", cursorFilter,
			strconv.FormatInt(page.Items[len(page.Items)-1].ID, 10))
		if err != nil {
			return model.Page[*model.ClientProbeProfile]{}, err
		}
	}
	return page, nil
}

func validProfileStatus(status model.ProbeProfileStatus) bool {
	return status == model.ProfileCandidate || status == model.ProfileTested || status == model.ProfileDisabled
}

// validateClientProfile 只校验 Store 侧不变量。请求形状本身（headers/body 是否
// 安全、是否可渲染）由 probetemplate 负责，这里不重复一套判断。
func validateClientProfile(profile *model.ClientProbeProfile) error {
	if profile == nil {
		return model.WrapValidation("client profile 不能为空")
	}
	if profile.UpstreamID < 1 || !profile.Endpoint.Valid() {
		return model.WrapValidation("client profile 的 upstream/endpoint 无效")
	}
	if profile.ClientFamily == "" || profile.ShapeHash == "" {
		return model.WrapValidation("client profile 必须带 client_family 与 shape_hash")
	}
	if profile.SeenCount < 1 {
		return model.WrapValidation("seen_count 必须 >= 1")
	}
	return nil
}

// CreateClientProfileCandidate 新建一个候选。永远建成 candidate：
// 从真实流量学到的形状没被探活验证过，不能直接当 tested 用。
func (store *Store) CreateClientProfileCandidate(ctx context.Context, profile *model.ClientProbeProfile) (err error) {
	if err := validateClientProfile(profile); err != nil {
		return err
	}
	headersJSON, err := json.Marshal(profile.SafeHeaders)
	if err != nil {
		return err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	now := nowMS()
	profile.Status = model.ProfileCandidate
	profile.Revision = 1
	profile.TestedExecutionID = ""
	profile.CreatedAt, profile.UpdatedAt = now, now
	if profile.LastSeenAt == 0 {
		profile.LastSeenAt = now
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO client_probe_profile
		(upstream_id,endpoint,status,safe_headers_json,fixed_raw_query,query_shape_json,body_template,
		 body_shape_json,client_family,shape_hash,revision,last_seen_at,seen_count,tested_execution_id,
		 created_at,updated_at) VALUES (?,?,'candidate',?,?,?,?,?,?,?,1,?,?,NULL,?,?)`,
		profile.UpstreamID, profile.Endpoint, string(headersJSON), profile.FixedRawQuery,
		profile.QueryShapeJSON, profile.BodyTemplate, profile.BodyShapeJSON, profile.ClientFamily,
		profile.ShapeHash, profile.LastSeenAt, profile.SeenCount, now, now)
	if err != nil {
		return wrapConstraint(err, "client_probe_profile")
	}
	if profile.ID, err = result.LastInsertId(); err != nil {
		return err
	}
	if err = replaceClientProfileSecretRefs(ctx, tx, profile); err != nil {
		return err
	}
	return tx.Commit()
}

// UpdateClientProfileCandidate 改候选的请求形状。只允许改 candidate：
// tested profile 正在被 Resolver 使用，改它等于悄悄换掉在服务的形状；
// 要改就先建新候选再重测发布。
func (store *Store) UpdateClientProfileCandidate(ctx context.Context, profile *model.ClientProbeProfile, expectedRevision int64) (err error) {
	if err := validateClientProfile(profile); err != nil {
		return err
	}
	if profile.ID < 1 || expectedRevision < 1 {
		return model.WrapValidation("client profile id/expected revision 无效")
	}
	headersJSON, err := json.Marshal(profile.SafeHeaders)
	if err != nil {
		return err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	current, err := scanClientProfile(tx.QueryRowContext(ctx, `SELECT `+clientProfileCols+
		` FROM client_probe_profile WHERE id=?`, profile.ID))
	if err != nil {
		return err
	}
	if current.Status != model.ProfileCandidate {
		return model.WrapValidation("只能修改 candidate profile，当前为 %s", current.Status)
	}
	now := nowMS()
	result, err := tx.ExecContext(ctx, `UPDATE client_probe_profile SET
		safe_headers_json=?,fixed_raw_query=?,query_shape_json=?,body_template=?,body_shape_json=?,
		client_family=?,shape_hash=?,revision=revision+1,updated_at=? WHERE id=? AND revision=?`,
		string(headersJSON), profile.FixedRawQuery, profile.QueryShapeJSON, profile.BodyTemplate,
		profile.BodyShapeJSON, profile.ClientFamily, profile.ShapeHash, now,
		profile.ID, expectedRevision)
	if err != nil {
		return wrapConstraint(err, "client_probe_profile")
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrRevisionConflict
	}
	profile.Status = current.Status
	profile.Revision = expectedRevision + 1
	profile.UpdatedAt = now
	profile.CreatedAt = current.CreatedAt
	profile.LastSeenAt, profile.SeenCount = current.LastSeenAt, current.SeenCount
	if err = replaceClientProfileSecretRefs(ctx, tx, profile); err != nil {
		return err
	}
	return tx.Commit()
}

// TouchClientProfile 记一次「又见到同样形状」。这是 telemetry，不是配置变更：
// 只动 last_seen_at/seen_count，绝不碰 revision —— 否则每来一个请求就会让
// 引用该 profile 的 Observation Token 失效，探活结论会被真实流量冲掉。
func (store *Store) TouchClientProfile(ctx context.Context, id int64, seenAtMS int64) error {
	if id < 1 || seenAtMS < 0 {
		return model.WrapValidation("client profile id/时间戳无效")
	}
	result, err := store.db.ExecContext(ctx, `UPDATE client_probe_profile
		SET last_seen_at=MAX(last_seen_at,?),seen_count=seen_count+1 WHERE id=?`, seenAtMS, id)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrNotFound
	}
	return nil
}

// MarkClientProfileTested 把候选提升为该 upstream+endpoint 的 tested fallback。
//
// executionID 必须是一次针对本 profile 的成功显式测试。旧的 tested 会先被降级
// 为 disabled 而不是删除：它可能还在被历史 execution 引用，且降级留痕比消失好查。
// 两步在同一事务内完成，partial unique index 保证中途不会出现两个 tested。
func (store *Store) MarkClientProfileTested(ctx context.Context, id int64, executionID string, expectedRevision int64) (err error) {
	if id < 1 || executionID == "" || expectedRevision < 1 {
		return model.WrapValidation("profile id/execution/expected revision 无效")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	profile, err := scanClientProfile(tx.QueryRowContext(ctx, `SELECT `+clientProfileCols+
		` FROM client_probe_profile WHERE id=?`, id))
	if err != nil {
		return err
	}
	if profile.Status == model.ProfileDisabled {
		return model.WrapValidation("disabled profile 不能直接发布，请先建新候选")
	}
	if err = requireProfileTestExecution(ctx, tx, profile, executionID); err != nil {
		return err
	}
	now := nowMS()
	// 先降级旧 tested，再升当前这条 —— 反过来会撞 partial unique index。
	demoted, err := tx.QueryContext(ctx, `SELECT id FROM client_probe_profile
		WHERE upstream_id=? AND endpoint=? AND status='tested' AND id!=?`,
		profile.UpstreamID, profile.Endpoint, id)
	if err != nil {
		return err
	}
	var demotedIDs []int64
	for demoted.Next() {
		var demotedID int64
		if err = demoted.Scan(&demotedID); err != nil {
			demoted.Close()
			return err
		}
		demotedIDs = append(demotedIDs, demotedID)
	}
	demoted.Close()
	if err = demoted.Err(); err != nil {
		return err
	}
	for _, demotedID := range demotedIDs {
		if _, err = tx.ExecContext(ctx, `UPDATE client_probe_profile
			SET status='disabled',revision=revision+1,updated_at=? WHERE id=?`, now, demotedID); err != nil {
			return err
		}
		// active ref 只跟随 tested binding：降级后立刻交出引用，
		// 否则被它引用的 Secret 会一直删不掉。
		if _, err = tx.ExecContext(ctx,
			`DELETE FROM client_profile_active_secret_ref WHERE client_profile_id=?`, demotedID); err != nil {
			return err
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE client_probe_profile
		SET status='tested',tested_execution_id=?,revision=revision+1,updated_at=?
		WHERE id=? AND revision=?`, executionID, now, id, expectedRevision)
	if err != nil {
		return wrapConstraint(err, "client_probe_profile")
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrRevisionConflict
	}
	profile.Status = model.ProfileTested
	profile.Revision = expectedRevision + 1
	if err = replaceClientProfileSecretRefs(ctx, tx, profile); err != nil {
		return err
	}
	return tx.Commit()
}

// requireProfileTestExecution 重验这次测试确实打的是本 profile 当前的形状。
// 只看 execution 自己记下的 target 与 profile identity：profile 在测试后被改过
// （revision 变了）就必须重测，不能拿旧结论发布新形状。
func requireProfileTestExecution(ctx context.Context, tx *sql.Tx, profile *model.ClientProbeProfile, executionID string) error {
	var upstreamID, profileID, identityRevision int64
	var endpoint, storage, bindingUse string
	var success bool
	if err := tx.QueryRowContext(ctx, `SELECT upstream_id,COALESCE(client_profile_id,0),
		recipe_identity_revision,endpoint,recipe_storage,recipe_binding_use,success
		FROM probe_execution WHERE id=?`, executionID).Scan(&upstreamID, &profileID,
		&identityRevision, &endpoint, &storage, &bindingUse, &success); errors.Is(err, sql.ErrNoRows) {
		return model.WrapValidation("测试用的 execution %q 不存在", executionID)
	} else if err != nil {
		return err
	}
	if !success {
		return model.WrapValidation("execution %q 未成功，不能作为发布依据", executionID)
	}
	if storage != string(model.RecipeStorageProfile) || bindingUse != string(model.BindingExplicitProfileTest) {
		return model.WrapValidation("execution %q 不是针对 profile 的显式测试", executionID)
	}
	if profileID != profile.ID || upstreamID != profile.UpstreamID || endpoint != string(profile.Endpoint) {
		return model.WrapValidation("execution %q 测的不是本 profile", executionID)
	}
	if identityRevision != profile.Revision {
		return model.WrapValidation("profile 在测试后已被修改（测试时 revision %d，现为 %d），请重测",
			identityRevision, profile.Revision)
	}
	return nil
}

// DisableClientProfile 停用一个 profile。不硬删：历史 execution 用 RESTRICT
// 外键指着它，且停用记录本身是排障线索。停用同时交出 active Secret 引用 ——
// 它已经不在服务，不该再挡住 Secret 删除。
func (store *Store) DisableClientProfile(ctx context.Context, id, expectedRevision int64) (err error) {
	if id < 1 || expectedRevision < 1 {
		return model.WrapValidation("profile id/expected revision 无效")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	result, err := tx.ExecContext(ctx, `UPDATE client_probe_profile
		SET status='disabled',revision=revision+1,updated_at=? WHERE id=? AND revision=?`,
		nowMS(), id, expectedRevision)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		// 分清「行不存在」与「revision 不匹配」：前者是 404，后者是 409。
		var exists int
		if err = tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM client_probe_profile WHERE id=?`, id).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			return ErrNotFound
		}
		return ErrRevisionConflict
	}
	if _, err = tx.ExecContext(ctx,
		`DELETE FROM client_profile_active_secret_ref WHERE client_profile_id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// replaceClientProfileSecretRefs 重写该 profile 的 Secret 引用。
//
// required_secret 是每条 profile 都要有的快照（它记录测试时绑定的是哪个
// Secret，便于事后核对）；active_secret_ref 只跟随 tested binding —— 候选
// 还没在服务，把它的引用记成 active 会让「引用中的 Secret 不能删除」
// 误伤一堆从未发布的候选。
func replaceClientProfileSecretRefs(ctx context.Context, tx *sql.Tx, profile *model.ClientProbeProfile) error {
	required, err := probetemplate.ScanRequiredSecrets(profile.Endpoint, probetemplate.TemplateContent{
		Method:   profile.Endpoint.Method(),
		RawQuery: profile.FixedRawQuery,
		Headers:  profile.SafeHeaders,
		Body:     profile.BodyTemplate,
	})
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM client_profile_active_secret_ref WHERE client_profile_id=?`, profile.ID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM client_profile_required_secret WHERE client_profile_id=?`, profile.ID); err != nil {
		return err
	}
	active := profile.Status == model.ProfileTested
	for _, name := range required {
		var secretID, revision int64
		var fingerprint string
		if err := tx.QueryRowContext(ctx, `SELECT id,revision,fingerprint FROM probe_secret WHERE name=?`,
			name).Scan(&secretID, &revision, &fingerprint); errors.Is(err, sql.ErrNoRows) {
			return model.WrapValidation("profile 引用的 Secret %q 不存在", name)
		} else if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO client_profile_required_secret
			(client_profile_id,name,resolved_secret_id,bound_secret_id_snapshot,bound_revision_snapshot,
			 bound_fingerprint_snapshot,bound_name_snapshot) VALUES (?,?,?,?,?,?,?)`,
			profile.ID, name, secretID, secretID, revision, fingerprint, name); err != nil {
			return err
		}
		if !active {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO client_profile_active_secret_ref
			(client_profile_id,secret_id,name,revision) VALUES (?,?,?,?)`,
			profile.ID, secretID, name, revision); err != nil {
			return err
		}
	}
	return nil
}
