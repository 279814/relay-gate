package store

// ConfigBundle 是一次 SQLite 只读事务读出的全部 routing+probe 配置行（§4.9）。
//
// Source 在事务结束后仅从这一份 rows 构建 routing/Probe 两张快照，完成校验
// 和深拷贝后才分配同一个新 Generation。因此并发管理员提交只能让一次 Refresh
// 得到全旧或全新，不能得到从未存在过的混合配置。

import (
	"context"
	"database/sql"
	"errors"

	"github.com/279814/relay-gate/internal/model"
)

// ConfigBundle 只含本次读事务拥有的深拷贝行；不含 Secret/API Key/legacy URL 明文。
type ConfigBundle struct {
	ModelNames              []*model.ModelName
	Upstreams               []*model.Upstream
	Routes                  []*model.Route
	Settings                model.Settings
	SettingsRowRevision     int64
	RunState                RunState
	Endpoints               []*model.UpstreamEndpoint
	LegacyFullURLs          []*model.LegacyFullURL
	Recipes                 []*model.ProbeRecipe
	RecipeVersions          []*model.ProbeRecipeVersion
	ClientProfiles          []*model.ClientProbeProfile
	SecretRevisions         []model.SecretRevision
	EndpointSecretRefs      map[int64][]model.RequiredSecretRef
	RecipeVersionSecretRefs map[int64][]model.RequiredSecretRef
	ClientProfileSecretRefs map[int64][]model.RequiredSecretRef
}

// LoadConfigBundle 在同一个 SQLite 只读事务中取得全部 routing+probe rows。
//
// 不得让 Source.load 逐表调用普通 List 方法拼装——那会在表与表之间露出
// 并发提交窗口，发布出从未存在过的混合快照。
func (store *Store) LoadConfigBundle(ctx context.Context) (*ConfigBundle, error) {
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	bundle := &ConfigBundle{
		EndpointSecretRefs:      map[int64][]model.RequiredSecretRef{},
		RecipeVersionSecretRefs: map[int64][]model.RequiredSecretRef{},
		ClientProfileSecretRefs: map[int64][]model.RequiredSecretRef{},
	}

	if bundle.ModelNames, err = loadBundleModelNames(ctx, tx); err != nil {
		return nil, err
	}
	if bundle.Upstreams, err = store.loadBundleUpstreams(ctx, tx); err != nil {
		return nil, err
	}
	if bundle.Routes, err = loadBundleRoutes(ctx, tx); err != nil {
		return nil, err
	}
	if bundle.Settings, bundle.SettingsRowRevision, err = loadBundleSettings(ctx, tx); err != nil {
		return nil, err
	}
	if bundle.RunState, err = loadBundleRunState(ctx, tx); err != nil {
		return nil, err
	}
	if bundle.Endpoints, err = loadBundleEndpoints(ctx, tx); err != nil {
		return nil, err
	}
	if bundle.LegacyFullURLs, err = loadBundleLegacyURLs(ctx, tx); err != nil {
		return nil, err
	}
	if bundle.Recipes, err = loadBundleRecipes(ctx, tx); err != nil {
		return nil, err
	}
	if bundle.RecipeVersions, err = loadBundleRecipeVersions(ctx, tx); err != nil {
		return nil, err
	}
	if bundle.ClientProfiles, err = loadBundleClientProfiles(ctx, tx); err != nil {
		return nil, err
	}
	if bundle.SecretRevisions, err = loadBundleSecretRevisions(ctx, tx); err != nil {
		return nil, err
	}
	if bundle.EndpointSecretRefs, err = loadBundleEndpointSecretRefs(ctx, tx); err != nil {
		return nil, err
	}
	if bundle.RecipeVersionSecretRefs, err = loadBundleRecipeVersionSecretRefs(ctx, tx); err != nil {
		return nil, err
	}
	if bundle.ClientProfileSecretRefs, err = loadBundleClientProfileSecretRefs(ctx, tx); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return bundle, nil
}

func loadBundleModelNames(ctx context.Context, tx *sql.Tx) ([]*model.ModelName, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+modelNameCols+` FROM model_name ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*model.ModelName{}
	for rows.Next() {
		m, err := scanModelName(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (store *Store) loadBundleUpstreams(ctx context.Context, tx *sql.Tx) ([]*model.Upstream, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+upstreamCols+` FROM upstream ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*model.Upstream{}
	for rows.Next() {
		// 解密只服务 routing 快照的出站鉴权；ProbeSnapshot 构建时会剥掉明文。
		u, err := store.scanUpstream(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func loadBundleRoutes(ctx context.Context, tx *sql.Tx) ([]*model.Route, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+routeCols+` FROM route ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*model.Route{}
	for rows.Next() {
		r, err := scanRoute(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func loadBundleSettings(ctx context.Context, tx *sql.Tx) (model.Settings, int64, error) {
	var raw string
	var revision int64
	err := tx.QueryRowContext(ctx, `SELECT value, revision FROM setting WHERE key=?`, keySettings).
		Scan(&raw, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		return model.DefaultSettings(), 0, nil
	}
	if err != nil {
		return model.Settings{}, 0, err
	}
	settings, err := usableSettings(DecodeLegacySettings([]byte(raw)))
	if err != nil {
		return model.Settings{}, 0, err
	}
	return settings, revision, nil
}

func loadBundleRunState(ctx context.Context, tx *sql.Tx) (RunState, error) {
	var raw string
	err := tx.QueryRowContext(ctx, `SELECT value FROM setting WHERE key=?`, keyRunState).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return StateRunning, nil
	}
	if err != nil {
		return "", err
	}
	state := RunState(raw)
	if state != StateRunning && state != StatePaused {
		return StateRunning, nil
	}
	return state, nil
}

func loadBundleEndpoints(ctx context.Context, tx *sql.Tx) ([]*model.UpstreamEndpoint, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+endpointColumns+` FROM upstream_endpoint ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*model.UpstreamEndpoint{}
	for rows.Next() {
		ep, err := scanEndpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ep)
	}
	return out, rows.Err()
}

func loadBundleLegacyURLs(ctx context.Context, tx *sql.Tx) ([]*model.LegacyFullURL, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,upstream_id,masked_url,fingerprint,
		COALESCE(inferred_endpoint,''),revision,needs_review FROM legacy_full_url ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*model.LegacyFullURL{}
	for rows.Next() {
		var row model.LegacyFullURL
		var inferred string
		if err := rows.Scan(&row.ID, &row.UpstreamID, &row.MaskedURL, &row.Fingerprint,
			&inferred, &row.Revision, &row.NeedsReview); err != nil {
			return nil, err
		}
		row.InferredEndpoint = model.EndpointKind(inferred)
		out = append(out, &row)
	}
	return out, rows.Err()
}

func loadBundleRecipes(ctx context.Context, tx *sql.Tx) ([]*model.ProbeRecipe, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+recipeCols+` FROM probe_recipe ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*model.ProbeRecipe{}
	for rows.Next() {
		recipe, err := scanProbeRecipe(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, recipe)
	}
	return out, rows.Err()
}

func loadBundleRecipeVersions(ctx context.Context, tx *sql.Tx) ([]*model.ProbeRecipeVersion, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+recipeVersionCols+` FROM probe_recipe_version ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*model.ProbeRecipeVersion{}
	for rows.Next() {
		version, err := scanRecipeVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, version)
	}
	return out, rows.Err()
}

func loadBundleClientProfiles(ctx context.Context, tx *sql.Tx) ([]*model.ClientProbeProfile, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+clientProfileCols+` FROM client_probe_profile ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*model.ClientProbeProfile{}
	for rows.Next() {
		profile, err := scanClientProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, profile)
	}
	return out, rows.Err()
}

func loadBundleSecretRevisions(ctx context.Context, tx *sql.Tx) ([]model.SecretRevision, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,name,revision FROM probe_secret ORDER BY name,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.SecretRevision{}
	for rows.Next() {
		var rev model.SecretRevision
		if err := rows.Scan(&rev.ID, &rev.Name, &rev.Revision); err != nil {
			return nil, err
		}
		rev.Resolved = true
		out = append(out, rev)
	}
	return out, rows.Err()
}

func loadBundleEndpointSecretRefs(ctx context.Context, tx *sql.Tx) (map[int64][]model.RequiredSecretRef, error) {
	rows, err := tx.QueryContext(ctx, `SELECT endpoint_id,name,secret_id FROM endpoint_active_secret_ref ORDER BY endpoint_id,name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]model.RequiredSecretRef{}
	for rows.Next() {
		var endpointID, secretID int64
		var name string
		if err := rows.Scan(&endpointID, &name, &secretID); err != nil {
			return nil, err
		}
		out[endpointID] = append(out[endpointID], model.RequiredSecretRef{Name: name, BoundSecretID: secretID})
	}
	return out, rows.Err()
}

func loadBundleRecipeVersionSecretRefs(ctx context.Context, tx *sql.Tx) (map[int64][]model.RequiredSecretRef, error) {
	rows, err := tx.QueryContext(ctx, `SELECT recipe_version_id,name,bound_secret_id_snapshot
		FROM recipe_version_required_secret
		WHERE bound_secret_id_snapshot IS NOT NULL AND bound_secret_id_snapshot>0
		ORDER BY recipe_version_id,name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]model.RequiredSecretRef{}
	for rows.Next() {
		var versionID, secretID int64
		var name string
		if err := rows.Scan(&versionID, &name, &secretID); err != nil {
			return nil, err
		}
		out[versionID] = append(out[versionID], model.RequiredSecretRef{Name: name, BoundSecretID: secretID})
	}
	return out, rows.Err()
}

func loadBundleClientProfileSecretRefs(ctx context.Context, tx *sql.Tx) (map[int64][]model.RequiredSecretRef, error) {
	rows, err := tx.QueryContext(ctx, `SELECT client_profile_id,name,secret_id
		FROM client_profile_active_secret_ref ORDER BY client_profile_id,name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]model.RequiredSecretRef{}
	for rows.Next() {
		var profileID, secretID int64
		var name string
		if err := rows.Scan(&profileID, &name, &secretID); err != nil {
			return nil, err
		}
		out[profileID] = append(out[profileID], model.RequiredSecretRef{Name: name, BoundSecretID: secretID})
	}
	return out, rows.Err()
}
