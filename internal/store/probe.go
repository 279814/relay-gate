package store

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

func (store *Store) CreateProbeSecret(name string, plain []byte) (*model.ProbeSecret, error) {
	if !validProbeSecretName(name) || len(plain) == 0 {
		return nil, model.WrapValidation("Secret name/value 无效")
	}
	encrypted, err := store.cipher.Encrypt(string(plain))
	if err != nil {
		return nil, err
	}
	now := nowMS()
	secret := &model.ProbeSecret{
		Name: name, Masked: MaskKey(string(plain)),
		Fingerprint: store.cipher.Fingerprint("probe-secret", plain),
		Revision:    1, CreatedAt: now, UpdatedAt: now,
	}
	result, err := store.db.Exec(`INSERT INTO probe_secret
		(name,value_enc,masked,fingerprint,revision,created_at,updated_at) VALUES (?,?,?,?,1,?,?)`,
		secret.Name, encrypted, secret.Masked, secret.Fingerprint, now, now)
	if err != nil {
		return nil, wrapConstraint(err, "probe_secret")
	}
	secret.ID, err = result.LastInsertId()
	return secret, err
}

func (store *Store) UpdateProbeSecret(id int64, expectedRevision int64, plain []byte) (*model.ProbeSecret, error) {
	if len(plain) == 0 || expectedRevision < 1 {
		return nil, model.WrapValidation("Secret value/expected revision 无效")
	}
	encrypted, err := store.cipher.Encrypt(string(plain))
	if err != nil {
		return nil, err
	}
	masked := MaskKey(string(plain))
	fingerprint := store.cipher.Fingerprint("probe-secret", plain)
	now := nowMS()
	result, err := store.db.Exec(`UPDATE probe_secret SET value_enc=?,masked=?,fingerprint=?,
		revision=revision+1,updated_at=? WHERE id=? AND revision=?`,
		encrypted, masked, fingerprint, now, id, expectedRevision)
	if err != nil {
		return nil, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		var exists int
		if scanErr := store.db.QueryRow(`SELECT COUNT(*) FROM probe_secret WHERE id=?`, id).Scan(&exists); scanErr != nil {
			return nil, scanErr
		}
		if exists == 0 {
			return nil, ErrNotFound
		}
		return nil, ErrRevisionConflict
	}
	var secret model.ProbeSecret
	if err := store.db.QueryRow(`SELECT id,name,masked,fingerprint,revision,created_at,updated_at
		FROM probe_secret WHERE id=?`, id).Scan(&secret.ID, &secret.Name, &secret.Masked,
		&secret.Fingerprint, &secret.Revision, &secret.CreatedAt, &secret.UpdatedAt); err != nil {
		return nil, err
	}
	return &secret, nil
}

func (store *Store) ResolveProbeSecret(ctx context.Context, name string) (probetemplate.ResolvedSecret, error) {
	var result probetemplate.ResolvedSecret
	var encrypted string
	if err := store.db.QueryRowContext(ctx, `SELECT id,value_enc,revision FROM probe_secret WHERE name=?`, name).
		Scan(&result.ID, &encrypted, &result.Revision); errors.Is(err, sql.ErrNoRows) {
		return result, ErrNotFound
	} else if err != nil {
		return result, err
	}
	plain, err := store.cipher.Decrypt(encrypted)
	if err != nil {
		return result, err
	}
	result.Plain = []byte(plain)
	return result, nil
}

func (store *Store) DeleteProbeSecret(id int64, expectedRevision int64) error {
	result, err := store.db.Exec(`DELETE FROM probe_secret WHERE id=? AND revision=?`, id, expectedRevision)
	if err != nil {
		if strings.Contains(err.Error(), "FOREIGN KEY constraint failed") {
			return ErrDependencyConflict
		}
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 1 {
		return nil
	}
	var exists int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM probe_secret WHERE id=?`, id).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return ErrNotFound
	}
	return ErrRevisionConflict
}

func (store *Store) ListProbeSecretsPage(ctx context.Context, filter model.ProbeSecretFilter) (model.Page[*model.ProbeSecret], error) {
	limit, err := normalizePageLimit(filter.Limit)
	if err != nil {
		return model.Page[*model.ProbeSecret]{}, err
	}
	cursorFilter := filter
	cursorFilter.PageRequest = model.PageRequest{}
	keys, err := decodePageCursor(filter.Cursor, "probe-secrets", cursorFilter, 2)
	if err != nil {
		return model.Page[*model.ProbeSecret]{}, err
	}
	conditions := []string{"1=1"}
	args := make([]any, 0, 5)
	if filter.NamePrefix != "" {
		conditions = append(conditions, `name>=? AND name<?`)
		args = append(args, filter.NamePrefix, filter.NamePrefix+"\U0010ffff")
	}
	if len(keys) == 2 {
		id, parseErr := strconv.ParseInt(keys[1], 10, 64)
		if parseErr != nil || id < 1 {
			return model.Page[*model.ProbeSecret]{}, ErrInvalidCursor
		}
		conditions = append(conditions, `(name>? OR (name=? AND id>?))`)
		args = append(args, keys[0], keys[0], id)
	}
	args = append(args, limit+1)
	// Deliberately omit value_enc: list access must never fetch ciphertext.
	rows, err := store.db.QueryContext(ctx, `SELECT id,name,masked,fingerprint,revision,created_at,updated_at
		FROM probe_secret WHERE `+strings.Join(conditions, " AND ")+` ORDER BY name,id LIMIT ?`, args...)
	if err != nil {
		return model.Page[*model.ProbeSecret]{}, err
	}
	defer rows.Close()
	items := make([]*model.ProbeSecret, 0, limit+1)
	for rows.Next() {
		var item model.ProbeSecret
		if err := rows.Scan(&item.ID, &item.Name, &item.Masked, &item.Fingerprint,
			&item.Revision, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return model.Page[*model.ProbeSecret]{}, err
		}
		items = append(items, &item)
	}
	if err := rows.Err(); err != nil {
		return model.Page[*model.ProbeSecret]{}, err
	}
	page := model.Page[*model.ProbeSecret]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor, err = encodePageCursor("probe-secrets", cursorFilter, last.Name, strconv.FormatInt(last.ID, 10))
		if err != nil {
			return model.Page[*model.ProbeSecret]{}, err
		}
	}
	return page, nil
}

func validProbeSecretName(name string) bool {
	if name == "" {
		return false
	}
	for _, char := range []byte(name) {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || strings.ContainsRune("-_.", rune(char)) {
			continue
		}
		return false
	}
	return true
}

func (store *Store) CreateRecipe(scope model.RecipeScope, scopeID int64, endpoint model.EndpointKind) (int64, error) {
	if !scope.Valid() || scopeID < 1 || !endpoint.Valid() {
		return 0, model.WrapValidation("recipe scope/endpoint 无效")
	}
	upstreamID, routeID := nullableScopeIDs(scope, scopeID)
	now := nowMS()
	result, err := store.db.Exec(`INSERT INTO probe_recipe
		(upstream_id,route_id,endpoint,status,pinned,revision,active_binding_revision,created_at,updated_at)
		VALUES (?,?,?,'draft',0,1,1,?,?)`, upstreamID, routeID, endpoint, now, now)
	if err != nil {
		return 0, wrapConstraint(err, "probe_recipe")
	}
	return result.LastInsertId()
}

const recipeCols = `id,upstream_id,route_id,endpoint,status,pinned,
	COALESCE(draft_version_id,0),COALESCE(published_version_id,0),last_publish_forced,
	COALESCE(last_test_execution_id,''),published_at,revision,active_binding_revision,created_at,updated_at`

func (store *Store) GetRecipe(ctx context.Context, id int64) (*model.ProbeRecipe, error) {
	return scanProbeRecipe(store.db.QueryRowContext(ctx, `SELECT `+recipeCols+
		` FROM probe_recipe WHERE id=?`, id))
}

func (store *Store) ListRecipesPage(ctx context.Context, filter model.RecipeFilter) (model.Page[*model.ProbeRecipe], error) {
	limit, err := normalizePageLimit(filter.Limit)
	if err != nil {
		return model.Page[*model.ProbeRecipe]{}, err
	}
	cursorFilter := filter
	cursorFilter.PageRequest = model.PageRequest{}
	keys, err := decodePageCursor(filter.Cursor, "recipes", cursorFilter, 1)
	if err != nil {
		return model.Page[*model.ProbeRecipe]{}, err
	}
	conditions := []string{"1=1"}
	args := make([]any, 0, 6)
	if filter.UpstreamID > 0 {
		conditions = append(conditions, "upstream_id=?")
		args = append(args, filter.UpstreamID)
	}
	if filter.RouteID > 0 {
		conditions = append(conditions, "route_id=?")
		args = append(args, filter.RouteID)
	}
	if filter.Endpoint != "" {
		if !filter.Endpoint.Valid() {
			return model.Page[*model.ProbeRecipe]{}, model.WrapValidation("endpoint filter 无效")
		}
		conditions = append(conditions, "endpoint=?")
		args = append(args, filter.Endpoint)
	}
	if filter.Status != "" {
		if !filter.Status.Valid() {
			return model.Page[*model.ProbeRecipe]{}, model.WrapValidation("recipe status filter 无效")
		}
		conditions = append(conditions, "status=?")
		args = append(args, filter.Status)
	}
	if len(keys) == 1 {
		id, cursorErr := cursorID(keys[0])
		if cursorErr != nil {
			return model.Page[*model.ProbeRecipe]{}, cursorErr
		}
		conditions = append(conditions, "id>?")
		args = append(args, id)
	}
	args = append(args, limit+1)
	rows, err := store.db.QueryContext(ctx, `SELECT `+recipeCols+` FROM probe_recipe WHERE `+
		strings.Join(conditions, " AND ")+` ORDER BY id LIMIT ?`, args...)
	if err != nil {
		return model.Page[*model.ProbeRecipe]{}, err
	}
	defer rows.Close()
	items := make([]*model.ProbeRecipe, 0, limit+1)
	for rows.Next() {
		item, scanErr := scanProbeRecipe(rows)
		if scanErr != nil {
			return model.Page[*model.ProbeRecipe]{}, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return model.Page[*model.ProbeRecipe]{}, err
	}
	page := model.Page[*model.ProbeRecipe]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextCursor, err = encodePageCursor("recipes", cursorFilter,
			strconv.FormatInt(page.Items[len(page.Items)-1].ID, 10))
		if err != nil {
			return model.Page[*model.ProbeRecipe]{}, err
		}
	}
	return page, nil
}

func scanProbeRecipe(scanner interface{ Scan(...any) error }) (*model.ProbeRecipe, error) {
	var recipe model.ProbeRecipe
	var upstreamID, routeID sql.NullInt64
	if err := scanner.Scan(&recipe.ID, &upstreamID, &routeID, &recipe.Endpoint, &recipe.Status,
		&recipe.Pinned, &recipe.DraftVersionID, &recipe.PublishedVersionID,
		&recipe.LastPublishForced, &recipe.LastTestExecutionID, &recipe.PublishedAt,
		&recipe.Revision, &recipe.ActiveBindingRevision, &recipe.CreatedAt, &recipe.UpdatedAt); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	if upstreamID.Valid {
		recipe.ScopeType, recipe.ScopeID = model.RecipeScopeUpstream, upstreamID.Int64
	} else {
		recipe.ScopeType, recipe.ScopeID = model.RecipeScopeRoute, routeID.Int64
	}
	return &recipe, nil
}

const recipeVersionCols = `id,recipe_id,version,origin,method,fixed_raw_query,headers_json,
	body,body_is_text,stream_expected,timeout_profile,created_at`

func scanRecipeVersion(scanner interface{ Scan(...any) error }) (*model.ProbeRecipeVersion, error) {
	var version model.ProbeRecipeVersion
	var headersJSON string
	if err := scanner.Scan(&version.ID, &version.RecipeID, &version.Version, &version.Origin,
		&version.Method, &version.FixedRawQuery, &headersJSON, &version.Body, &version.BodyIsText,
		&version.StreamExpected, &version.TimeoutProfile, &version.CreatedAt); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(headersJSON), &version.Headers); err != nil {
		return nil, fmt.Errorf("recipe version %d 的 headers_json: %w", version.ID, err)
	}
	return &version, nil
}

func (store *Store) GetRecipeVersion(ctx context.Context, id int64) (*model.ProbeRecipeVersion, error) {
	return scanRecipeVersion(store.db.QueryRowContext(ctx, `SELECT `+recipeVersionCols+
		` FROM probe_recipe_version WHERE id=?`, id))
}

// ListRecipeVersionsPage 按 (version, id) 升序翻页，走 idx_recipe_version_recipe_version_id。
// version 在同一 recipe 内唯一，但 filter 允许跨 recipe，故仍要 id 兜底做 tie-breaker。
func (store *Store) ListRecipeVersionsPage(ctx context.Context, filter model.RecipeVersionFilter) (model.Page[*model.ProbeRecipeVersion], error) {
	limit, err := normalizePageLimit(filter.Limit)
	if err != nil {
		return model.Page[*model.ProbeRecipeVersion]{}, err
	}
	cursorFilter := filter
	cursorFilter.PageRequest = model.PageRequest{}
	keys, err := decodePageCursor(filter.Cursor, "recipe-versions", cursorFilter, 2)
	if err != nil {
		return model.Page[*model.ProbeRecipeVersion]{}, err
	}
	conditions := []string{"1=1"}
	args := make([]any, 0, 6)
	if filter.RecipeID > 0 {
		conditions = append(conditions, "recipe_id=?")
		args = append(args, filter.RecipeID)
	}
	if filter.Origin != "" {
		if !filter.Origin.Valid() {
			return model.Page[*model.ProbeRecipeVersion]{}, model.WrapValidation("recipe origin filter 无效")
		}
		conditions = append(conditions, "origin=?")
		args = append(args, filter.Origin)
	}
	if len(keys) == 2 {
		version, parseErr := strconv.Atoi(keys[0])
		if parseErr != nil || version < 1 {
			return model.Page[*model.ProbeRecipeVersion]{}, ErrInvalidCursor
		}
		id, cursorErr := cursorID(keys[1])
		if cursorErr != nil {
			return model.Page[*model.ProbeRecipeVersion]{}, cursorErr
		}
		conditions = append(conditions, "(version>? OR (version=? AND id>?))")
		args = append(args, version, version, id)
	}
	args = append(args, limit+1)
	rows, err := store.db.QueryContext(ctx, `SELECT `+recipeVersionCols+` FROM probe_recipe_version WHERE `+
		strings.Join(conditions, " AND ")+` ORDER BY version,id LIMIT ?`, args...)
	if err != nil {
		return model.Page[*model.ProbeRecipeVersion]{}, err
	}
	defer rows.Close()
	items := make([]*model.ProbeRecipeVersion, 0, limit+1)
	for rows.Next() {
		item, scanErr := scanRecipeVersion(rows)
		if scanErr != nil {
			return model.Page[*model.ProbeRecipeVersion]{}, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return model.Page[*model.ProbeRecipeVersion]{}, err
	}
	page := model.Page[*model.ProbeRecipeVersion]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor, err = encodePageCursor("recipe-versions", cursorFilter,
			strconv.Itoa(last.Version), strconv.FormatInt(last.ID, 10))
		if err != nil {
			return model.Page[*model.ProbeRecipeVersion]{}, err
		}
	}
	return page, nil
}

func (store *Store) AddRecipeVersion(version *model.ProbeRecipeVersion, expectedRecipeRevision int64) (err error) {
	if version == nil || expectedRecipeRevision < 1 {
		return model.WrapValidation("recipe version/expected revision 无效")
	}
	tx, err := store.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	recipe, err := scanProbeRecipe(tx.QueryRow(`SELECT ` + recipeCols +
		` FROM probe_recipe WHERE id=?`, version.RecipeID))
	if err != nil {
		return err
	}
	if recipe.Revision != expectedRecipeRevision || recipe.Status == model.RecipeArchived {
		return ErrRevisionConflict
	}
	if err := version.ValidateForEndpoint(recipe.Endpoint); err != nil {
		return err
	}
	if !version.Origin.Valid() {
		return model.WrapValidation("recipe origin 无效")
	}
	required, err := probetemplate.ScanRequiredSecrets(recipe.Endpoint, probetemplate.TemplateContent{
		Method: version.Method, RawQuery: version.FixedRawQuery, Headers: version.Headers, Body: version.Body,
	})
	if err != nil {
		return err
	}
	var nextVersion int
	if err := tx.QueryRow(`SELECT COALESCE(MAX(version),0)+1 FROM probe_recipe_version WHERE recipe_id=?`, recipe.ID).Scan(&nextVersion); err != nil {
		return err
	}
	headersJSON, err := json.Marshal(version.Headers)
	if err != nil {
		return err
	}
	version.Version = nextVersion
	version.CreatedAt = nowMS()
	result, err := tx.Exec(`INSERT INTO probe_recipe_version
		(recipe_id,version,origin,method,fixed_raw_query,headers_json,body,body_is_text,
		 stream_expected,timeout_profile,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		version.RecipeID, version.Version, version.Origin, version.Method, version.FixedRawQuery,
		string(headersJSON), version.Body, version.BodyIsText, version.StreamExpected,
		version.TimeoutProfile, version.CreatedAt)
	if err != nil {
		return err
	}
	version.ID, err = result.LastInsertId()
	if err != nil {
		return err
	}
	for _, name := range required {
		var id, revision int64
		var fingerprint string
		if err := tx.QueryRow(`SELECT id,revision,fingerprint FROM probe_secret WHERE name=?`, name).
			Scan(&id, &revision, &fingerprint); errors.Is(err, sql.ErrNoRows) {
			return model.WrapValidation("Recipe 引用的 Secret %q 不存在", name)
		} else if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO recipe_version_required_secret
			(recipe_version_id,name,resolved_secret_id,bound_secret_id_snapshot,bound_revision_snapshot,
			 bound_fingerprint_snapshot,bound_name_snapshot) VALUES (?,?,?,?,?,?,?)`,
			version.ID, name, id, id, revision, fingerprint, name); err != nil {
			return err
		}
	}
	update, err := tx.Exec(`UPDATE probe_recipe SET draft_version_id=?,revision=revision+1,updated_at=?
		WHERE id=? AND revision=?`, version.ID, version.CreatedAt, recipe.ID, expectedRecipeRevision)
	if err != nil {
		return err
	}
	if affected, _ := update.RowsAffected(); affected != 1 {
		return ErrRevisionConflict
	}
	return tx.Commit()
}

func (store *Store) ArchiveRecipe(ctx context.Context, recipeID, expectedRevision int64) error {
	result, err := store.db.ExecContext(ctx, `UPDATE probe_recipe SET status='archived',
		revision=revision+1,active_binding_revision=active_binding_revision+1,updated_at=?
		WHERE id=? AND revision=? AND status!='archived'`, nowMS(), recipeID, expectedRevision)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		var exists int
		if err := store.db.QueryRow(`SELECT COUNT(*) FROM probe_recipe WHERE id=?`, recipeID).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			return ErrNotFound
		}
		return ErrRevisionConflict
	}
	return nil
}

func (store *Store) DisableRecipe(ctx context.Context, recipeID, expectedRevision int64) error {
	result, err := store.db.ExecContext(ctx, `UPDATE probe_recipe SET status='disabled',
		revision=revision+1,active_binding_revision=active_binding_revision+1,updated_at=?
		WHERE id=? AND revision=? AND status!='archived'`, nowMS(), recipeID, expectedRevision)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrRevisionConflict
	}
	return nil
}
