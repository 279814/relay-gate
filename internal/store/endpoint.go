package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probetemplate"
)

const endpointColumns = `id,upstream_id,endpoint,url_mode,COALESCE(legacy_full_url_id,0),
	legacy_full_url_revision,legacy_compat_real_only,url_override,fixed_query_template,
	auth_mode,calibrated_mode,auth_header_name,auth_query_name,auth_secret_ref,
	auth_manual_headers_json,auth_profile_revision,revision,needs_review,created_at,updated_at`

func canonicalEndpointBundle(upstream *model.Upstream) []*model.UpstreamEndpoint {
	authMode, headerName := legacyAuthProfile(upstream.AuthStyle)
	realOnly := authMode == model.AuthModeLegacyAutoRealOnly
	result := make([]*model.UpstreamEndpoint, 0, 5)
	for _, kind := range []model.EndpointKind{
		model.EndpointModels,
		model.EndpointMessages,
		model.EndpointResponses,
		model.EndpointChatCompletions,
		model.EndpointCountTokens,
	} {
		result = append(result, &model.UpstreamEndpoint{
			UpstreamID: upstream.ID,
			Kind:       kind,
			URLMode:    model.EndpointURLCanonical,
			// full_url_mode 与自定义 l1_path 必须在创建时就落到 url_override 上。
			// 只在 UpdateUpstream 里翻译的话，一个**新建**的 full_url_mode 站
			// 会被 Resolver 拼成 base+/v1/messages —— 而这个开关的全部用途
			// 恰恰是「不要拼路径」。
			URLOverride:          upstream.EndpointURLOverride(kind),
			LegacyCompatRealOnly: realOnly,
			AuthProfile: model.EndpointAuthProfile{
				Mode:       authMode,
				HeaderName: headerName,
				SecretRef:  "upstream_api_key",
				Revision:   1,
			},
			Revision: 1,
		})
	}
	return result
}

func (store *Store) CreateUpstreamWithEndpoints(ctx context.Context, upstream *model.Upstream, endpoints []*model.UpstreamEndpoint) (err error) {
	upstream.Defaults()
	if err := upstream.Validate(); err != nil {
		return err
	}
	if upstream.APIKey == "" {
		return model.WrapValidation("api_key 不能为空")
	}
	if err := validateCanonicalEndpointBundle(endpoints); err != nil {
		return err
	}
	encrypted, err := store.cipher.Encrypt(upstream.APIKey)
	if err != nil {
		return err
	}
	headersJSON, err := marshalHeaders(upstream.ProbeHeaders)
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
	upstream.CreatedAt = nowMS()
	upstream.UpdatedAt = upstream.CreatedAt
	upstream.Revision = 1
	upstream.NetworkRevision = 1
	upstream.CredentialRevision = 1
	result, err := tx.ExecContext(ctx, `INSERT INTO upstream
		(name,base_url,api_key_enc,auth_style,full_url_mode,proxy_url,enabled,l1_path,
		 probe_headers,created_at,updated_at,probe_mode,host_override,tls_server_name,
		 revision,network_revision,credential_revision)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,1,1)`,
		upstream.Name, upstream.BaseURL, encrypted, upstream.AuthStyle, upstream.FullURLMode,
		upstream.ProxyURL, upstream.Enabled, upstream.L1Path, headersJSON, upstream.CreatedAt,
		upstream.UpdatedAt, upstream.ProbeMode, upstream.HostOverride, upstream.TLSServerName)
	if err != nil {
		return wrapConstraint(err, "upstream")
	}
	upstream.ID, err = result.LastInsertId()
	if err != nil {
		return err
	}
	for _, endpoint := range endpoints {
		endpoint.UpstreamID = upstream.ID
		if endpoint.URLMode == "" {
			endpoint.URLMode = model.EndpointURLCanonical
		}
		if endpoint.AuthProfile.SecretRef == "" {
			endpoint.AuthProfile.SecretRef = "upstream_api_key"
		}
		if endpoint.Revision == 0 {
			endpoint.Revision = 1
		}
		if endpoint.AuthProfile.Revision == 0 {
			endpoint.AuthProfile.Revision = 1
		}
		endpoint.CreatedAt = upstream.CreatedAt
		endpoint.UpdatedAt = upstream.UpdatedAt
		if err := endpoint.Validate(); err != nil {
			return err
		}
		if err := insertEndpointTx(ctx, tx, endpoint); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}

func validateCanonicalEndpointBundle(endpoints []*model.UpstreamEndpoint) error {
	if len(endpoints) != 5 {
		return model.WrapValidation("Upstream 必须同时配置五个 Endpoint")
	}
	seen := make(map[model.EndpointKind]struct{}, 5)
	for _, endpoint := range endpoints {
		if endpoint == nil || !endpoint.Kind.Valid() {
			return model.WrapValidation("Endpoint 配置无效")
		}
		if _, exists := seen[endpoint.Kind]; exists {
			return model.WrapValidation("Endpoint %s 重复", endpoint.Kind)
		}
		seen[endpoint.Kind] = struct{}{}
	}
	for _, kind := range []model.EndpointKind{model.EndpointModels, model.EndpointMessages, model.EndpointResponses, model.EndpointChatCompletions, model.EndpointCountTokens} {
		if _, ok := seen[kind]; !ok {
			return model.WrapValidation("缺少 Endpoint %s", kind)
		}
	}
	return nil
}

func insertEndpointTx(ctx context.Context, tx *sql.Tx, endpoint *model.UpstreamEndpoint) error {
	manualJSON, err := json.Marshal(endpoint.AuthProfile.ManualHeaders)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO upstream_endpoint
		(upstream_id,endpoint,url_mode,legacy_full_url_id,legacy_full_url_revision,
		 legacy_compat_real_only,url_override,fixed_query_template,auth_mode,calibrated_mode,
		 auth_header_name,auth_query_name,auth_secret_ref,auth_manual_headers_json,
		 auth_profile_revision,revision,needs_review,created_at,updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		endpoint.UpstreamID, endpoint.Kind, endpoint.URLMode, nullablePositiveID(endpoint.LegacyFullURLID),
		endpoint.LegacyFullURLRevision, endpoint.LegacyCompatRealOnly, endpoint.URLOverride,
		endpoint.FixedQueryTemplate, endpoint.AuthProfile.Mode, endpoint.AuthProfile.CalibratedMode,
		endpoint.AuthProfile.HeaderName, endpoint.AuthProfile.QueryName, endpoint.AuthProfile.SecretRef,
		string(manualJSON), endpoint.AuthProfile.Revision, endpoint.Revision, endpoint.NeedsReview,
		endpoint.CreatedAt, endpoint.UpdatedAt)
	if err != nil {
		return wrapConstraint(err, "upstream_endpoint")
	}
	endpoint.ID, err = result.LastInsertId()
	if err != nil {
		return err
	}
	return replaceEndpointSecretRefs(ctx, tx, endpoint)
}

func (store *Store) CreateEndpoint(endpoint *model.UpstreamEndpoint) (err error) {
	if endpoint.URLMode == "" {
		endpoint.URLMode = model.EndpointURLCanonical
	}
	if endpoint.AuthProfile.SecretRef == "" {
		endpoint.AuthProfile.SecretRef = "upstream_api_key"
	}
	endpoint.Revision = 1
	endpoint.AuthProfile.Revision = 1
	endpoint.CreatedAt = nowMS()
	endpoint.UpdatedAt = endpoint.CreatedAt
	if err := endpoint.Validate(); err != nil {
		return err
	}
	tx, err := store.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err = insertEndpointTx(context.Background(), tx, endpoint); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) GetEndpoint(id int64) (*model.UpstreamEndpoint, error) {
	return scanEndpoint(store.db.QueryRow(`SELECT `+endpointColumns+` FROM upstream_endpoint WHERE id=?`, id))
}

// Endpoint 按 (upstream, kind) 取一条 Endpoint，满足 outbound.EndpointConfigSource。
//
// 与 GetEndpoint 分开是因为出站路径手上只有「哪个站的哪个端点」，没有行 ID；
// 让它先 List 再筛会把一次点查变成一次全表扫，而这是每请求都走的路径。
func (store *Store) Endpoint(ctx context.Context, upstreamID int64,
	kind model.EndpointKind) (*model.UpstreamEndpoint, error) {

	if !kind.Valid() {
		return nil, model.WrapValidation("endpoint 无效: %q", kind)
	}
	return scanEndpoint(store.db.QueryRowContext(ctx,
		`SELECT `+endpointColumns+` FROM upstream_endpoint WHERE upstream_id=? AND endpoint=?`,
		upstreamID, kind))
}

func scanEndpoint(scanner interface{ Scan(...any) error }) (*model.UpstreamEndpoint, error) {
	var endpoint model.UpstreamEndpoint
	var manualJSON string
	err := scanner.Scan(&endpoint.ID, &endpoint.UpstreamID, &endpoint.Kind, &endpoint.URLMode,
		&endpoint.LegacyFullURLID, &endpoint.LegacyFullURLRevision, &endpoint.LegacyCompatRealOnly,
		&endpoint.URLOverride, &endpoint.FixedQueryTemplate, &endpoint.AuthProfile.Mode,
		&endpoint.AuthProfile.CalibratedMode, &endpoint.AuthProfile.HeaderName,
		&endpoint.AuthProfile.QueryName, &endpoint.AuthProfile.SecretRef, &manualJSON,
		&endpoint.AuthProfile.Revision, &endpoint.Revision, &endpoint.NeedsReview,
		&endpoint.CreatedAt, &endpoint.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(manualJSON), &endpoint.AuthProfile.ManualHeaders); err != nil {
		return nil, fmt.Errorf("endpoint %d manual headers: %w", endpoint.ID, err)
	}
	return &endpoint, nil
}

func (store *Store) ListEndpointsPage(ctx context.Context, filter model.EndpointFilter) (model.Page[*model.UpstreamEndpoint], error) {
	limit, err := normalizePageLimit(filter.Limit)
	if err != nil {
		return model.Page[*model.UpstreamEndpoint]{}, err
	}
	cursorFilter := filter
	cursorFilter.PageRequest = model.PageRequest{}
	keys, err := decodePageCursor(filter.Cursor, "endpoints", cursorFilter, 1)
	if err != nil {
		return model.Page[*model.UpstreamEndpoint]{}, err
	}
	conditions := []string{"1=1"}
	args := make([]any, 0, 6)
	if filter.UpstreamID > 0 {
		conditions = append(conditions, "upstream_id=?")
		args = append(args, filter.UpstreamID)
	}
	if filter.Endpoint != "" {
		if !filter.Endpoint.Valid() {
			return model.Page[*model.UpstreamEndpoint]{}, model.WrapValidation("endpoint filter 无效")
		}
		conditions = append(conditions, "endpoint=?")
		args = append(args, filter.Endpoint)
	}
	if filter.NeedsReview != nil {
		conditions = append(conditions, "needs_review=?")
		args = append(args, *filter.NeedsReview)
	}
	if len(keys) == 1 {
		id, parseErr := strconv.ParseInt(keys[0], 10, 64)
		if parseErr != nil || id < 1 {
			return model.Page[*model.UpstreamEndpoint]{}, ErrInvalidCursor
		}
		conditions = append(conditions, "id>?")
		args = append(args, id)
	}
	args = append(args, limit+1)
	rows, err := store.db.QueryContext(ctx, `SELECT `+endpointColumns+` FROM upstream_endpoint WHERE `+
		strings.Join(conditions, " AND ")+` ORDER BY id LIMIT ?`, args...)
	if err != nil {
		return model.Page[*model.UpstreamEndpoint]{}, err
	}
	defer rows.Close()
	items := make([]*model.UpstreamEndpoint, 0, limit+1)
	for rows.Next() {
		item, scanErr := scanEndpoint(rows)
		if scanErr != nil {
			return model.Page[*model.UpstreamEndpoint]{}, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return model.Page[*model.UpstreamEndpoint]{}, err
	}
	page := model.Page[*model.UpstreamEndpoint]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextCursor, err = encodePageCursor("endpoints", cursorFilter, strconv.FormatInt(page.Items[len(page.Items)-1].ID, 10))
		if err != nil {
			return model.Page[*model.UpstreamEndpoint]{}, err
		}
	}
	return page, nil
}

func (store *Store) UpdateEndpoint(endpoint *model.UpstreamEndpoint, expectedRevision int64) (err error) {
	if expectedRevision < 1 {
		return model.WrapValidation("expected revision 必须为正数")
	}
	if err := endpoint.Validate(); err != nil {
		return err
	}
	tx, err := store.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	current, err := scanEndpoint(tx.QueryRow(`SELECT `+endpointColumns+` FROM upstream_endpoint WHERE id=?`, endpoint.ID))
	if err != nil {
		return err
	}
	if current.Revision != expectedRevision {
		return ErrRevisionConflict
	}
	endpoint.Revision = current.Revision + 1
	if reflect.DeepEqual(endpoint.AuthProfile, current.AuthProfile) {
		endpoint.AuthProfile.Revision = current.AuthProfile.Revision
	} else {
		endpoint.AuthProfile.Revision = current.AuthProfile.Revision + 1
	}
	endpoint.CreatedAt = current.CreatedAt
	endpoint.UpdatedAt = nowMS()
	manualJSON, err := json.Marshal(endpoint.AuthProfile.ManualHeaders)
	if err != nil {
		return err
	}
	result, err := tx.Exec(`UPDATE upstream_endpoint SET
		endpoint=?,url_mode=?,legacy_full_url_id=?,legacy_full_url_revision=?,legacy_compat_real_only=?,
		url_override=?,fixed_query_template=?,auth_mode=?,calibrated_mode=?,auth_header_name=?,
		auth_query_name=?,auth_secret_ref=?,auth_manual_headers_json=?,auth_profile_revision=?,
		revision=?,needs_review=?,updated_at=? WHERE id=? AND revision=?`,
		endpoint.Kind, endpoint.URLMode, nullablePositiveID(endpoint.LegacyFullURLID), endpoint.LegacyFullURLRevision,
		endpoint.LegacyCompatRealOnly, endpoint.URLOverride, endpoint.FixedQueryTemplate,
		endpoint.AuthProfile.Mode, endpoint.AuthProfile.CalibratedMode, endpoint.AuthProfile.HeaderName,
		endpoint.AuthProfile.QueryName, endpoint.AuthProfile.SecretRef, string(manualJSON),
		endpoint.AuthProfile.Revision, endpoint.Revision, endpoint.NeedsReview, endpoint.UpdatedAt,
		endpoint.ID, expectedRevision)
	if err != nil {
		return wrapConstraint(err, "upstream_endpoint")
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrRevisionConflict
	}
	if err = replaceEndpointSecretRefs(context.Background(), tx, endpoint); err != nil {
		return err
	}
	return tx.Commit()
}

func replaceEndpointSecretRefs(ctx context.Context, tx *sql.Tx, endpoint *model.UpstreamEndpoint) error {
	content := probetemplate.TemplateContent{
		Method:   endpoint.Kind.Method(),
		RawQuery: endpoint.FixedQueryTemplate,
		Headers:  endpoint.AuthProfile.ManualHeaders,
	}
	required, err := probetemplate.ScanRequiredSecrets(endpoint.Kind, content)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM endpoint_active_secret_ref WHERE endpoint_id=?`, endpoint.ID); err != nil {
		return err
	}
	for _, name := range required {
		var id, revision int64
		if err := tx.QueryRowContext(ctx, `SELECT id,revision FROM probe_secret WHERE name=?`, name).Scan(&id, &revision); errors.Is(err, sql.ErrNoRows) {
			return model.WrapValidation("Endpoint 引用的 Secret %q 不存在", name)
		} else if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO endpoint_active_secret_ref(endpoint_id,secret_id,name,revision)
			VALUES (?,?,?,?)`, endpoint.ID, id, name, revision); err != nil {
			return err
		}
	}
	return nil
}

func (store *Store) DeleteEndpoint(id, expectedRevision int64) (err error) {
	tx, err := store.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	endpoint, err := scanEndpoint(tx.QueryRow(`SELECT `+endpointColumns+` FROM upstream_endpoint WHERE id=?`, id))
	if err != nil {
		return err
	}
	if endpoint.Revision != expectedRevision {
		return ErrRevisionConflict
	}
	if endpoint.URLMode == model.EndpointURLLegacyExact || endpoint.NeedsReview {
		return fmt.Errorf("%w: migration-only Endpoint 不可删除", ErrDependencyConflict)
	}
	var enabled bool
	if err := tx.QueryRow(`SELECT enabled FROM upstream WHERE id=?`, endpoint.UpstreamID).Scan(&enabled); err != nil {
		return err
	}
	if enabled {
		return fmt.Errorf("%w: 必须先停用 Upstream", ErrDependencyConflict)
	}
	var dependent int
	if err := tx.QueryRow(`SELECT
		(SELECT COUNT(*) FROM route WHERE upstream_id=?) +
		(SELECT COUNT(*) FROM probe_execution WHERE endpoint_id=?) +
		(SELECT COUNT(*) FROM endpoint_capability WHERE endpoint_id=?) +
		(SELECT COUNT(*) FROM probe_recipe WHERE endpoint=? AND
		 ((upstream_id=?) OR route_id IN (SELECT id FROM route WHERE upstream_id=?)))`,
		endpoint.UpstreamID, endpoint.ID, endpoint.ID, endpoint.Kind, endpoint.UpstreamID, endpoint.UpstreamID).Scan(&dependent); err != nil {
		return err
	}
	if dependent != 0 {
		return fmt.Errorf("%w: Endpoint 有 Route 或历史记录", ErrDependencyConflict)
	}
	result, err := tx.Exec(`DELETE FROM upstream_endpoint WHERE id=? AND revision=?`, id, expectedRevision)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrRevisionConflict
	}
	return tx.Commit()
}

func (store *Store) ResolveUpstreamAPIKey(ctx context.Context, upstreamID, expectedCredentialRevision int64) ([]byte, error) {
	var encrypted string
	var revision int64
	if err := store.db.QueryRowContext(ctx, `SELECT api_key_enc,credential_revision FROM upstream WHERE id=?`, upstreamID).
		Scan(&encrypted, &revision); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	if revision != expectedCredentialRevision {
		return nil, ErrRevisionConflict
	}
	plain, err := store.cipher.Decrypt(encrypted)
	if err != nil {
		return nil, err
	}
	return []byte(plain), nil
}

func (store *Store) ResolveLegacyURL(ctx context.Context, id, expectedRevision int64) ([]byte, error) {
	var encrypted string
	var revision int64
	if err := store.db.QueryRowContext(ctx, `SELECT url_enc,revision FROM legacy_full_url WHERE id=?`, id).
		Scan(&encrypted, &revision); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	if revision != expectedRevision {
		return nil, ErrRevisionConflict
	}
	plain, err := store.cipher.Decrypt(encrypted)
	if err != nil {
		return nil, err
	}
	return []byte(plain), nil
}
