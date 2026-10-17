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
	"github.com/279814/relay-gate/internal/outbound"
)

// ErrNotFound 供 API 层判定回 404。
var ErrNotFound = errors.New("not found")

const upstreamCols = `id, name, base_url, api_key_enc, auth_style, full_url_mode,
	proxy_url, enabled, l1_path, probe_headers, created_at, updated_at,
	probe_mode,host_override,tls_server_name,revision,network_revision,credential_revision`

// scanUpstream 读一行。api_key 解密后填入，调用方负责在回显前脱敏。
func (s *Store) scanUpstream(sc interface{ Scan(...any) error }) (*model.Upstream, error) {
	var u model.Upstream
	var keyEnc, probeHeaders string
	if err := sc.Scan(&u.ID, &u.Name, &u.BaseURL, &keyEnc, &u.AuthStyle,
		&u.FullURLMode, &u.ProxyURL, &u.Enabled, &u.L1Path, &probeHeaders,
		&u.CreatedAt, &u.UpdatedAt, &u.ProbeMode, &u.HostOverride, &u.TLSServerName,
		&u.Revision, &u.NetworkRevision, &u.CredentialRevision); err != nil {
		return nil, err
	}
	if keyEnc != "" {
		plain, err := s.cipher.Decrypt(keyEnc)
		if err != nil {
			return nil, fmt.Errorf("upstream %d(%s) 的 api_key: %w", u.ID, u.Name, err)
		}
		u.APIKey = plain
	}
	if probeHeaders != "" {
		if err := json.Unmarshal([]byte(probeHeaders), &u.ProbeHeaders); err != nil {
			return nil, fmt.Errorf("upstream %d(%s) 的 probe_headers 不是合法 JSON: %w", u.ID, u.Name, err)
		}
	}
	return &u, nil
}

func (s *Store) ListUpstreamsPage(ctx context.Context, filter model.UpstreamFilter) (model.Page[*model.Upstream], error) {
	limit, err := normalizePageLimit(filter.Limit)
	if err != nil {
		return model.Page[*model.Upstream]{}, err
	}
	cursorFilter := filter
	cursorFilter.PageRequest = model.PageRequest{}
	keys, err := decodePageCursor(filter.Cursor, "upstreams", cursorFilter, 1)
	if err != nil {
		return model.Page[*model.Upstream]{}, err
	}
	conditions := []string{"id>0"}
	args := make([]any, 0, 4)
	if filter.Enabled != nil {
		conditions = append(conditions, "enabled=?")
		args = append(args, *filter.Enabled)
	}
	if filter.ProbeMode != "" {
		if !filter.ProbeMode.Valid() {
			return model.Page[*model.Upstream]{}, model.WrapValidation("probe mode filter 无效")
		}
		conditions = append(conditions, "probe_mode=?")
		args = append(args, filter.ProbeMode)
	}
	if len(keys) == 1 {
		id, cursorErr := cursorID(keys[0])
		if cursorErr != nil {
			return model.Page[*model.Upstream]{}, cursorErr
		}
		conditions = append(conditions, "id>?")
		args = append(args, id)
	}
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(ctx, `SELECT `+upstreamCols+` FROM upstream WHERE `+
		strings.Join(conditions, " AND ")+` ORDER BY id LIMIT ?`, args...)
	if err != nil {
		return model.Page[*model.Upstream]{}, err
	}
	defer rows.Close()
	items := make([]*model.Upstream, 0, limit+1)
	for rows.Next() {
		item, scanErr := s.scanUpstream(rows)
		if scanErr != nil {
			return model.Page[*model.Upstream]{}, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return model.Page[*model.Upstream]{}, err
	}
	page := model.Page[*model.Upstream]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextCursor, err = encodePageCursor("upstreams", cursorFilter,
			strconv.FormatInt(page.Items[len(page.Items)-1].ID, 10))
		if err != nil {
			return model.Page[*model.Upstream]{}, err
		}
	}
	return page, nil
}

func (s *Store) GetUpstream(id int64) (*model.Upstream, error) {
	row := s.db.QueryRow(`SELECT `+upstreamCols+` FROM upstream WHERE id = ?`, id)
	u, err := s.scanUpstream(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *Store) CreateUpstream(u *model.Upstream) error {
	u.Defaults()
	return s.CreateUpstreamWithEndpoints(context.Background(), u, canonicalEndpointBundle(u))
}

// UpdateUpstreamWithRevision 全量更新。APIKey 为空或等于 MaskKey(现钥) 表示「不改 key」——
// GET/list 回显的是脱敏值，前端把它原样提交回来时不能当作真 key 写入，
// 否则一次编辑就会把 key 破坏成 "sk-abcd…wxyz"。
// proxy_url 同理：回显经 MaskProxyURL 去掉 password，原样提交必须保留库中真凭据。
func (s *Store) UpdateUpstreamWithRevision(ctx context.Context, upstream *model.Upstream, expectedRevision int64) (err error) {
	if expectedRevision < 1 {
		return model.WrapValidation("expected_revision 必须为正数")
	}
	upstream.Defaults()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	current, err := s.scanUpstream(tx.QueryRowContext(ctx, `SELECT `+upstreamCols+` FROM upstream WHERE id=?`, upstream.ID))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if current.Revision != expectedRevision {
		return ErrRevisionConflict
	}
	if len(upstream.ProbeHeaders) == 0 && len(current.ProbeHeaders) == 0 {
		upstream.ProbeHeaders = current.ProbeHeaders
	}
	if upstream.AuthStyle != current.AuthStyle || upstream.FullURLMode != current.FullURLMode || upstream.L1Path != current.L1Path || !reflect.DeepEqual(upstream.ProbeHeaders, current.ProbeHeaders) {
		return model.WrapValidation("旧全局 auth_style/full_url_mode/l1_path/probe_headers 不可修改，请编辑对应 Endpoint 或 Recipe")
	}
	// 由停用转启用时必须先补齐五类 Endpoint。放行一个缺 Endpoint 的站，
	// 症状是「界面看起来一切正常，客户端一调那个协议就报错」——
	// 选路时才发现 URL 解析不出来，已经晚了。
	//
	// 检查放在读 current 的同一个事务里（DSN 带 _txlock=immediate，开事务即持写锁），
	// 所以「删 Endpoint」与「enable」并发时只有一方能提交。
	if upstream.Enabled && !current.Enabled {
		if err := validateRouteEndpointCompleteness(tx, upstream.ID); err != nil {
			return err
		}
	}
	// 脱敏回显与空串都归一成「不改」；只有真正的新明文才换钥。
	// 必须在 Validate 之前：MaskKey 回显通常短于 MinRedactableKeyLen，
	// 否则前端把脱敏值原样提交会被误判成「短 key」。
	if upstream.APIKey == "" || (current.APIKey != "" && upstream.APIKey == MaskKey(current.APIKey)) {
		upstream.APIKey = ""
	}
	// GET 回显的 proxy_url 已去掉 password（MaskProxyURL）；前端原样提交时
	// 不能把 "user:xxxxx@host" 当真凭据写入，否则一次编辑就毁掉代理认证。
	if current.ProxyURL != "" && upstream.ProxyURL == MaskProxyURL(current.ProxyURL) {
		upstream.ProxyURL = current.ProxyURL
	}
	if err := upstream.Validate(); err != nil {
		return err
	}
	if upstream.BaseURL != current.BaseURL {
		if err := validateCurrentEndpointOrigins(ctx, tx, upstream.ID, upstream.BaseURL); err != nil {
			return err
		}
	}
	// 脏行/历史短钥：留空或 mask 回显不能再成功「保留」——否则短钥继续
	// 出现在 Location 等 URI 头且 RedactText 不会遮。必须提交足够长的新钥。
	if upstream.APIKey == "" && current.APIKey != "" && len(current.APIKey) < model.MinRedactableKeyLen {
		return model.WrapValidation("api_key 长度至少为 %d（短于此无法在 Location 等 URI 头中脱敏），收到 %d",
			model.MinRedactableKeyLen, len(current.APIKey))
	}
	credentialChanged := upstream.APIKey != "" && upstream.APIKey != current.APIKey
	networkChanged := upstream.BaseURL != current.BaseURL || upstream.ProxyURL != current.ProxyURL ||
		upstream.HostOverride != current.HostOverride || upstream.TLSServerName != current.TLSServerName ||
		upstream.FullURLMode != current.FullURLMode
	rowChanged := upstream.Name != current.Name || networkChanged || credentialChanged ||
		upstream.AuthStyle != current.AuthStyle || upstream.Enabled != current.Enabled ||
		upstream.L1Path != current.L1Path || upstream.ProbeMode != current.ProbeMode ||
		!reflect.DeepEqual(upstream.ProbeHeaders, current.ProbeHeaders)
	if !rowChanged {
		upstream.Revision = current.Revision
		upstream.NetworkRevision = current.NetworkRevision
		upstream.CredentialRevision = current.CredentialRevision
		upstream.CreatedAt = current.CreatedAt
		upstream.UpdatedAt = current.UpdatedAt
		return tx.Commit()
	}
	headersJSON, err := marshalHeaders(upstream.ProbeHeaders)
	if err != nil {
		return err
	}
	upstream.Revision = current.Revision + 1
	upstream.NetworkRevision = current.NetworkRevision
	// §9.2: re-enable invalidates the previous connectivity/capability lifecycle
	// atomically with the update, including results still waiting to commit.
	if networkChanged || (!current.Enabled && upstream.Enabled) {
		upstream.NetworkRevision++
	}
	upstream.CredentialRevision = current.CredentialRevision
	if credentialChanged {
		upstream.CredentialRevision++
	}
	upstream.CreatedAt = current.CreatedAt
	upstream.UpdatedAt = nowMS()
	var result sql.Result
	if credentialChanged {
		encrypted, encryptErr := s.cipher.Encrypt(upstream.APIKey)
		if encryptErr != nil {
			return encryptErr
		}
		result, err = tx.ExecContext(ctx, `UPDATE upstream SET name=?,base_url=?,api_key_enc=?,auth_style=?,
			full_url_mode=?,proxy_url=?,enabled=?,l1_path=?,probe_headers=?,probe_mode=?,host_override=?,
			tls_server_name=?,revision=?,network_revision=?,credential_revision=?,updated_at=?
			WHERE id=? AND revision=?`, upstream.Name, upstream.BaseURL, encrypted, upstream.AuthStyle,
			upstream.FullURLMode, upstream.ProxyURL, upstream.Enabled, upstream.L1Path, headersJSON,
			upstream.ProbeMode, upstream.HostOverride, upstream.TLSServerName, upstream.Revision,
			upstream.NetworkRevision, upstream.CredentialRevision, upstream.UpdatedAt, upstream.ID, expectedRevision)
	} else {
		result, err = tx.ExecContext(ctx, `UPDATE upstream SET name=?,base_url=?,auth_style=?,full_url_mode=?,
			proxy_url=?,enabled=?,l1_path=?,probe_headers=?,probe_mode=?,host_override=?,tls_server_name=?,
			revision=?,network_revision=?,credential_revision=?,updated_at=? WHERE id=? AND revision=?`,
			upstream.Name, upstream.BaseURL, upstream.AuthStyle, upstream.FullURLMode, upstream.ProxyURL,
			upstream.Enabled, upstream.L1Path, headersJSON, upstream.ProbeMode, upstream.HostOverride,
			upstream.TLSServerName, upstream.Revision, upstream.NetworkRevision,
			upstream.CredentialRevision, upstream.UpdatedAt, upstream.ID, expectedRevision)
	}
	if err != nil {
		return wrapConstraint(err, "upstream")
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrRevisionConflict
	}
	if !current.Enabled && upstream.Enabled {
		if err = deleteConfigErrorCapabilitiesTx(ctx, tx,
			`scope_upstream_id=? OR scope_route_id IN (SELECT id FROM route WHERE upstream_id=?)`,
			upstream.ID, upstream.ID); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if upstream.APIKey == "" {
		upstream.APIKey = ""
	}
	return nil
}

func validateCurrentEndpointOrigins(ctx context.Context, tx *sql.Tx, upstreamID int64, baseURL string) error {
	rows, err := tx.QueryContext(ctx, `SELECT url_mode,url_override FROM upstream_endpoint WHERE upstream_id=?`, upstreamID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var mode model.EndpointURLMode
		var override string
		if err := rows.Scan(&mode, &override); err != nil {
			return err
		}
		if mode == model.EndpointURLLegacyExact {
			return model.WrapValidation("legacy_exact Endpoint 保留捕获的 URL，不能通过修改 base_url 改写，请先人工审核或新建 Upstream")
		}
		if err := outbound.ValidateURLOverride(baseURL, override); err != nil {
			return model.WrapValidation("现有 Endpoint URL 与新 base_url 不兼容，请先调整 Endpoint: %v", err)
		}
	}
	return rows.Err()
}

// DeleteUpstreamWithRevision rejects a stale administrator view in the same
// transaction as detaching references and deleting the row.
func (s *Store) DeleteUpstreamWithRevision(ctx context.Context, id, expectedRevision int64) error {
	if expectedRevision <= 0 {
		return model.WrapValidation("expected_revision 必须为正数")
	}
	return s.deleteUpstream(ctx, id, expectedRevision)
}

func (s *Store) deleteUpstream(ctx context.Context, id, expectedRevision int64) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var revision int64
	err = tx.QueryRowContext(ctx, `SELECT revision FROM upstream WHERE id=?`, id).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if revision != expectedRevision {
		return ErrRevisionConflict
	}
	if err = requireEntityDeleteUnreferenced(ctx, tx, "upstream", id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM probe_recipe WHERE upstream_id=?`, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM transform_binding WHERE endpoint_id IN (SELECT id FROM upstream_endpoint WHERE upstream_id=?)`, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM upstream_endpoint WHERE upstream_id=?`, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM legacy_full_url WHERE upstream_id=?`, id); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM upstream WHERE id=?`, id)
	if err != nil {
		return err
	}
	if err = checkAffected(res); err != nil {
		return err
	}
	return tx.Commit()
}

func marshalHeaders(h map[string]string) (string, error) {
	if len(h) == 0 {
		return "", nil
	}
	b, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("序列化 probe_headers: %w", err)
	}
	return string(b), nil
}

func checkAffected(res interface{ RowsAffected() (int64, error) }) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
