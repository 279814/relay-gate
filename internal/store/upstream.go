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

func (s *Store) ListUpstreams() ([]*model.Upstream, error) {
	rows, err := s.db.Query(`SELECT ` + upstreamCols + ` FROM upstream ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*model.Upstream{}
	for rows.Next() {
		u, err := s.scanUpstream(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
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
	conditions := []string{"1=1"}
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

// UpdateUpstream 全量更新。APIKey 为空表示「不改 key」——
// 因为 GET 返回的是脱敏值，前端把它原样提交回来时不能当作真 key 写入，
// 否则一次编辑就会把 key 破坏成 "sk-abcd…wxyz"。
func (s *Store) UpdateUpstream(u *model.Upstream) error {
	current, err := s.GetUpstream(u.ID)
	if err != nil {
		return err
	}
	return s.UpdateUpstreamWithRevision(context.Background(), u, current.Revision)
}

func (s *Store) UpdateUpstreamWithRevision(ctx context.Context, upstream *model.Upstream, expectedRevision int64) (err error) {
	upstream.Defaults()
	if err := upstream.Validate(); err != nil {
		return err
	}
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
	if networkChanged {
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
	if upstream.AuthStyle != current.AuthStyle {
		mode, headerName := legacyAuthProfile(upstream.AuthStyle)
		if _, err := tx.ExecContext(ctx, `UPDATE upstream_endpoint SET auth_mode=?,auth_header_name=?,
			legacy_compat_real_only=?,auth_profile_revision=auth_profile_revision+1,
			revision=revision+1,updated_at=? WHERE upstream_id=?`,
			mode, headerName, mode == model.AuthModeLegacyAutoRealOnly, upstream.UpdatedAt, upstream.ID); err != nil {
			return err
		}
	}
	if upstream.L1Path != current.L1Path {
		override := ""
		if upstream.L1Path != "" && upstream.L1Path != "/v1/models" {
			override = strings.TrimRight(upstream.BaseURL, "/") + upstream.L1Path
		}
		if _, err := tx.ExecContext(ctx, `UPDATE upstream_endpoint SET url_override=?,revision=revision+1,
			updated_at=? WHERE upstream_id=? AND endpoint='models'`, override, upstream.UpdatedAt, upstream.ID); err != nil {
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

func (s *Store) DeleteUpstream(id int64) error {
	res, err := s.db.Exec(`DELETE FROM upstream WHERE id = ?`, id)
	if err != nil {
		return err
	}
	return checkAffected(res)
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
