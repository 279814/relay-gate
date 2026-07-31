package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/279814/relay-gate/internal/model"
)

// ErrNotFound 供 API 层判定回 404。
var ErrNotFound = errors.New("not found")

const upstreamCols = `id, name, base_url, api_key_enc, auth_style, full_url_mode,
	proxy_url, enabled, l1_path, probe_headers, created_at, updated_at`

// scanUpstream 读一行。api_key 解密后填入，调用方负责在回显前脱敏。
func (s *Store) scanUpstream(sc interface{ Scan(...any) error }) (*model.Upstream, error) {
	var u model.Upstream
	var keyEnc, probeHeaders string
	if err := sc.Scan(&u.ID, &u.Name, &u.BaseURL, &keyEnc, &u.AuthStyle,
		&u.FullURLMode, &u.ProxyURL, &u.Enabled, &u.L1Path, &probeHeaders,
		&u.CreatedAt, &u.UpdatedAt); err != nil {
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
	if err := u.Validate(); err != nil {
		return err
	}
	if u.APIKey == "" {
		return fmt.Errorf("%w: api_key 不能为空", model.ErrValidation)
	}
	keyEnc, err := s.cipher.Encrypt(u.APIKey)
	if err != nil {
		return err
	}
	ph, err := marshalHeaders(u.ProbeHeaders)
	if err != nil {
		return err
	}

	u.CreatedAt = nowMS()
	u.UpdatedAt = u.CreatedAt
	res, err := s.db.Exec(`INSERT INTO upstream
		(name, base_url, api_key_enc, auth_style, full_url_mode, proxy_url,
		 enabled, l1_path, probe_headers, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		u.Name, u.BaseURL, keyEnc, u.AuthStyle, u.FullURLMode, u.ProxyURL,
		u.Enabled, u.L1Path, ph, u.CreatedAt, u.UpdatedAt)
	if err != nil {
		return wrapConstraint(err, "upstream")
	}
	u.ID, err = res.LastInsertId()
	return err
}

// UpdateUpstream 全量更新。APIKey 为空表示「不改 key」——
// 因为 GET 返回的是脱敏值，前端把它原样提交回来时不能当作真 key 写入，
// 否则一次编辑就会把 key 破坏成 "sk-abcd…wxyz"。
func (s *Store) UpdateUpstream(u *model.Upstream) error {
	u.Defaults()
	if err := u.Validate(); err != nil {
		return err
	}
	ph, err := marshalHeaders(u.ProbeHeaders)
	if err != nil {
		return err
	}
	u.UpdatedAt = nowMS()

	var res interface{ RowsAffected() (int64, error) }
	if u.APIKey == "" {
		res, err = s.db.Exec(`UPDATE upstream SET
			name=?, base_url=?, auth_style=?, full_url_mode=?, proxy_url=?,
			enabled=?, l1_path=?, probe_headers=?, updated_at=? WHERE id=?`,
			u.Name, u.BaseURL, u.AuthStyle, u.FullURLMode, u.ProxyURL,
			u.Enabled, u.L1Path, ph, u.UpdatedAt, u.ID)
	} else {
		var keyEnc string
		if keyEnc, err = s.cipher.Encrypt(u.APIKey); err != nil {
			return err
		}
		res, err = s.db.Exec(`UPDATE upstream SET
			name=?, base_url=?, api_key_enc=?, auth_style=?, full_url_mode=?,
			proxy_url=?, enabled=?, l1_path=?, probe_headers=?, updated_at=? WHERE id=?`,
			u.Name, u.BaseURL, keyEnc, u.AuthStyle, u.FullURLMode, u.ProxyURL,
			u.Enabled, u.L1Path, ph, u.UpdatedAt, u.ID)
	}
	if err != nil {
		return wrapConstraint(err, "upstream")
	}
	return checkAffected(res)
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
