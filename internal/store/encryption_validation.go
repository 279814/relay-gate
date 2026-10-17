package store

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func validateDirectSecrets(ctx context.Context, q encryptedStateQuery, c *Cipher) error {
	for _, direct := range []struct {
		table, column string
		envelope      bool
	}{
		{"upstream", "api_key_enc", false}, {"probe_secret", "value_enc", false}, {"smtp_config", "password_enc", true}, {"legacy_full_url", "url_enc", false},
	} {
		var exists int
		if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name=?`, direct.table).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			continue
		}
		rows, err := q.QueryContext(ctx, `SELECT `+direct.column+` FROM `+direct.table+` WHERE `+direct.column+` IS NOT NULL AND length(`+direct.column+`)>0`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var encoded string
			if err := rows.Scan(&encoded); err != nil {
				rows.Close()
				return err
			}
			if direct.envelope {
				_, err = c.DecryptEnvelope(encoded)
			} else {
				_, err = c.Decrypt(encoded)
			}
			if err != nil {
				rows.Close()
				return fmt.Errorf("%s 密文校验失败", direct.table)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func validateEncryptedState(ctx context.Context, q encryptedStateQuery, c *Cipher) error {
	if err := validateDirectSecrets(ctx, q, c); err != nil {
		return err
	}
	if err := walkSensitiveBodies(ctx, q, func(col bodyColumn, id, total int64) error {
		return validateSensitiveBody(c, col.purpose, &sampleBlobReader{ctx: ctx, q: q, table: col.table, column: col.column, id: id, total: total})
	}); err != nil {
		return err
	}
	rows, err := q.QueryContext(ctx, `SELECT detail FROM security_finding WHERE length(detail)>0`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var encoded []byte
		if err := rows.Scan(&encoded); err != nil {
			return err
		}
		if _, err := c.decryptDataBlob(securityKeyPurpose, encoded); err != nil {
			return fmt.Errorf("security evidence 密文校验失败")
		}
	}
	return rows.Err()
}

// ValidateEncryptedState validates all current encrypted rows using a fresh
// unwrapping of the database's Data Keys, never cached keys from a prior store.
func (s *Store) ValidateEncryptedState() error {
	c := s.cipher.cloneMasterCipher()
	keys, err := readDataKeys(context.Background(), s.db, c)
	if err != nil {
		return err
	}
	c.installDataKeys(keys)
	return validateEncryptedState(context.Background(), s.db, c)
}

// ValidateDatabaseEncryption is used before activating a pending master and
// during journal recovery. It never migrates or changes the keyring/database.
func ValidateDatabaseEncryption(ctx context.Context, databasePath, master string) error {
	c, err := NewCipher(master)
	if err != nil {
		return err
	}
	db, err := openReadOnlySQLite(databasePath)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	state, err := inspectSchemaState(ctx, db)
	if err != nil {
		return err
	}
	if state.Empty {
		return fmt.Errorf("拒绝验证空数据库")
	}
	if state.Version < 8 {
		if err := validateDirectSecrets(ctx, db, c); err != nil {
			return err
		}
		return validateLegacySampleBodies(ctx, db, c, state.Version)
	}
	keys, err := readDataKeys(ctx, db, c)
	if err != nil {
		return err
	}
	c.installDataKeys(keys)
	return validateEncryptedState(ctx, db, c)
}

func openReadOnlySQLite(path string) (*sql.DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return nil, fmt.Errorf("验证需要已存在的非空数据库")
	}
	if err := rejectSymlinkOrReparse(abs); err != nil {
		return nil, err
	}
	uriPath := filepath.ToSlash(abs)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	uri := url.URL{Scheme: "file", Path: uriPath, RawQuery: "mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(5000)"}
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

func validateLegacySampleBodies(ctx context.Context, q encryptedStateQuery, c *Cipher, version int) error {
	columns := []bodyColumn{{"sample", "in_body", sampleKeyPurpose}, {"sample", "out_body", sampleKeyPurpose}, {"sample", "resp_body", sampleKeyPurpose}}
	if version >= 7 {
		columns = sensitiveBodyColumns[:3]
	}
	for _, col := range columns {
		var exists int
		if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name=?`, col.table).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			continue
		}
		var cursor int64
		for {
			var id, total int64
			err := q.QueryRowContext(ctx, `SELECT id,COALESCE(length(CAST(`+col.column+` AS BLOB)),0) FROM `+col.table+` WHERE id>? ORDER BY id LIMIT 1`, cursor).Scan(&id, &total)
			if err == sql.ErrNoRows {
				break
			}
			if err != nil {
				return err
			}
			cursor = id
			if total == 0 {
				continue
			}
			reader := bufio.NewReader(&sampleBlobReader{ctx: ctx, q: q, table: col.table, column: col.column, id: id, total: total})
			prefix, _ := reader.Peek(4)
			if bytes.Equal(prefix, []byte("v1m:")) {
				legacy, err := newLegacyMultipartReader(c, reader)
				if err != nil {
					return err
				}
				if _, err := io.Copy(io.Discard, legacy); err != nil {
					return err
				}
			} else if bytes.HasPrefix(prefix, []byte("v1:")) {
				raw, err := io.ReadAll(reader)
				if err != nil {
					return err
				}
				if _, err := c.DecryptEnvelope(string(raw)); err != nil {
					return fmt.Errorf("旧样本信封校验失败")
				}
			} else if bytes.HasPrefix(prefix, []byte("v2")) {
				return fmt.Errorf("旧 schema 不能包含 Data Key 正文")
			}
		}
	}
	return nil
}

// Read encrypted multipart bodies without accumulating plaintext during
// startup/rotation validation. Single-message legacy GCM needs its full frame.
