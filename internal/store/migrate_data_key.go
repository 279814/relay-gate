package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

func initializeEmptySchemaEight(ctx context.Context, db *sql.DB, c *Cipher) error {
	if err := initializeEmptySchemaSeven(ctx, db); err != nil {
		return err
	}
	_, err := migrateSchemaSevenToEight(ctx, db, "", c, MigrationBackupIdentity{})
	return err
}

func (c *Cipher) cloneMasterCipher() *Cipher {
	c.mu.RLock()
	defer c.mu.RUnlock()
	// Verification must succeed with the current master alone. Accepting a
	// retired key here would let cleanup hide an incomplete direct-secret rewrap.
	return &Cipher{aead: c.aead, rootKey: c.rootKey}
}

func migrateSchemaSevenToEight(ctx context.Context, db *sql.DB, path string, c *Cipher, identity MigrationBackupIdentity) (result MigrationBackupResult, err error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return result, err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return result, err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()
	before, err := inspectSchemaState(ctx, conn)
	if err != nil || before.Version != 7 {
		return result, fmt.Errorf("schema 7→8 前置检查失败: %v", err)
	}
	if err := validateDirectSecrets(ctx, conn, c); err != nil {
		return result, err
	}
	if err := validateLegacySampleBodies(ctx, conn, c, 7); err != nil {
		return result, err
	}
	if path != "" {
		backupConn, err := db.Conn(ctx)
		if err != nil {
			return result, err
		}
		contract := identity.ReaderContract
		if contract == "" || (identity.PairedBuildID == "relay-gate-pre-p0" && contract == "schema-1-reader") {
			contract = "schema-7-reader"
		}
		pairedBuild := identity.PairedBuildID
		if pairedBuild == "" || pairedBuild == "relay-gate-pre-p0" {
			pairedBuild = "605a935"
		}
		result, err = createMigrationBackup(ctx, backupConn, path, MigrationBackupSpec{SourceSchema: 7, TargetSchema: 8, SourceFingerprint: before.Fingerprint, LegacyCipherID: c.KeyID(), SourceValidator: "schema-7-v1", PairedBuildID: pairedBuild, ReaderContract: contract, CreatedAt: identity.CreatedAt})
		backupConn.Close()
		if err != nil {
			return result, err
		}
	}
	script, err := migrationFS.ReadFile("migrations/0008_sample_data_key.sql")
	if err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, string(script)); err != nil {
		return result, err
	}
	for _, purpose := range []string{sampleKeyPurpose, securityKeyPurpose} {
		id, wrapped, err := newWrappedDataKey(c, purpose)
		if err != nil {
			return result, err
		}
		if _, err = conn.ExecContext(ctx, `INSERT INTO data_key(purpose,key_id,wrapped_key,created_at) VALUES (?,?,?,?)`, purpose, id, wrapped, nowMS()); err != nil {
			return result, err
		}
	}
	migrationCipher := c.cloneMasterCipher()
	keys, err := readDataKeys(ctx, conn, migrationCipher)
	if err != nil {
		return result, err
	}
	migrationCipher.installDataKeys(keys)
	if err = migrateSampleDataBodies(ctx, conn, migrationCipher); err != nil {
		return result, err
	}
	if err = migrateSecurityDataBodies(ctx, conn, migrationCipher, true); err != nil {
		return result, err
	}
	if err = validateEncryptedState(ctx, conn, migrationCipher); err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, `UPDATE schema_version SET version=8 WHERE singleton=1 AND version=7`); err != nil {
		return result, err
	}
	if _, err = inspectSchemaState(ctx, conn); err != nil {
		return result, err
	}
	if err = validateForeignKeys(ctx, conn); err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, `COMMIT`); err != nil {
		return result, err
	}
	committed = true
	c.installDataKeys(keys)
	return result, nil
}

func migrateSecurityDataBodies(ctx context.Context, q encryptedStateExecutor, c *Cipher, legacy bool) error {
	var cursor string
	for {
		var id string
		var detail []byte
		err := q.QueryRowContext(ctx, `SELECT id,detail FROM security_finding WHERE id>? ORDER BY id LIMIT 1`, cursor).Scan(&id, &detail)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if len(detail) > 0 {
			if !legacy && strings.HasPrefix(string(detail), "v2:") {
				if _, err := c.decryptDataBlob(securityKeyPurpose, detail); err != nil {
					return err
				}
			} else {
				encoded, err := c.encryptDataBlob(securityKeyPurpose, detail)
				if err != nil {
					return err
				}
				if _, err := q.ExecContext(ctx, `UPDATE security_finding SET detail=? WHERE id=?`, encoded, id); err != nil {
					return err
				}
			}
		}
		cursor = id
	}
}

func (s *Store) migrateDataBodies() (int64, error) {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var before int64
	legacy := func(column string) string {
		return `length(` + column + `)>0 AND substr(CAST(` + column + ` AS BLOB),1,3)!=CAST('v2:' AS BLOB) AND substr(CAST(` + column + ` AS BLOB),1,4)!=CAST('v2m:' AS BLOB)`
	}
	if err := tx.QueryRow(`SELECT COUNT(*) FROM (SELECT id AS request_id FROM sample_request WHERE ` + legacy("in_body") + ` UNION SELECT request_id FROM sample_attempt WHERE (` + legacy("out_body") + `) OR (` + legacy("resp_body") + `))`).Scan(&before); err != nil {
		return 0, err
	}
	if err := migrateSampleDataBodies(context.Background(), tx, s.cipher); err != nil {
		return 0, err
	}
	if err := migrateSecurityDataBodies(context.Background(), tx, s.cipher, false); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return before, nil
}
