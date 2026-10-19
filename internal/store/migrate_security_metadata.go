package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

func initializeEmptySchemaTen(ctx context.Context, db *sql.DB, c *Cipher) error {
	if err := initializeEmptySchemaNine(ctx, db, c); err != nil {
		return err
	}
	_, err := migrateSchemaNineToTen(ctx, db, "", c, MigrationBackupIdentity{}, "")
	return err
}

func migrateSchemaNineToTen(ctx context.Context, db *sql.DB, path string, c *Cipher, identity MigrationBackupIdentity, buildID string) (result MigrationBackupResult, err error) {
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
	if err != nil {
		return result, err
	}
	if before.Version != 9 {
		return result, fmt.Errorf("schema 9→10 requires schema 9")
	}
	validation := c.cloneMasterCipher()
	keys, err := readDataKeys(ctx, conn, validation)
	if err != nil {
		return result, err
	}
	validation.installDataKeys(keys)
	if err := validateEncryptedState(ctx, conn, validation); err != nil {
		return result, err
	}
	if path != "" {
		backupConn, err := db.Conn(ctx)
		if err != nil {
			return result, err
		}
		if buildID == "" {
			var buildErr error
			buildID, buildErr = CurrentReaderBuildID("dev")
			if buildErr != nil {
				backupConn.Close()
				return result, buildErr
			}
		}
		result, err = createMigrationBackup(ctx, backupConn, path, MigrationBackupSpec{SourceSchema: 9, TargetSchema: 10, SourceFingerprint: before.Fingerprint, LegacyCipherID: c.KeyID(), SourceValidator: "schema-9-route-health-v1", PairedBuildID: buildID, ReaderContract: "schema-9-route-health-v1-reader", CreatedAt: identity.CreatedAt})
		backupConn.Close()
		if err != nil {
			return result, err
		}
	}
	script, err := migrationFS.ReadFile("migrations/0010_security_scan_metadata.sql")
	if err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, string(script)); err != nil {
		return result, err
	}
	if err = validateForeignKeys(ctx, conn); err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, `UPDATE schema_version SET version=10 WHERE singleton=1 AND version=9`); err != nil {
		return result, err
	}
	if _, err = inspectSchemaState(ctx, conn); err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, `COMMIT`); err != nil {
		return result, err
	}
	committed = true
	return result, nil
}

// Match only the exact additive metadata definitions over a known schema-9
// catalog, including its already reviewed optional retention indexes.
func knownSchemaTen(catalog []schemaCatalogRow) bool {
	const suffix = ", truncated INTEGER NOT NULL DEFAULT 0 CHECK (truncated IN (0,1)), decode_depth INTEGER NOT NULL DEFAULT 0 CHECK (decode_depth BETWEEN 0 AND 2), evidence_hash TEXT NOT NULL DEFAULT '')"
	base := append([]schemaCatalogRow(nil), catalog...)
	found := false
	for i, row := range base {
		if row.objectType == "table" && row.name == "security_finding" && row.table == "security_finding" {
			old, ok := strings.CutSuffix(row.statement, suffix)
			if !ok {
				return false
			}
			base[i].statement = old + ")"
			found = true
		}
	}
	return found && knownSchemaNine(base)
}
