package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

func initializeEmptySchemaNine(ctx context.Context, db *sql.DB, c *Cipher) error {
	if err := initializeEmptySchemaEight(ctx, db, c); err != nil {
		return err
	}
	_, err := migrateSchemaEightToNine(ctx, db, "", c, MigrationBackupIdentity{}, "")
	return err
}

func migrateSchemaEightToNine(ctx context.Context, db *sql.DB, path string, c *Cipher, identity MigrationBackupIdentity, buildID string) (result MigrationBackupResult, err error) {
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
	if before.Version != 8 {
		return result, fmt.Errorf("schema 8→9 requires schema 8")
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
		result, err = createMigrationBackup(ctx, backupConn, path, MigrationBackupSpec{SourceSchema: 8, TargetSchema: 9, SourceFingerprint: before.Fingerprint, LegacyCipherID: c.KeyID(), SourceValidator: "schema-8-data-key-v2", PairedBuildID: buildID, ReaderContract: "schema-8-data-key-v2-reader", CreatedAt: identity.CreatedAt})
		backupConn.Close()
		if err != nil {
			return result, err
		}
	}
	script, err := migrationFS.ReadFile("migrations/0009_route_health_identity.sql")
	if err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, string(script)); err != nil {
		return result, err
	}
	if err = validateForeignKeys(ctx, conn); err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, `UPDATE schema_version SET version=9 WHERE singleton=1 AND version=8`); err != nil {
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

// Match only the exact four ALTER definitions over a known schema-8 catalog.
// Keep returning the complete physical schema-9 fingerprint to backup callers.
func knownSchemaNine(catalog []schemaCatalogRow) bool {
	const suffix = ", cooldown_until INTEGER NOT NULL DEFAULT 0, dead_since INTEGER NOT NULL DEFAULT 0, recovery_required INTEGER NOT NULL DEFAULT 0 CHECK (recovery_required IN (0,1)), identity_json TEXT NOT NULL DEFAULT '')"
	base := append([]schemaCatalogRow(nil), catalog...)
	found := false
	for i, row := range base {
		if row.objectType == "table" && row.name == "route_health" && row.table == "route_health" {
			old, ok := strings.CutSuffix(row.statement, suffix)
			if !ok {
				return false
			}
			base[i].statement = old + ")"
			found = true
		}
	}
	return found && (schemaVersionFingerprintKnown(8, schemaCatalogFingerprint(base)) || knownSchemaEightWithRetentionIndexes(base))
}
