package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

func initializeEmptySchemaSixteen(ctx context.Context, db *sql.DB, cipher *Cipher) error {
	if err := initializeEmptySchemaFifteen(ctx, db, cipher); err != nil {
		return err
	}
	_, err := migrateSchemaFifteenToSixteen(ctx, db, "", cipher, MigrationBackupIdentity{}, "")
	return err
}

func migrateSchemaFifteenToSixteen(ctx context.Context, db *sql.DB, path string, cipher *Cipher, identity MigrationBackupIdentity, buildID string) (result MigrationBackupResult, err error) {
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
	if before.Version != 15 {
		return result, fmt.Errorf("schema 15→16 requires schema 15")
	}
	validation := cipher.cloneMasterCipher()
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
			buildID, err = CurrentReaderBuildID("dev")
			if err != nil {
				backupConn.Close()
				return result, err
			}
		}
		result, err = createMigrationBackup(ctx, backupConn, path, MigrationBackupSpec{SourceSchema: 15, TargetSchema: 16, SourceFingerprint: before.Fingerprint, LegacyCipherID: cipher.KeyID(), SourceValidator: "schema-15-upstream-sample-v1", PairedBuildID: buildID, ReaderContract: "schema-15-upstream-sample-v1-reader", CreatedAt: identity.CreatedAt})
		backupConn.Close()
		if err != nil {
			return result, err
		}
	}
	script, err := migrationFS.ReadFile("migrations/0016_transform_admin.sql")
	if err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, string(script)); err != nil {
		return result, err
	}
	if err = validateForeignKeys(ctx, conn); err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, `UPDATE schema_version SET version=16 WHERE singleton=1 AND version=15`); err != nil {
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

// Accept only the exact ALTER definitions over the historical schema-15 catalog.
func knownSchemaSixteen(catalog []schemaCatalogRow) bool {
	const suffix = ", revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1), lifecycle_state TEXT NOT NULL DEFAULT 'active' CHECK (lifecycle_state IN ('active','disabled','archived')))"
	base := append([]schemaCatalogRow(nil), catalog...)
	found := false
	for i, row := range base {
		if row.objectType == "table" && row.name == "transform_set" && row.table == "transform_set" {
			original, ok := strings.CutSuffix(row.statement, suffix)
			if !ok {
				return false
			}
			base[i].statement = original + ")"
			found = true
		}
	}
	return found && knownSchemaFifteen(base)
}
