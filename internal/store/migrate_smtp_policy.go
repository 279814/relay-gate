package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

func initializeEmptySchemaThirteen(ctx context.Context, db *sql.DB, cipher *Cipher) error {
	if err := initializeEmptySchemaTwelve(ctx, db, cipher); err != nil {
		return err
	}
	_, err := migrateSchemaTwelveToThirteen(ctx, db, "", cipher, MigrationBackupIdentity{}, "")
	return err
}

func migrateSchemaTwelveToThirteen(ctx context.Context, db *sql.DB, path string, cipher *Cipher, identity MigrationBackupIdentity, buildID string) (result MigrationBackupResult, err error) {
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
	if before.Version != 12 {
		return result, fmt.Errorf("schema 12→13 requires schema 12")
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
		result, err = createMigrationBackup(ctx, backupConn, path, MigrationBackupSpec{SourceSchema: 12, TargetSchema: 13, SourceFingerprint: before.Fingerprint, LegacyCipherID: cipher.KeyID(), SourceValidator: "schema-12-attempt-metadata-v1", PairedBuildID: buildID, ReaderContract: "schema-12-attempt-metadata-v1-reader", CreatedAt: identity.CreatedAt})
		backupConn.Close()
		if err != nil {
			return result, err
		}
	}
	script, err := migrationFS.ReadFile("migrations/0013_smtp_policy.sql")
	if err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, string(script)); err != nil {
		return result, err
	}
	if err = validateForeignKeys(ctx, conn); err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, `UPDATE schema_version SET version=13 WHERE singleton=1 AND version=12`); err != nil {
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

// Accept only the exact ALTER definitions on a known schema-12 catalog.
func knownSchemaThirteen(catalog []schemaCatalogRow) bool {
	const suffix = ", aggregation_window_sec INTEGER NOT NULL DEFAULT 300 CHECK (aggregation_window_sec BETWEEN 1 AND 86400), rate_limit_window_sec INTEGER NOT NULL DEFAULT 300 CHECK (rate_limit_window_sec BETWEEN 1 AND 86400), revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1))"
	base := append([]schemaCatalogRow(nil), catalog...)
	found := false
	for i, row := range base {
		if row.objectType == "table" && row.name == "smtp_config" && row.table == "smtp_config" {
			original, ok := strings.CutSuffix(row.statement, suffix)
			if !ok {
				return false
			}
			base[i].statement = original + ")"
			found = true
		}
	}
	return found && knownSchemaTwelve(base)
}
