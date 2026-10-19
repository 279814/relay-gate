package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

func initializeEmptySchemaFifteen(ctx context.Context, db *sql.DB, cipher *Cipher) error {
	if err := initializeEmptySchemaFourteen(ctx, db, cipher); err != nil {
		return err
	}
	_, err := migrateSchemaFourteenToFifteen(ctx, db, "", cipher, MigrationBackupIdentity{}, "")
	return err
}

func migrateSchemaFourteenToFifteen(ctx context.Context, db *sql.DB, path string, cipher *Cipher, identity MigrationBackupIdentity, buildID string) (result MigrationBackupResult, err error) {
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
	if before.Version != 14 {
		return result, fmt.Errorf("schema 14→15 requires schema 14")
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
		result, err = createMigrationBackup(ctx, backupConn, path, MigrationBackupSpec{SourceSchema: 14, TargetSchema: 15, SourceFingerprint: before.Fingerprint, LegacyCipherID: cipher.KeyID(), SourceValidator: "schema-14-canary-v1", PairedBuildID: buildID, ReaderContract: "schema-14-canary-v1-reader", CreatedAt: identity.CreatedAt})
		backupConn.Close()
		if err != nil {
			return result, err
		}
	}
	script, err := migrationFS.ReadFile("migrations/0015_upstream_sample.sql")
	if err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, string(script)); err != nil {
		return result, err
	}
	if err = validateForeignKeys(ctx, conn); err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, `UPDATE schema_version SET version=15 WHERE singleton=1 AND version=14`); err != nil {
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

// Accept only the exact ALTER definitions on a known schema-14 catalog.
func knownSchemaFifteen(catalog []schemaCatalogRow) bool {
	const suffix = ", response_capture_view TEXT NOT NULL DEFAULT 'legacy' CHECK (response_capture_view IN ('legacy','upstream_response','upstream_attempt_prefix','no_response','omitted_secret','omitted_unverified')))"
	base := append([]schemaCatalogRow(nil), catalog...)
	found := false
	for i, row := range base {
		if row.objectType == "table" && row.name == "sample_attempt_metadata" && row.table == "sample_attempt_metadata" {
			original, ok := strings.CutSuffix(row.statement, suffix)
			if !ok {
				return false
			}
			base[i].statement = original + ")"
			found = true
		}
	}
	return found && knownSchemaFourteen(base)
}
