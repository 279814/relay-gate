package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

func initializeEmptySchemaTwelve(ctx context.Context, db *sql.DB, cipher *Cipher) error {
	if err := initializeEmptySchemaEleven(ctx, db, cipher); err != nil {
		return err
	}
	_, err := migrateSchemaElevenToTwelve(ctx, db, "", cipher, MigrationBackupIdentity{}, "")
	return err
}

func migrateSchemaElevenToTwelve(ctx context.Context, db *sql.DB, path string, cipher *Cipher, identity MigrationBackupIdentity, buildID string) (result MigrationBackupResult, err error) {
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
	if before.Version != 11 {
		return result, fmt.Errorf("schema 11→12 requires schema 11")
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
		result, err = createMigrationBackup(ctx, backupConn, path, MigrationBackupSpec{SourceSchema: 11, TargetSchema: 12, SourceFingerprint: before.Fingerprint, LegacyCipherID: cipher.KeyID(), SourceValidator: "schema-11-audit-v1", PairedBuildID: buildID, ReaderContract: "schema-11-audit-v1-reader", CreatedAt: identity.CreatedAt})
		backupConn.Close()
		if err != nil {
			return result, err
		}
	}
	script, err := migrationFS.ReadFile("migrations/0012_attempt_metadata.sql")
	if err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, string(script)); err != nil {
		return result, err
	}
	if err = validateForeignKeys(ctx, conn); err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, `UPDATE schema_version SET version=12 WHERE singleton=1 AND version=11`); err != nil {
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

func knownSchemaTwelve(catalog []schemaCatalogRow) bool {
	script, err := migrationFS.ReadFile("migrations/0012_attempt_metadata.sql")
	if err != nil {
		return false
	}
	expected := make(map[string]string)
	for _, statement := range strings.Split(string(script), ";") {
		statement = normalizeSchemaStatement(statement)
		if statement == "" {
			continue
		}
		fields := strings.Fields(statement)
		if len(fields) < 3 || fields[0] != "CREATE" {
			return false
		}
		expected[strings.ToLower(fields[1])+":"+fields[2]] = statement
	}
	base := make([]schemaCatalogRow, 0, len(catalog))
	for _, row := range catalog {
		key := row.objectType + ":" + row.name
		if statement, ok := expected[key]; ok {
			if (row.table != "request_log_metadata" && row.table != "sample_attempt_metadata") || row.statement != statement {
				return false
			}
			delete(expected, key)
			continue
		}
		base = append(base, row)
	}
	return len(expected) == 0 && knownSchemaEleven(base)
}
