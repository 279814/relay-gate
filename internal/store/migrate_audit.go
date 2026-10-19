package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

func initializeEmptySchemaEleven(ctx context.Context, db *sql.DB, cipher *Cipher) error {
	if err := initializeEmptySchemaTen(ctx, db, cipher); err != nil {
		return err
	}
	_, err := migrateSchemaTenToEleven(ctx, db, "", cipher, MigrationBackupIdentity{}, "")
	return err
}

func migrateSchemaTenToEleven(ctx context.Context, db *sql.DB, path string, cipher *Cipher, identity MigrationBackupIdentity, buildID string) (result MigrationBackupResult, err error) {
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
	if before.Version != 10 {
		return result, fmt.Errorf("schema 10→11 requires schema 10")
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
		result, err = createMigrationBackup(ctx, backupConn, path, MigrationBackupSpec{SourceSchema: 10, TargetSchema: 11, SourceFingerprint: before.Fingerprint, LegacyCipherID: cipher.KeyID(), SourceValidator: "schema-10-security-scan-v1", PairedBuildID: buildID, ReaderContract: "schema-10-security-scan-v1-reader", CreatedAt: identity.CreatedAt})
		backupConn.Close()
		if err != nil {
			return result, err
		}
	}
	script, err := migrationFS.ReadFile("migrations/0011_audit_event.sql")
	if err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, string(script)); err != nil {
		return result, err
	}
	if err = validateForeignKeys(ctx, conn); err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, `UPDATE schema_version SET version=11 WHERE singleton=1 AND version=10`); err != nil {
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

func knownSchemaEleven(catalog []schemaCatalogRow) bool {
	script, err := migrationFS.ReadFile("migrations/0011_audit_event.sql")
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
			if row.table != "audit_event" || row.statement != statement {
				return false
			}
			delete(expected, key)
			continue
		}
		base = append(base, row)
	}
	return len(expected) == 0 && knownSchemaTen(base)
}
