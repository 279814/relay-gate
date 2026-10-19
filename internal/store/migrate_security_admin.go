package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

func initializeEmptySchemaSeventeen(ctx context.Context, db *sql.DB, cipher *Cipher) error {
	if err := initializeEmptySchemaSixteen(ctx, db, cipher); err != nil {
		return err
	}
	_, err := migrateSchemaSixteenToSeventeen(ctx, db, "", cipher, MigrationBackupIdentity{}, "")
	return err
}

func migrateSchemaSixteenToSeventeen(ctx context.Context, db *sql.DB, path string, cipher *Cipher, identity MigrationBackupIdentity, buildID string) (result MigrationBackupResult, err error) {
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
	if before.Version != 16 {
		return result, fmt.Errorf("schema 16→17 requires schema 16")
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
		result, err = createMigrationBackup(ctx, backupConn, path, MigrationBackupSpec{SourceSchema: 16, TargetSchema: 17, SourceFingerprint: before.Fingerprint, LegacyCipherID: cipher.KeyID(), SourceValidator: "schema-16-transform-admin-v1", PairedBuildID: buildID, ReaderContract: "schema-16-transform-admin-v1-reader", CreatedAt: identity.CreatedAt})
		backupConn.Close()
		if err != nil {
			return result, err
		}
	}
	script, err := migrationFS.ReadFile("migrations/0017_security_admin.sql")
	if err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, string(script)); err != nil {
		return result, err
	}
	if err = validateForeignKeys(ctx, conn); err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, `UPDATE schema_version SET version=17 WHERE singleton=1 AND version=16`); err != nil {
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

func knownSchemaSeventeen(catalog []schemaCatalogRow) bool {
	script, err := migrationFS.ReadFile("migrations/0017_security_admin.sql")
	if err != nil {
		return false
	}
	expected := make(map[string]string)
	for _, statement := range strings.Split(string(script), ";") {
		statement = normalizeSchemaStatement(statement)
		if statement == "" || strings.HasPrefix(statement, "ALTER TABLE ") {
			continue
		}
		fields := strings.Fields(statement)
		if len(fields) < 3 || fields[0] != "CREATE" {
			return false
		}
		expected[strings.ToLower(fields[1])+":"+fields[2]] = statement
	}
	const suffix = ", upstream_id INTEGER NOT NULL DEFAULT 0 CHECK (upstream_id >= 0), rule_id TEXT NOT NULL DEFAULT '' CHECK (length(CAST(rule_id AS BLOB)) <= 128))"
	base := make([]schemaCatalogRow, 0, len(catalog))
	found := false
	for _, row := range catalog {
		key := row.objectType + ":" + row.name
		if statement, ok := expected[key]; ok {
			if row.statement != statement || (row.table != "security_finding" && row.table != "security_finding_review" && row.table != "security_ignore_rule") {
				return false
			}
			delete(expected, key)
			continue
		}
		if row.objectType == "table" && row.name == "security_finding" && row.table == "security_finding" {
			original, ok := strings.CutSuffix(row.statement, suffix)
			if !ok {
				return false
			}
			row.statement = original + ")"
			found = true
		}
		base = append(base, row)
	}
	return found && len(expected) == 0 && knownSchemaSixteen(base)
}
