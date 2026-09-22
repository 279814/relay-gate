package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

func initializeEmptySchemaFive(ctx context.Context, db *sql.DB) error {
	if err := initializeEmptySchemaFour(ctx, db); err != nil {
		return err
	}
	return applySchemaFive(ctx, db)
}

func applySchemaFive(ctx context.Context, db *sql.DB) (err error) {
	script, err := migrationFS.ReadFile("migrations/0005_p3_security.sql")
	if err != nil {
		return fmt.Errorf("读取 schema 5 migration: %w", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开始 schema 5 migration: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	before, err := inspectSchemaState(ctx, tx)
	if err != nil {
		return fmt.Errorf("schema 5 migration 前检查: %w", err)
	}
	if before.Version != 4 {
		return fmt.Errorf("%w: schema 5 migration 需要 version=4，得到 %+v", ErrUnknownSchema, before)
	}
	if _, err = tx.ExecContext(ctx, string(script)); err != nil {
		return fmt.Errorf("执行 schema 5 migration: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE schema_version SET version=5 WHERE singleton=1 AND version=4`); err != nil {
		return fmt.Errorf("标记 schema 5: %w", err)
	}
	after, err := inspectSchemaState(ctx, tx)
	if err != nil {
		return fmt.Errorf("schema 5 migration 后检查: %w", err)
	}
	if after.Version != 5 {
		return fmt.Errorf("%w: schema 5 migration 得到 version=%d fingerprint=%s", ErrUnknownSchema, after.Version, after.Fingerprint)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("提交 schema 5 migration: %w", err)
	}
	return nil
}

func migrateSchemaFourToFive(ctx context.Context, db *sql.DB, databasePath string, cipher *Cipher, identity MigrationBackupIdentity) (result MigrationBackupResult, err error) {
	if cipher == nil {
		return result, ErrNoKey
	}
	script, err := migrationFS.ReadFile("migrations/0005_p3_security.sql")
	if err != nil {
		return result, fmt.Errorf("读取 schema 5 migration: %w", err)
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return result, fmt.Errorf("取得 schema 4→5 migration 连接: %w", err)
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return result, fmt.Errorf("锁定 schema 4→5 migration: %w", err)
	}
	transactionOpen := true
	defer func() {
		if transactionOpen {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()

	state, err := inspectSchemaState(ctx, conn)
	if err != nil {
		return result, fmt.Errorf("锁内重验 schema 4: %w", err)
	}
	if state.Version != 4 {
		return result, fmt.Errorf("%w: schema 4→5 需要 version=4，得到 %+v", ErrUnknownSchema, state)
	}

	backupConn, backupConnErr := db.Conn(ctx)
	if backupConnErr != nil {
		return result, fmt.Errorf("取得 schema 4→5 备份连接: %w", backupConnErr)
	}
	readerContract := identity.ReaderContract
	if readerContract == "" || strings.HasPrefix(readerContract, "schema-") {
		readerContract = "schema-4-reader"
	}
	result, err = createMigrationBackup(ctx, backupConn, databasePath, MigrationBackupSpec{
		SourceSchema:      4,
		SourceFingerprint: state.Fingerprint,
		TargetSchema:      5,
		LegacyCipherID:    cipher.KeyID(),
		SourceValidator:   "schema-4-v1",
		PairedBuildID:     identity.PairedBuildID,
		ReaderContract:    readerContract,
		CreatedAt:         identity.CreatedAt,
	})
	closeBackupErr := backupConn.Close()
	if err != nil {
		return result, fmt.Errorf("创建 schema 4→5 备份: %w", err)
	}
	if closeBackupErr != nil {
		return result, fmt.Errorf("关闭 schema 4→5 备份连接: %w", closeBackupErr)
	}

	if _, err = conn.ExecContext(ctx, string(script)); err != nil {
		return result, fmt.Errorf("执行 schema 5 migration: %w", err)
	}
	if _, err = conn.ExecContext(ctx, `UPDATE schema_version SET version=5 WHERE singleton=1 AND version=4`); err != nil {
		return result, fmt.Errorf("标记 schema 5: %w", err)
	}
	after, err := inspectSchemaState(ctx, conn)
	if err != nil {
		return result, fmt.Errorf("校验 schema 5: %w", err)
	}
	if after.Version != 5 {
		return result, fmt.Errorf("%w: schema 4→5 得到 %+v", ErrUnknownSchema, after)
	}
	if _, err = conn.ExecContext(ctx, `COMMIT`); err != nil {
		return result, fmt.Errorf("提交 schema 4→5: %w", err)
	}
	transactionOpen = false
	return result, nil
}
