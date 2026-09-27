package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

func initializeEmptySchemaSeven(ctx context.Context, db *sql.DB) error {
	if err := initializeEmptySchemaSix(ctx, db); err != nil {
		return err
	}
	return applySchemaSeven(ctx, db)
}

func applySchemaSeven(ctx context.Context, db *sql.DB) (err error) {
	script, err := migrationFS.ReadFile("migrations/0007_sample_group.sql")
	if err != nil {
		return fmt.Errorf("读取 schema 7 migration: %w", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开始 schema 7 migration: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	before, err := inspectSchemaState(ctx, tx)
	if err != nil {
		return fmt.Errorf("schema 7 migration 前检查: %w", err)
	}
	if before.Version != 6 {
		return fmt.Errorf("%w: schema 7 migration 需要 version=6，得到 %+v", ErrUnknownSchema, before)
	}
	if err = runSchemaSevenScript(ctx, tx, script); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE schema_version SET version=7 WHERE singleton=1 AND version=6`); err != nil {
		return fmt.Errorf("标记 schema 7: %w", err)
	}
	after, err := inspectSchemaState(ctx, tx)
	if err != nil {
		return fmt.Errorf("schema 7 migration 后检查: %w", err)
	}
	if after.Version != 7 {
		return fmt.Errorf("%w: schema 7 migration 得到 version=%d fingerprint=%s", ErrUnknownSchema, after.Version, after.Fingerprint)
	}
	if err = validateForeignKeys(ctx, tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("提交 schema 7 migration: %w", err)
	}
	return nil
}

type schemaSevenExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// runSchemaSevenScript 执行 0007 并校验 §5.7 第 10 步的行数：
// 每条旧 sample 恰好得到一条 sample_request 和一条 sample_attempt。
func runSchemaSevenScript(ctx context.Context, db schemaSevenExecutor, script []byte) error {
	var legacyRows int64
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sample`).Scan(&legacyRows); err != nil {
		return fmt.Errorf("统计旧 sample 行数: %w", err)
	}
	if _, err := db.ExecContext(ctx, string(script)); err != nil {
		return fmt.Errorf("执行 schema 7 migration: %w", err)
	}
	var requests, attempts, legacyLinked int64
	if err := db.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM sample_request),
		(SELECT COUNT(*) FROM sample_attempt),
		(SELECT COUNT(*) FROM sample_request WHERE legacy_sample_id = id)`).
		Scan(&requests, &attempts, &legacyLinked); err != nil {
		return fmt.Errorf("校验 schema 7 行数: %w", err)
	}
	if requests != legacyRows || attempts != legacyRows || legacyLinked != legacyRows {
		return fmt.Errorf("%w: schema 7 行数不一致 sample=%d request=%d attempt=%d legacy=%d",
			ErrUnknownSchema, legacyRows, requests, attempts, legacyLinked)
	}
	return nil
}

func migrateSchemaSixToSeven(ctx context.Context, db *sql.DB, databasePath string, cipher *Cipher, identity MigrationBackupIdentity) (result MigrationBackupResult, err error) {
	if cipher == nil {
		return result, ErrNoKey
	}
	script, err := migrationFS.ReadFile("migrations/0007_sample_group.sql")
	if err != nil {
		return result, fmt.Errorf("读取 schema 7 migration: %w", err)
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return result, fmt.Errorf("取得 schema 6→7 migration 连接: %w", err)
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return result, fmt.Errorf("锁定 schema 6→7 migration: %w", err)
	}
	transactionOpen := true
	defer func() {
		if transactionOpen {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()

	state, err := inspectSchemaState(ctx, conn)
	if err != nil {
		return result, fmt.Errorf("锁内重验 schema 6: %w", err)
	}
	if state.Version != 6 {
		return result, fmt.Errorf("%w: schema 6→7 需要 version=6，得到 %+v", ErrUnknownSchema, state)
	}

	backupConn, backupConnErr := db.Conn(ctx)
	if backupConnErr != nil {
		return result, fmt.Errorf("取得 schema 6→7 备份连接: %w", backupConnErr)
	}
	readerContract := identity.ReaderContract
	if readerContract == "" || strings.HasPrefix(readerContract, "schema-") {
		readerContract = "schema-6-reader"
	}
	result, err = createMigrationBackup(ctx, backupConn, databasePath, MigrationBackupSpec{
		SourceSchema:      6,
		SourceFingerprint: state.Fingerprint,
		TargetSchema:      7,
		LegacyCipherID:    cipher.KeyID(),
		SourceValidator:   "schema-6-v1",
		PairedBuildID:     identity.PairedBuildID,
		ReaderContract:    readerContract,
		CreatedAt:         identity.CreatedAt,
	})
	closeBackupErr := backupConn.Close()
	if err != nil {
		return result, fmt.Errorf("创建 schema 6→7 备份: %w", err)
	}
	if closeBackupErr != nil {
		return result, fmt.Errorf("关闭 schema 6→7 备份连接: %w", closeBackupErr)
	}

	if err = runSchemaSevenScript(ctx, conn, script); err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, `UPDATE schema_version SET version=7 WHERE singleton=1 AND version=6`); err != nil {
		return result, fmt.Errorf("标记 schema 7: %w", err)
	}
	after, err := inspectSchemaState(ctx, conn)
	if err != nil {
		return result, fmt.Errorf("校验 schema 7: %w", err)
	}
	if after.Version != 7 {
		return result, fmt.Errorf("%w: schema 6→7 得到 %+v", ErrUnknownSchema, after)
	}
	if err = validateForeignKeys(ctx, conn); err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, `COMMIT`); err != nil {
		return result, fmt.Errorf("提交 schema 6→7: %w", err)
	}
	transactionOpen = false
	return result, nil
}
