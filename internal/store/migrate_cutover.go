package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"

	"github.com/279814/relay-gate/internal/model"
)

const (
	keyP0Cutover = "p0_cutover"
)

func initializeEmptySchemaThree(ctx context.Context, db *sql.DB) error {
	if err := initializeEmptySchemaTwo(ctx, db); err != nil {
		return err
	}
	script, err := migrationFS.ReadFile("migrations/0003_p0_cutover.sql")
	if err != nil {
		return fmt.Errorf("读取 schema 3 migration: %w", err)
	}
	return applySchemaThree(ctx, db, script, nil)
}

func applySchemaThree(ctx context.Context, db *sql.DB, script []byte, cipher *Cipher) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开始 schema 3 migration: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	before, err := inspectSchemaState(ctx, tx)
	if err != nil {
		return fmt.Errorf("schema 3 migration 前检查: %w", err)
	}
	if before.Version != 2 {
		return fmt.Errorf("%w: schema 3 migration 需要 version=2，得到 %+v", ErrUnknownSchema, before)
	}
	if _, err = tx.ExecContext(ctx, string(script)); err != nil {
		return fmt.Errorf("执行 schema 3 migration: %w", err)
	}
	if err = cutoverFullURLOrigins(ctx, tx, cipher); err != nil {
		return err
	}
	if err = validateSchemaThreeReady(ctx, tx); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE schema_version SET version=3 WHERE singleton=1 AND version=2`); err != nil {
		return fmt.Errorf("标记 schema 3: %w", err)
	}
	after, err := inspectSchemaState(ctx, tx)
	if err != nil {
		return fmt.Errorf("schema 3 migration 后检查: %w", err)
	}
	if after.Version != 3 {
		return fmt.Errorf("%w: schema 3 migration 得到 version=%d", ErrUnknownSchema, after.Version)
	}
	if err = validateForeignKeys(ctx, tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("提交 schema 3 migration: %w", err)
	}
	return nil
}

func migrateSchemaTwoToThree(ctx context.Context, db *sql.DB, databasePath string, cipher *Cipher, identity MigrationBackupIdentity) (result MigrationBackupResult, err error) {
	if cipher == nil {
		return result, ErrNoKey
	}
	script, err := migrationFS.ReadFile("migrations/0003_p0_cutover.sql")
	if err != nil {
		return result, fmt.Errorf("读取 schema 3 migration: %w", err)
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return result, fmt.Errorf("取得 schema 2→3 migration 连接: %w", err)
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return result, fmt.Errorf("锁定 schema 2→3 migration: %w", err)
	}
	transactionOpen := true
	defer func() {
		if transactionOpen {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()

	state, err := inspectSchemaState(ctx, conn)
	if err != nil {
		return result, fmt.Errorf("锁内重验 schema 2: %w", err)
	}
	if state.Version != 2 {
		return result, fmt.Errorf("%w: schema 2→3 需要 version=2，得到 %+v", ErrUnknownSchema, state)
	}
	if err = validateSchemaTwoForCutover(ctx, conn, cipher); err != nil {
		return result, err
	}

	backupConn, backupConnErr := db.Conn(ctx)
	if backupConnErr != nil {
		return result, fmt.Errorf("取得 schema 2→3 备份连接: %w", backupConnErr)
	}
	readerContract := identity.ReaderContract
	if readerContract == "" || readerContract == "schema-1-reader" {
		readerContract = "schema-2-reader"
	}
	result, err = createMigrationBackup(ctx, backupConn, databasePath, MigrationBackupSpec{
		SourceSchema:      2,
		SourceFingerprint: state.Fingerprint,
		TargetSchema:      3,
		LegacyCipherID:    cipher.KeyID(),
		SourceValidator:   "schema-2-v1",
		PairedBuildID:     identity.PairedBuildID,
		ReaderContract:    readerContract,
		CreatedAt:         identity.CreatedAt,
	})
	closeBackupErr := backupConn.Close()
	if err != nil {
		return result, fmt.Errorf("创建 schema 2→3 备份: %w", err)
	}
	if closeBackupErr != nil {
		return result, fmt.Errorf("关闭 schema 2→3 备份连接: %w", closeBackupErr)
	}

	if _, err = conn.ExecContext(ctx, string(script)); err != nil {
		return result, fmt.Errorf("执行 schema 3 migration: %w", err)
	}
	if err = cutoverFullURLOrigins(ctx, conn, cipher); err != nil {
		return result, err
	}
	if err = validateSchemaThreeReady(ctx, conn); err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, `UPDATE schema_version SET version=3 WHERE singleton=1 AND version=2`); err != nil {
		return result, fmt.Errorf("标记 schema 3: %w", err)
	}
	after, err := inspectSchemaState(ctx, conn)
	if err != nil {
		return result, fmt.Errorf("校验 schema 3: %w", err)
	}
	if after.Version != 3 {
		return result, fmt.Errorf("%w: schema 2→3 得到 %+v", ErrUnknownSchema, after)
	}
	if err = validateForeignKeys(ctx, conn); err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, `COMMIT`); err != nil {
		return result, fmt.Errorf("提交 schema 2→3: %w", err)
	}
	transactionOpen = false
	return result, nil
}

type cutoverDB interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func cutoverFullURLOrigins(ctx context.Context, db cutoverDB, cipher *Cipher) error {
	rows, err := db.QueryContext(ctx, `SELECT id, base_url, full_url_mode, enabled FROM upstream WHERE full_url_mode=1`)
	if err != nil {
		return fmt.Errorf("列举 full_url upstream: %w", err)
	}
	defer rows.Close()
	type item struct {
		id      int64
		baseURL string
		enabled bool
	}
	var items []item
	for rows.Next() {
		var it item
		var mode int
		var enabled int
		if err := rows.Scan(&it.id, &it.baseURL, &mode, &enabled); err != nil {
			return err
		}
		it.enabled = enabled != 0
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, it := range items {
		origin, ok := safeOrigin(it.baseURL)
		enabled := it.enabled
		if !ok {
			origin = "http://invalid.invalid"
			enabled = false
		}
		if _, err := db.ExecContext(ctx, `UPDATE upstream SET base_url=?, full_url_mode=0, enabled=?,
			network_revision=network_revision+1, revision=revision+1, updated_at=? WHERE id=?`,
			origin, boolToInt(enabled), nowMS(), it.id); err != nil {
			return fmt.Errorf("cutover upstream %d origin: %w", it.id, err)
		}
	}
	_ = cipher
	return nil
}

func safeOrigin(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}
	if u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		// Strip userinfo/query/fragment by rebuilding.
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	return u.Scheme + "://" + u.Host, true
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func validateSchemaTwoForCutover(ctx context.Context, db cutoverDB, cipher *Cipher) error {
	if err := validateLegacyUpstreamKeys(ctx, db, cipher); err != nil {
		return err
	}
	// Every enabled Route must have a matching Endpoint for its protocol.
	rows, err := db.QueryContext(ctx, `
		SELECT r.id, r.upstream_id, m.protocol
		FROM route r JOIN model_name m ON m.id = r.model_name_id
		WHERE r.enabled=1`)
	if err != nil {
		return fmt.Errorf("列举活动 Route: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var routeID, upstreamID int64
		var protocol model.Protocol
		if err := rows.Scan(&routeID, &upstreamID, &protocol); err != nil {
			return err
		}
		endpoint, ok := protocol.Endpoint()
		if !ok {
			return fmt.Errorf("route %d protocol %q 无 Endpoint 映射", routeID, protocol)
		}
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM upstream_endpoint
			WHERE upstream_id=? AND endpoint=?`, upstreamID, string(endpoint)).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("route %d upstream %d 缺少 endpoint %s，拒绝 cutover", routeID, upstreamID, endpoint)
		}
		if protocol == model.ProtoAnthropic {
			if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM upstream_endpoint
				WHERE upstream_id=? AND endpoint=?`, upstreamID, string(model.EndpointCountTokens)).Scan(&n); err != nil {
				return err
			}
			if n == 0 {
				return fmt.Errorf("route %d anthropic upstream %d 缺少 count_tokens endpoint", routeID, upstreamID)
			}
		}
	}
	return rows.Err()
}

func validateSchemaThreeReady(ctx context.Context, db cutoverDB) error {
	var headersLeft int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM upstream WHERE probe_headers IS NOT NULL AND probe_headers != ''`).Scan(&headersLeft); err != nil {
		return err
	}
	if headersLeft != 0 {
		return fmt.Errorf("cutover 后仍有 %d 行 probe_headers 明文", headersLeft)
	}
	var fullURLLeft int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM upstream WHERE full_url_mode=1`).Scan(&fullURLLeft); err != nil {
		return err
	}
	if fullURLLeft != 0 {
		return fmt.Errorf("cutover 后仍有 %d 行 full_url_mode=1", fullURLLeft)
	}
	var costLeft int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM setting WHERE key=?`, keyProbeCost).Scan(&costLeft); err != nil {
		return err
	}
	if costLeft != 0 {
		return fmt.Errorf("cutover 后仍保留旧 probe_cost_today")
	}
	var marker string
	if err := db.QueryRowContext(ctx, `SELECT value FROM setting WHERE key=?`, keyP0Cutover).Scan(&marker); err != nil {
		return fmt.Errorf("缺少 p0_cutover marker: %w", err)
	}
	if marker != "schema3" {
		return fmt.Errorf("p0_cutover marker = %q", marker)
	}
	return validateForeignKeys(ctx, db)
}

// CutoverCompleted reports whether this store finished schema-3 cutover.
func (s *Store) CutoverCompleted(ctx context.Context) (bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM setting WHERE key=?`, keyP0Cutover).Scan(&v)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return v == "schema3", nil
}
