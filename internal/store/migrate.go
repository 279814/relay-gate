package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"
)

const developmentSchemaVersion = 2

//go:embed migrations/*.sql
var migrationFS embed.FS

var (
	ErrUnknownSchema = errors.New("未知数据库结构")
	ErrSchemaTooNew  = errors.New("数据库 schema 版本高于当前程序")
)

type legacySchemaVariant string

const (
	legacySchemaM2          legacySchemaVariant = "m2"
	legacySchemaM6PreColumn legacySchemaVariant = "m6_precolumn"
	legacySchemaM6PreIndex  legacySchemaVariant = "m6_preindex"
	legacySchemaM6Current   legacySchemaVariant = "m6_current"
)

type inspectedSchemaState struct {
	Empty       bool
	Version     int
	Variant     legacySchemaVariant
	Fingerprint string
}

const (
	legacyM2Fingerprint                = "43c11536b89d30c62d41bd0e9533ddc641750ce3738c2a09896197b7a3597750"
	legacyM6PreColumnFingerprint       = "6a32f9b741015bf28c60ab0054f906c15b06a2d8fd7197d980bc7a1018a11609"
	legacyM6PreIndexUpgradeFingerprint = "6b6d564c887b776177c9b63914bc27f1595e762b45957463417e11b0f274794e"
	legacyM6PreIndexFreshFingerprint   = "e2927dc50adb831e9c18131bd00a5e5ba6fff3e9e67f49d210119d1aebfa3bf3"
	legacyM6CurrentUpgradeFingerprint  = "88d2490416e4bc0213ec9a9d91663e6055b7165bf0076da787275cc07832ff0a"
	legacyM6CurrentFreshFingerprint    = "65687b7c654be8f076091ebb211f5fb78f264e13795176d696c2b1e96f003993"
	schemaV1FreshFingerprint           = "cef6c9e40b9fe61f3faf3bb3b4c3262713c5d74482ecff6d85a634725efebc8c"
	schemaV1M2UpgradeFingerprint       = "ea5bae56d38415486c8f4b9f57c1e59699b58d49df18b6186fce8af17e808a9d"
	schemaV1M6UpgradeFingerprint       = "56fca9b32c6683310c6808fa6c1a5400d72e847703112e6debbd33dc94b15ea2"
	schemaV2FreshFingerprint           = "ca6217482a0464d771535862bc99f2624f985732fdc4b7f951b00810b655bcbf"
	schemaV2M2UpgradeFingerprint       = "82fbd450859331bc56bebeb2b5019e2d3bf26d53a722c4f042e2d8d5b0898295"
	schemaV2M6UpgradeFingerprint       = "0be11e42d9f087afba819457b94458d03aa595e9a504d49ee9dce6ac1b1c4710"
)

type schemaQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

type schemaCatalogRow struct {
	objectType string
	name       string
	table      string
	statement  string
}

func inspectSchemaState(ctx context.Context, db schemaQuerier) (inspectedSchemaState, error) {
	catalog, fingerprint, err := readSchemaCatalog(ctx, db)
	if err != nil {
		return inspectedSchemaState{}, err
	}
	if len(catalog) == 0 {
		return inspectedSchemaState{Empty: true}, nil
	}

	if schemaCatalogContains(catalog, "table", "schema_version") {
		version, err := readSchemaVersion(ctx, db)
		if err != nil {
			return inspectedSchemaState{}, err
		}
		if version > developmentSchemaVersion {
			return inspectedSchemaState{}, fmt.Errorf("%w: database=%d program=%d", ErrSchemaTooNew, version, developmentSchemaVersion)
		}
		if !schemaVersionFingerprintKnown(version, fingerprint) {
			return inspectedSchemaState{}, fmt.Errorf("%w: version=%d fingerprint=%s", ErrUnknownSchema, version, fingerprint)
		}
		return inspectedSchemaState{Version: version, Fingerprint: fingerprint}, nil
	}

	legacyVariants := map[string]legacySchemaVariant{
		legacyM2Fingerprint:                legacySchemaM2,
		legacyM6PreColumnFingerprint:       legacySchemaM6PreColumn,
		legacyM6PreIndexUpgradeFingerprint: legacySchemaM6PreIndex,
		legacyM6PreIndexFreshFingerprint:   legacySchemaM6PreIndex,
		legacyM6CurrentUpgradeFingerprint:  legacySchemaM6Current,
		legacyM6CurrentFreshFingerprint:    legacySchemaM6Current,
	}
	if variant, ok := legacyVariants[fingerprint]; ok {
		return inspectedSchemaState{Variant: variant, Fingerprint: fingerprint}, nil
	}
	return inspectedSchemaState{}, fmt.Errorf("%w: fingerprint=%s", ErrUnknownSchema, fingerprint)
}

func schemaVersionFingerprintKnown(version int, fingerprint string) bool {
	switch version {
	case 1:
		switch fingerprint {
		case schemaV1FreshFingerprint, schemaV1M2UpgradeFingerprint, schemaV1M6UpgradeFingerprint:
			return true
		}
	case 2:
		return fingerprint == schemaV2FreshFingerprint ||
			fingerprint == schemaV2M2UpgradeFingerprint ||
			fingerprint == schemaV2M6UpgradeFingerprint
	}
	return false
}

func readSchemaCatalog(ctx context.Context, db schemaQuerier) ([]schemaCatalogRow, string, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT type, name, tbl_name, COALESCE(sql, '')
		FROM sqlite_schema
		WHERE name NOT LIKE 'sqlite_%'
		ORDER BY type, name, tbl_name
	`)
	if err != nil {
		return nil, "", fmt.Errorf("读取数据库结构: %w", err)
	}
	defer rows.Close()

	digest := sha256.New()
	catalog := make([]schemaCatalogRow, 0)
	for rows.Next() {
		var row schemaCatalogRow
		if err := rows.Scan(&row.objectType, &row.name, &row.table, &row.statement); err != nil {
			return nil, "", fmt.Errorf("扫描数据库结构: %w", err)
		}
		row.statement = normalizeSchemaStatement(row.statement)
		catalog = append(catalog, row)
		writeSchemaFingerprintField(digest, row.objectType)
		writeSchemaFingerprintField(digest, row.name)
		writeSchemaFingerprintField(digest, row.table)
		writeSchemaFingerprintField(digest, row.statement)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("遍历数据库结构: %w", err)
	}
	return catalog, hex.EncodeToString(digest.Sum(nil)), nil
}

func normalizeSchemaStatement(statement string) string {
	statement = strings.ReplaceAll(statement, "\r\n", "\n")
	statement = strings.ReplaceAll(statement, "\r", "\n")
	return strings.TrimSpace(statement)
}

func writeSchemaFingerprintField(digest hash.Hash, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = digest.Write(size[:])
	_, _ = digest.Write([]byte(value))
}

func schemaCatalogContains(catalog []schemaCatalogRow, objectType, name string) bool {
	for _, row := range catalog {
		if row.objectType == objectType && row.name == name {
			return true
		}
	}
	return false
}

func readSchemaVersion(ctx context.Context, db schemaQuerier) (int, error) {
	rows, err := db.QueryContext(ctx, `SELECT singleton, version FROM schema_version ORDER BY singleton`)
	if err != nil {
		return 0, fmt.Errorf("%w: 读取 schema_version: %v", ErrUnknownSchema, err)
	}
	defer rows.Close()

	count := 0
	version := 0
	for rows.Next() {
		var singleton int
		if err := rows.Scan(&singleton, &version); err != nil {
			return 0, fmt.Errorf("%w: 扫描 schema_version: %v", ErrUnknownSchema, err)
		}
		count++
		if singleton != 1 || count > 1 {
			return 0, fmt.Errorf("%w: schema_version 必须只有 singleton=1", ErrUnknownSchema)
		}
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("%w: 遍历 schema_version: %v", ErrUnknownSchema, err)
	}
	if count != 1 || version < 1 {
		return 0, fmt.Errorf("%w: schema_version 行无效", ErrUnknownSchema)
	}
	return version, nil
}

func initializeEmptySchemaOne(ctx context.Context, db *sql.DB) (err error) {
	script, err := migrationFS.ReadFile("migrations/0001_legacy.sql")
	if err != nil {
		return fmt.Errorf("读取 schema 1 migration: %w", err)
	}
	return applySchemaOne(ctx, db, script)
}

func initializeEmptySchemaTwo(ctx context.Context, db *sql.DB) error {
	if err := initializeEmptySchemaOne(ctx, db); err != nil {
		return err
	}
	script, err := migrationFS.ReadFile("migrations/0002_p0_probe.sql")
	if err != nil {
		return fmt.Errorf("读取 schema 2 migration: %w", err)
	}
	return applySchemaTwo(ctx, db, script)
}

func applySchemaOne(ctx context.Context, db *sql.DB, script []byte) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开始 schema 1 migration: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	before, err := inspectSchemaState(ctx, tx)
	if err != nil {
		return fmt.Errorf("schema 1 migration 前检查: %w", err)
	}
	if !before.Empty {
		return fmt.Errorf("%w: schema 1 空库初始化收到非空数据库", ErrUnknownSchema)
	}
	if _, err = tx.ExecContext(ctx, string(script)); err != nil {
		return fmt.Errorf("执行 schema 1 migration: %w", err)
	}
	// 版本行必须是本事务最后一条写 SQL，避免 DDL 成功但版本未推进的 crash gap。
	if _, err = tx.ExecContext(ctx, `INSERT INTO schema_version(singleton, version) VALUES (1, 1)`); err != nil {
		return fmt.Errorf("标记 schema 1: %w", err)
	}
	after, err := inspectSchemaState(ctx, tx)
	if err != nil {
		return fmt.Errorf("schema 1 migration 后检查: %w", err)
	}
	if after.Version != 1 {
		return fmt.Errorf("%w: schema 1 migration 得到 version=%d", ErrUnknownSchema, after.Version)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("提交 schema 1 migration: %w", err)
	}
	return nil
}

func applySchemaTwo(ctx context.Context, db *sql.DB, script []byte) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开始 schema 2 migration: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	before, err := inspectSchemaState(ctx, tx)
	if err != nil {
		return fmt.Errorf("schema 2 migration 前检查: %w", err)
	}
	if before.Version != 1 {
		return fmt.Errorf("%w: schema 2 migration 需要 version=1，得到 %+v", ErrUnknownSchema, before)
	}
	if _, err = tx.ExecContext(ctx, string(script)); err != nil {
		return fmt.Errorf("执行 schema 2 migration: %w", err)
	}
	// 与所有 migration 一样，schema_version 必须是事务中的最后一条写 SQL。
	if _, err = tx.ExecContext(ctx, `UPDATE schema_version SET version=2 WHERE singleton=1 AND version=1`); err != nil {
		return fmt.Errorf("标记 schema 2: %w", err)
	}
	after, err := inspectSchemaState(ctx, tx)
	if err != nil {
		return fmt.Errorf("schema 2 migration 后检查: %w", err)
	}
	if after.Version != 2 {
		return fmt.Errorf("%w: schema 2 migration 得到 version=%d", ErrUnknownSchema, after.Version)
	}
	if err = validateForeignKeys(ctx, tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("提交 schema 2 migration: %w", err)
	}
	return nil
}

func migrateSchemaOneToTwo(ctx context.Context, db *sql.DB, databasePath string, cipher *Cipher, identity MigrationBackupIdentity) (result MigrationBackupResult, err error) {
	if cipher == nil {
		return result, ErrNoKey
	}
	script, err := migrationFS.ReadFile("migrations/0002_p0_probe.sql")
	if err != nil {
		return result, fmt.Errorf("读取 schema 2 migration: %w", err)
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return result, fmt.Errorf("取得 schema 1→2 migration 连接: %w", err)
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return result, fmt.Errorf("锁定 schema 1→2 migration: %w", err)
	}
	transactionOpen := true
	defer func() {
		if transactionOpen {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()

	state, err := inspectSchemaState(ctx, conn)
	if err != nil {
		return result, fmt.Errorf("锁内重验 schema 1: %w", err)
	}
	if state.Version != 1 {
		return result, fmt.Errorf("%w: schema 1→2 需要 version=1，得到 %+v", ErrUnknownSchema, state)
	}
	if err = validateLegacyUpstreamKeys(ctx, conn, cipher); err != nil {
		return result, err
	}

	backupConn, backupConnErr := db.Conn(ctx)
	if backupConnErr != nil {
		return result, fmt.Errorf("取得 schema 1→2 备份连接: %w", backupConnErr)
	}
	result, err = createMigrationBackup(ctx, backupConn, databasePath, MigrationBackupSpec{
		SourceSchema:      1,
		SourceFingerprint: state.Fingerprint,
		TargetSchema:      2,
		LegacyCipherID:    cipher.KeyID(),
		SourceValidator:   "schema-1-v1",
		PairedBuildID:     identity.PairedBuildID,
		ReaderContract:    identity.ReaderContract,
		CreatedAt:         identity.CreatedAt,
	})
	closeBackupErr := backupConn.Close()
	if err != nil {
		return result, fmt.Errorf("创建 schema 1→2 备份: %w", err)
	}
	if closeBackupErr != nil {
		return result, fmt.Errorf("关闭 schema 1→2 备份连接: %w", closeBackupErr)
	}

	if _, err = conn.ExecContext(ctx, string(script)); err != nil {
		return result, fmt.Errorf("执行 schema 2 migration: %w", err)
	}
	// Backfill belongs to this transaction; schema_version remains the final write.
	if err = backfillSchemaTwo(ctx, conn, cipher); err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, `UPDATE schema_version SET version=2 WHERE singleton=1 AND version=1`); err != nil {
		return result, fmt.Errorf("标记 schema 2: %w", err)
	}
	after, err := inspectSchemaState(ctx, conn)
	if err != nil {
		return result, fmt.Errorf("校验 schema 2: %w", err)
	}
	if after.Version != 2 {
		return result, fmt.Errorf("%w: schema 1→2 得到 %+v", ErrUnknownSchema, after)
	}
	if err = validateForeignKeys(ctx, conn); err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, `COMMIT`); err != nil {
		return result, fmt.Errorf("提交 schema 1→2: %w", err)
	}
	transactionOpen = false
	return result, nil
}

type schemaTwoExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func normalizeLegacyToSchemaOne(ctx context.Context, db *sql.DB, databasePath string, cipher *Cipher, identity MigrationBackupIdentity) (result MigrationBackupResult, err error) {
	if cipher == nil {
		return result, ErrNoKey
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return result, fmt.Errorf("取得 migration 连接: %w", err)
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return result, fmt.Errorf("锁定 legacy migration: %w", err)
	}
	transactionOpen := true
	defer func() {
		if transactionOpen {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()

	state, err := inspectSchemaState(ctx, conn)
	if err != nil {
		return result, fmt.Errorf("锁内重验 legacy schema: %w", err)
	}
	if state.Version != 0 || state.Variant == "" {
		return result, fmt.Errorf("%w: 需要已知 legacy schema，得到 %+v", ErrUnknownSchema, state)
	}
	if err = validateLegacyUpstreamKeys(ctx, conn, cipher); err != nil {
		return result, err
	}

	// SQLite's online backup API returns SQLITE_BUSY when the source handle is
	// the same connection that owns BEGIN IMMEDIATE. Keep the writer lock on
	// conn, and copy the now-stable committed snapshot through a second reader.
	backupConn, backupConnErr := db.Conn(ctx)
	if backupConnErr != nil {
		return result, fmt.Errorf("取得 migration 备份连接: %w", backupConnErr)
	}
	result, err = createMigrationBackup(ctx, backupConn, databasePath, MigrationBackupSpec{
		SourceSchema:      0,
		SourceVariant:     string(state.Variant),
		SourceFingerprint: state.Fingerprint,
		TargetSchema:      1,
		LegacyCipherID:    cipher.KeyID(),
		SourceValidator:   "legacy-" + string(state.Variant) + "-v1",
		PairedBuildID:     identity.PairedBuildID,
		ReaderContract:    identity.ReaderContract,
		CreatedAt:         identity.CreatedAt,
	})
	closeBackupErr := backupConn.Close()
	if err != nil {
		return result, fmt.Errorf("创建 schema 0→1 备份: %w", err)
	}
	if closeBackupErr != nil {
		return result, fmt.Errorf("关闭 migration 备份连接: %w", closeBackupErr)
	}

	for _, statement := range legacyNormalizationStatements(state.Variant) {
		if _, err = conn.ExecContext(ctx, statement); err != nil {
			return result, fmt.Errorf("normalize %s: %w", state.Variant, err)
		}
	}
	// schema_version is deliberately the final write in this transaction.
	if _, err = conn.ExecContext(ctx, `INSERT INTO schema_version(singleton, version) VALUES (1, 1)`); err != nil {
		return result, fmt.Errorf("标记 schema 1: %w", err)
	}
	after, err := inspectSchemaState(ctx, conn)
	if err != nil {
		return result, fmt.Errorf("校验 schema 1 normalization: %w", err)
	}
	if after.Version != 1 {
		return result, fmt.Errorf("%w: normalization 得到 %+v", ErrUnknownSchema, after)
	}
	if err = validateForeignKeys(ctx, conn); err != nil {
		return result, err
	}
	if _, err = conn.ExecContext(ctx, `COMMIT`); err != nil {
		return result, fmt.Errorf("提交 schema 0→1: %w", err)
	}
	transactionOpen = false
	return result, nil
}

func validateLegacyUpstreamKeys(ctx context.Context, db schemaQuerier, cipher *Cipher) error {
	rows, err := db.QueryContext(ctx, `SELECT id, name, api_key_enc FROM upstream ORDER BY id`)
	if err != nil {
		return fmt.Errorf("读取 legacy upstream 密文: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var name, encrypted string
		if err := rows.Scan(&id, &name, &encrypted); err != nil {
			return fmt.Errorf("扫描 legacy upstream 密文: %w", err)
		}
		if _, err := cipher.Decrypt(encrypted); err != nil {
			return fmt.Errorf("upstream %d(%s) 的 api_key: %w", id, name, err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("遍历 legacy upstream 密文: %w", err)
	}
	return nil
}

func validateForeignKeys(ctx context.Context, db schemaQuerier) error {
	rows, err := db.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return fmt.Errorf("执行 foreign_key_check: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return fmt.Errorf("%w: foreign_key_check 发现违规行", ErrUnknownSchema)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("读取 foreign_key_check: %w", err)
	}
	return nil
}

func legacyNormalizationStatements(variant legacySchemaVariant) []string {
	statements := make([]string, 0, 8)
	if variant == legacySchemaM2 {
		statements = append(statements,
			legacyRequestLogTableSQL,
			`CREATE INDEX idx_reqlog_ts ON request_log (ts_recv DESC)`,
			`CREATE INDEX idx_reqlog_req ON request_log (req_id, attempt)`,
			`CREATE INDEX idx_reqlog_route ON request_log (route_id, ts_recv DESC)`,
			`CREATE INDEX idx_reqlog_upstream ON request_log (upstream_id, ts_recv DESC)`,
		)
	}
	if variant == legacySchemaM2 || variant == legacySchemaM6PreColumn {
		statements = append(statements, `ALTER TABLE sample ADD COLUMN req_id TEXT NOT NULL DEFAULT ''`)
	}
	if variant != legacySchemaM6Current {
		statements = append(statements, `CREATE INDEX idx_sample_req ON sample (req_id)`)
	}
	statements = append(statements, `CREATE TABLE schema_version (
		singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
		version INTEGER NOT NULL
	)`)
	return statements
}

const legacyRequestLogTableSQL = `CREATE TABLE request_log (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	req_id TEXT NOT NULL,
	attempt INTEGER NOT NULL DEFAULT 1,
	attempts INTEGER NOT NULL DEFAULT 1,
	ts_recv INTEGER NOT NULL,
	ts_sent INTEGER NOT NULL DEFAULT 0,
	ts_first_byte INTEGER NOT NULL DEFAULT 0,
	ts_done INTEGER NOT NULL DEFAULT 0,
	endpoint TEXT NOT NULL DEFAULT '',
	model_in TEXT NOT NULL DEFAULT '',
	model_out TEXT NOT NULL DEFAULT '',
	model_name_id INTEGER NOT NULL DEFAULT 0,
	route_id INTEGER NOT NULL DEFAULT 0,
	upstream_id INTEGER NOT NULL DEFAULT 0,
	upstream_name TEXT NOT NULL DEFAULT '',
	resp_status INTEGER NOT NULL DEFAULT 0,
	ttft_ms INTEGER NOT NULL DEFAULT 0,
	bytes_written INTEGER NOT NULL DEFAULT 0,
	outcome TEXT NOT NULL DEFAULT '',
	retried INTEGER NOT NULL DEFAULT 0,
	half_open INTEGER NOT NULL DEFAULT 0,
	error TEXT NOT NULL DEFAULT ''
)`

// migrate 把 0001_legacy.sql 覆盖不到的变更补上。
//
// 为什么需要它：`CREATE TABLE IF NOT EXISTS` 对**已存在**的表是空操作，
// 加不了列。也就是说建表脚本只能让新库长对，老库会静默停在旧结构上 ——
// 而症状是「新字段读出来永远是零值」，不报错、不失败。
//
// 每一条都必须幂等：建表脚本每次都跑一遍，这里也一样。
func migrate(db *sql.DB) error {
	// M6：样本挂上 req_id，与 request_log 同组。
	//
	// 方向是「sample 存 req_id」而不是「request_log 存 sample_id」：
	// 样本 id 由后台 writer 落库时才分配，而日志在转发路径上就要写出去 ——
	// 那一刻 sample_id 还不存在。req_id 是我们自己在请求开始时生成的，
	// 两边都同步可知。
	if err := addColumn(db, "sample", "req_id",
		`ALTER TABLE sample ADD COLUMN req_id TEXT NOT NULL DEFAULT ''`); err != nil {
		return err
	}
	// 老样本没有 req_id（空串），索引照建 —— 空串会挤在一起，
	// 但那部分数据本来就查不到组，不影响新数据的查询。
	if _, err := db.Exec(
		`CREATE INDEX IF NOT EXISTS idx_sample_req ON sample (req_id)`); err != nil {
		return fmt.Errorf("建 idx_sample_req: %w", err)
	}
	return nil
}

// addColumn 幂等地加一列：已存在就跳过。
//
// 先查 PRAGMA 再决定，而不是「无脑 ALTER 然后忽略错误」。后者会把**任何**
// 错误都当成「列已存在」咽掉 —— 磁盘满、库损坏、SQL 写错，全都变成静默跳过，
// 而后果是程序带着一个缺列的表继续跑。
func addColumn(db *sql.DB, table, column, ddl string) error {
	has, err := hasColumn(db, table, column)
	if err != nil {
		return err
	}
	if has {
		return nil
	}
	if _, err := db.Exec(ddl); err != nil {
		return fmt.Errorf("给 %s 加列 %s: %w", table, column, err)
	}
	return nil
}

// hasColumn 查表里有没有这一列。
func hasColumn(db *sql.DB, table, column string) (bool, error) {
	// PRAGMA 不接受参数绑定，表名只能拼进去。这里的表名全是代码里的字面量
	// （不来自用户输入），所以不构成注入面；真要传外部输入进来时必须先做白名单。
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return false, fmt.Errorf("读取 %s 的列信息: %w", table, err)
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}
