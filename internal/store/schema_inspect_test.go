package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectSchemaStateIsReadOnlyAndFailClosed(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T, db *sql.DB)
		wantVersion int
		wantVariant legacySchemaVariant
		wantEmpty   bool
		wantErr     error
	}{
		{
			name:      "empty",
			wantEmpty: true,
		},
		{
			name: "known M2",
			setup: func(t *testing.T, db *sql.DB) {
				t.Helper()
				loadLegacyVariantFixture(t, db, legacySchemaM2)
			},
			wantVariant: legacySchemaM2,
		},
		{
			name: "known M6 pre-column",
			setup: func(t *testing.T, db *sql.DB) {
				t.Helper()
				loadLegacyVariantFixture(t, db, legacySchemaM6PreColumn)
			},
			wantVariant: legacySchemaM6PreColumn,
		},
		{
			name: "known M6 pre-index upgrade path",
			setup: func(t *testing.T, db *sql.DB) {
				t.Helper()
				loadLegacyVariantFixture(t, db, legacySchemaM6PreIndex)
			},
			wantVariant: legacySchemaM6PreIndex,
		},
		{
			name: "known M6 pre-index fresh path",
			setup: func(t *testing.T, db *sql.DB) {
				t.Helper()
				loadLegacySchema(t, db)
			},
			wantVariant: legacySchemaM6PreIndex,
		},
		{
			name: "known M6 current upgrade path",
			setup: func(t *testing.T, db *sql.DB) {
				t.Helper()
				loadLegacyVariantFixture(t, db, legacySchemaM6Current)
			},
			wantVariant: legacySchemaM6Current,
		},
		{
			name: "known M6 current fresh path",
			setup: func(t *testing.T, db *sql.DB) {
				t.Helper()
				loadLegacySchema(t, db)
				if _, err := db.Exec(`CREATE INDEX idx_sample_req ON sample (req_id)`); err != nil {
					t.Fatal(err)
				}
			},
			wantVariant: legacySchemaM6Current,
		},
		{
			name: "unknown unversioned structure",
			setup: func(t *testing.T, db *sql.DB) {
				t.Helper()
				if _, err := db.Exec(`CREATE TABLE mystery (id INTEGER PRIMARY KEY, value TEXT)`); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: ErrUnknownSchema,
		},
		{
			name: "malformed supported schema version one",
			setup: func(t *testing.T, db *sql.DB) {
				t.Helper()
				createSchemaVersionFixture(t, db, 1)
				if _, err := db.Exec(`CREATE TABLE unexpected_v1_table (id INTEGER PRIMARY KEY)`); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: ErrUnknownSchema,
		},
		{
			name: "malformed supported schema version two",
			setup: func(t *testing.T, db *sql.DB) {
				t.Helper()
				createSchemaVersionFixture(t, db, 2)
				if _, err := db.Exec(`CREATE TABLE unexpected_v2_table (id INTEGER PRIMARY KEY)`); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: ErrUnknownSchema,
		},
		{
			name: "newer schema version",
			setup: func(t *testing.T, db *sql.DB) {
				t.Helper()
				createSchemaVersionFixture(t, db, 99)
				if _, err := db.Exec(`CREATE TABLE future_marker (id INTEGER PRIMARY KEY)`); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: ErrSchemaTooNew,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "inspect.db")
			db, err := sql.Open("sqlite", path+connPragmas)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if err := db.Ping(); err != nil {
				t.Fatal(err)
			}
			if tc.setup != nil {
				tc.setup(t, db)
			}

			before := schemaCatalogSnapshot(t, db)
			beforeJournal := journalMode(t, db)
			state, err := inspectSchemaState(context.Background(), db)
			after := schemaCatalogSnapshot(t, db)
			afterJournal := journalMode(t, db)

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("inspect error = %v, want %v", err, tc.wantErr)
			}
			if before != after {
				t.Fatalf("inspection changed sqlite_schema\nbefore: %s\nafter:  %s", before, after)
			}
			if beforeJournal != afterJournal {
				t.Fatalf("inspection changed journal mode from %q to %q", beforeJournal, afterJournal)
			}
			if err != nil {
				return
			}
			if state.Empty != tc.wantEmpty || state.Version != tc.wantVersion || state.Variant != tc.wantVariant {
				t.Fatalf("state = %+v, want empty=%v version=%d variant=%q", state, tc.wantEmpty, tc.wantVersion, tc.wantVariant)
			}
			if !state.Empty && state.Fingerprint == "" {
				t.Fatal("non-empty schema must have a source fingerprint")
			}
		})
	}
}

func createSchemaVersionFixture(t *testing.T, db *sql.DB, version int) {
	t.Helper()
	if _, err := db.Exec(`
		CREATE TABLE schema_version (
			singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
			version INTEGER NOT NULL
		)
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_version(singleton, version) VALUES (1, ?)`, version); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyM6DeltaFixturesMatchHistoricalStartupOrder(t *testing.T) {
	historical := openSchemaTestDB(t, "historical.db")
	loadLegacyVariantFixture(t, historical, legacySchemaM2)
	loadLegacySchema(t, historical)

	fixture := openSchemaTestDB(t, "fixture.db")
	loadLegacyVariantFixture(t, fixture, legacySchemaM6PreColumn)
	assertSchemaFingerprintEqual(t, historical, fixture, "pre-column")

	if _, err := historical.Exec(`ALTER TABLE sample ADD COLUMN req_id TEXT NOT NULL DEFAULT ''`); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join("testdata", "legacy-m6-preindex.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.Exec(string(content)); err != nil {
		t.Fatal(err)
	}
	assertSchemaFingerprintEqual(t, historical, fixture, "pre-index")

	if _, err := historical.Exec(`CREATE INDEX IF NOT EXISTS idx_sample_req ON sample (req_id)`); err != nil {
		t.Fatal(err)
	}
	content, err = os.ReadFile(filepath.Join("testdata", "legacy-m6-current.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.Exec(string(content)); err != nil {
		t.Fatal(err)
	}
	assertSchemaFingerprintEqual(t, historical, fixture, "current")
}

func TestInitializeEmptySchemaOneCreatesKnownVersionWithoutJournalMutation(t *testing.T) {
	db := openSchemaTestDB(t, "empty-to-v1.db")
	beforeJournal := journalMode(t, db)

	if err := initializeEmptySchemaOne(context.Background(), db); err != nil {
		t.Fatalf("initialize schema 1: %v", err)
	}

	afterJournal := journalMode(t, db)
	if afterJournal != beforeJournal {
		t.Fatalf("migration changed journal mode from %q to %q", beforeJournal, afterJournal)
	}
	state, err := inspectSchemaState(context.Background(), db)
	if err != nil {
		t.Fatalf("inspect initialized schema: %v", err)
	}
	if state.Empty || state.Version != 1 || state.Variant != "" {
		t.Fatalf("state = %+v, want version 1", state)
	}
	for _, name := range []string{"upstream", "model_name", "route", "sample", "request_log", "schema_version"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name=?`, name).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("table %s count = %d, want 1", name, count)
		}
	}
	var indexCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_schema WHERE type='index' AND name='idx_sample_req'`).Scan(&indexCount); err != nil {
		t.Fatal(err)
	}
	if indexCount != 1 {
		t.Fatalf("idx_sample_req count = %d, want 1", indexCount)
	}
}

func TestApplySchemaOneRollsBackAllDDLOnFailure(t *testing.T) {
	db := openSchemaTestDB(t, "schema-one-rollback.db")
	script := []byte(`
		CREATE TABLE migration_probe (id INTEGER PRIMARY KEY);
		CREATE TABLE broken (
	`)

	if err := applySchemaOne(context.Background(), db, script); err == nil {
		t.Fatal("invalid migration must fail")
	}
	state, err := inspectSchemaState(context.Background(), db)
	if err != nil {
		t.Fatalf("inspect rolled-back database: %v", err)
	}
	if !state.Empty {
		t.Fatalf("failed migration left schema behind: %+v", state)
	}
}

func openSchemaTestDB(t *testing.T, name string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), name)+connPragmas)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func assertSchemaFingerprintEqual(t *testing.T, left, right *sql.DB, stage string) {
	t.Helper()
	leftCatalog, leftFingerprint, err := readSchemaCatalog(context.Background(), left)
	if err != nil {
		t.Fatal(err)
	}
	rightCatalog, rightFingerprint, err := readSchemaCatalog(context.Background(), right)
	if err != nil {
		t.Fatal(err)
	}
	if leftFingerprint != rightFingerprint {
		limit := min(len(leftCatalog), len(rightCatalog))
		for index := 0; index < limit; index++ {
			if leftCatalog[index] != rightCatalog[index] {
				t.Fatalf("%s fixture differs at catalog row %d\nfixture:   %+v\nhistorical: %+v", stage, index, rightCatalog[index], leftCatalog[index])
			}
		}
		t.Fatalf("%s fixture fingerprint = %s, historical startup = %s", stage, rightFingerprint, leftFingerprint)
	}
}

func loadLegacyVariantFixture(t *testing.T, db *sql.DB, variant legacySchemaVariant) {
	t.Helper()
	files := []string{"legacy-m2.sql"}
	switch variant {
	case legacySchemaM2:
	case legacySchemaM6PreColumn:
		files = append(files, "legacy-m6-precolumn.sql")
	case legacySchemaM6PreIndex:
		files = append(files, "legacy-m6-precolumn.sql", "legacy-m6-preindex.sql")
	case legacySchemaM6Current:
		files = append(files, "legacy-m6-precolumn.sql", "legacy-m6-preindex.sql", "legacy-m6-current.sql")
	default:
		t.Fatalf("unknown fixture variant %q", variant)
	}
	for _, name := range files {
		content, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(string(content)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
}

// loadLegacySchema 建出 schema 1（pre-P0 的结构）。
//
// 它现在读 testdata/legacy-v1.sql —— 这份 SQL 曾是生产用的 schema.sql 并被
// embed 进二进制，但版本化 runner 接管建库后就只剩测试在用它。留在包根
// 且带 //go:embed，会让人误以为启动路径还会执行它。
func loadLegacySchema(t *testing.T, db *sql.DB) {
	t.Helper()
	schema, err := os.ReadFile(filepath.Join("testdata", "legacy-v1.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(schema)); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
}

func schemaCatalogSnapshot(t *testing.T, db *sql.DB) string {
	t.Helper()
	rows, err := db.Query(`
		SELECT type, name, tbl_name, COALESCE(sql, '')
		FROM sqlite_schema
		WHERE name NOT LIKE 'sqlite_%'
		ORDER BY type, name, tbl_name
	`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var snapshot string
	for rows.Next() {
		var objectType, name, table, statement string
		if err := rows.Scan(&objectType, &name, &table, &statement); err != nil {
			t.Fatal(err)
		}
		snapshot += objectType + "\x00" + name + "\x00" + table + "\x00" + statement + "\n"
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func journalMode(t *testing.T, db *sql.DB) string {
	t.Helper()
	var mode string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	return mode
}
