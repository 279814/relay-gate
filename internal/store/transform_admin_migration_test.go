package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func schemaFifteenTransformFixture(t *testing.T) (*Store, *Cipher) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "transform-admin.db")
	cipher, err := NewCipher("transform-admin-migration-master-long-enough")
	if err != nil {
		t.Fatal(err)
	}
	db := openDatabaseAtPath(t, path)
	if err := initializeEmptySchemaFifteen(context.Background(), db, cipher); err != nil {
		t.Fatal(err)
	}
	st := &Store{db: db, cipher: cipher, path: path}
	t.Cleanup(func() { st.Close() })
	return st, cipher
}

func TestTransformAdminMigrationPairsFifteenAndPreservesDraft(t *testing.T) {
	st, cipher := schemaFifteenTransformFixture(t)
	const draft = `{"id":2,"set_id":1,"revision":4,"rules":[]}`
	if _, err := st.db.Exec(`INSERT INTO transform_set(id,name,created_at,draft_json) VALUES(1,'existing transform',1,?)`, draft); err != nil {
		t.Fatal(err)
	}
	before, err := inspectSchemaState(context.Background(), st.db)
	if err != nil {
		t.Fatal(err)
	}
	path := st.path
	st.Close()
	current, err := Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	state, err := inspectSchemaState(context.Background(), current.db)
	if err != nil || state.Version != 16 {
		t.Fatalf("transform admin schema=%+v %v", state, err)
	}
	var stored, lifecycle string
	var revision int64
	if err := current.db.QueryRow(`SELECT draft_json,revision,lifecycle_state FROM transform_set WHERE id=1`).Scan(&stored, &revision, &lifecycle); err != nil || stored != draft || revision != 1 || lifecycle != "active" {
		t.Fatalf("legacy draft/defaults changed: %d %s %v", revision, lifecycle, err)
	}
	files, err := filepath.Glob(filepath.Join(filepath.Dir(path), "backups", "schema-15-to-16-*", "manifest.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("paired15 backup=%v %v", files, err)
	}
	manifest, err := CheckBackup(context.Background(), path, files[0], cipher)
	if err != nil || manifest.SourceFingerprint != before.Fingerprint || manifest.SourceValidator != "schema-15-upstream-sample-v1" || manifest.ReaderContract != "schema-15-upstream-sample-v1-reader" {
		t.Fatalf("schema15 contract=%+v %v", manifest, err)
	}
	db := openDatabaseAtPath(t, filepath.Join(filepath.Dir(files[0]), manifest.DatabaseFile))
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('transform_set') WHERE name IN ('revision','lifecycle_state')`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("transform DDL preceded backup: %d %v", count, err)
	}
}

func TestTransformAdminBackupFailureLeavesFifteen(t *testing.T) {
	st, cipher := schemaFifteenTransformFixture(t)
	path := st.path
	st.Close()
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "backups"), []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	if current, err := Open(path, cipher); err == nil {
		current.Close()
		t.Fatal("transform migration ignored failed backup")
	}
	db := openDatabaseAtPath(t, path)
	defer db.Close()
	state, err := inspectSchemaState(context.Background(), db)
	if err != nil || state.Version != 15 {
		t.Fatalf("failed backup changed source: %+v %v", state, err)
	}
}

func TestTransformAdminSchemaRejectsPartialChangedUnknown(t *testing.T) {
	for _, mutation := range []string{
		`ALTER TABLE transform_set DROP COLUMN lifecycle_state`,
		`ALTER TABLE transform_set RENAME COLUMN revision TO guessed_revision`,
		`CREATE INDEX unknown_transform_state ON transform_set(lifecycle_state)`,
		`PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=replace(sql,"DEFAULT 'active'","DEFAULT 'archived'") WHERE name='transform_set'; PRAGMA writable_schema=OFF`,
	} {
		t.Run(mutation[:min(len(mutation), 48)], func(t *testing.T) {
			st := testStore(t)
			if _, err := st.db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			before := schemaCatalogSnapshot(t, st.db)
			if _, err := inspectSchemaState(context.Background(), st.db); !errors.Is(err, ErrUnknownSchema) {
				t.Fatalf("accepted modified transform schema: %v", err)
			}
			if schemaCatalogSnapshot(t, st.db) != before {
				t.Fatal("inspector repaired transform schema")
			}
		})
	}
}

func TestTransformAdminRotationPinsSixteenReaderAndRestoresState(t *testing.T) {
	st := testStore(t)
	if _, err := st.db.Exec(`INSERT INTO transform_set(id,name,created_at,draft_json,revision,lifecycle_state) VALUES(1,'retained',1,'',5,'disabled')`); err != nil {
		t.Fatal(err)
	}
	backup, err := st.CreateRotationBackup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if m := backup.Manifest; m.SourceSchema != 16 || m.TargetSchema != 16 || m.SourceValidator != "schema-16-transform-admin-v1" || m.ReaderContract != "schema-16-transform-admin-v1-reader" {
		t.Fatalf("transform backup=%+v", m)
	}
	bad := backup.Manifest
	bad.ReaderContract = "schema-15-upstream-sample-v1-reader"
	raw, _ := json.Marshal(bad)
	if err := os.WriteFile(backup.ManifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBackup(context.Background(), st.path, backup.ManifestPath, st.cipher); !errors.Is(err, ErrRestoreRejected) {
		t.Fatalf("accepted old transform reader: %v", err)
	}
	raw, _ = json.Marshal(backup.Manifest)
	if err := os.WriteFile(backup.ManifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	path, cipher := st.path, st.cipher
	st.Close()
	result, err := RestoreDatabase(context.Background(), path, backup.ManifestPath, cipher, true, backup.Manifest.ReaderContract)
	if err != nil || result.RestoredSchemaVersion != 16 {
		t.Fatalf("restore transform=%+v %v", result, err)
	}
	db := openDatabaseAtPath(t, path)
	defer db.Close()
	var state string
	var revision int64
	if err := db.QueryRow(`SELECT revision,lifecycle_state FROM transform_set`).Scan(&revision, &state); err != nil || revision != 5 || state != "disabled" {
		t.Fatalf("lost transform state: %d %s %v", revision, state, err)
	}
}
