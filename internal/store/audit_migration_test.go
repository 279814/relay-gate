package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func schemaTenAuditFixture(t *testing.T) (*Store, *Cipher) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	cipher, err := NewCipher("audit-migration-master-long-enough")
	if err != nil {
		t.Fatal(err)
	}
	db := openDatabaseAtPath(t, path)
	if err := initializeEmptySchemaTen(context.Background(), db, cipher); err != nil {
		t.Fatal(err)
	}
	st := &Store{db: db, cipher: cipher, path: path}
	t.Cleanup(func() { st.Close() })
	return st, cipher
}

func TestAuditMigrationBackupFailureLeavesSchemaTenUntouched(t *testing.T) {
	st, cipher := schemaTenAuditFixture(t)
	path := st.path
	st.Close()
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "backups"), []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(path, cipher); err == nil {
		opened.Close()
		t.Fatal("audit migration ignored its failed paired backup")
	}
	db := openDatabaseAtPath(t, path)
	defer db.Close()
	state, err := inspectSchemaState(context.Background(), db)
	if err != nil || state.Version != 10 {
		t.Fatalf("failed audit backup changed source: state=%+v err=%v", state, err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_schema WHERE name='audit_event'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("audit DDL preceded backup: count=%d err=%v", count, err)
	}
}

func TestAuditSchemaRejectsPartialChangedAndUnknownObjectsWithoutRepair(t *testing.T) {
	for _, kind := range []string{"partial", "missing index", "changed", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			st, _ := schemaTenAuditFixture(t)
			if kind == "partial" {
				if _, err := st.db.Exec(`CREATE TABLE audit_event(id INTEGER PRIMARY KEY); UPDATE schema_version SET version=11`); err != nil {
					t.Fatal(err)
				}
			} else {
				script, err := migrationFS.ReadFile("migrations/0011_audit_event.sql")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := st.db.Exec(string(script) + `UPDATE schema_version SET version=11`); err != nil {
					t.Fatal(err)
				}
				statement := `CREATE INDEX unreviewed_audit ON audit_event(outcome)`
				if kind == "changed" {
					statement = `ALTER TABLE audit_event RENAME COLUMN actor_hash TO raw_actor`
				} else if kind == "missing index" {
					statement = `DROP INDEX idx_audit_event_at_id`
				}
				if _, err := st.db.Exec(statement); err != nil {
					t.Fatal(err)
				}
			}
			before := schemaCatalogSnapshot(t, st.db)
			if _, err := inspectSchemaState(context.Background(), st.db); !errors.Is(err, ErrUnknownSchema) {
				t.Fatalf("accepted %s audit schema: %v", kind, err)
			}
			if schemaCatalogSnapshot(t, st.db) != before {
				t.Fatal("inspection changed a rejected audit schema")
			}
		})
	}
}

func TestAuditSchemaRotationBackupPinsReaderAndRestoresHistory(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	path, cipher := st.path, st.cipher
	if _, err := st.db.Exec(`INSERT INTO audit_event(operation_id,at_ms,category,action,resource_type,resource_id,actor_hash)
		VALUES ('0123456789abcdef0123456789abcdef',1,'route','route_disable','route','1',?)`, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	backup, err := st.CreateRotationBackup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if m := backup.Manifest; m.SourceSchema != 11 || m.TargetSchema != 11 || m.SourceValidator != "schema-11-audit-v1" || m.ReaderContract != "schema-11-audit-v1-reader" {
		t.Fatalf("audit backup pairing=%+v", m)
	}
	if _, err := CheckBackup(ctx, path, backup.ManifestPath, cipher); err != nil {
		t.Fatal(err)
	}
	bad := backup.Manifest
	bad.ReaderContract = "schema-10-security-scan-v1-reader"
	raw, _ := json.Marshal(bad)
	if err := os.WriteFile(backup.ManifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBackup(ctx, path, backup.ManifestPath, cipher); !errors.Is(err, ErrRestoreRejected) {
		t.Fatalf("audit backup accepted an old reader: %v", err)
	}
	raw, _ = json.Marshal(backup.Manifest)
	if err := os.WriteFile(backup.ManifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	st.Close()
	result, err := RestoreDatabase(ctx, path, backup.ManifestPath, cipher, true, backup.Manifest.ReaderContract)
	if err != nil || result.RestoredSchemaVersion != 11 {
		t.Fatalf("restored audit schema=%+v err=%v", result, err)
	}
	restored, err := Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	var action string
	if err := restored.db.QueryRow(`SELECT action FROM audit_event`).Scan(&action); err != nil || action != "route_disable" {
		t.Fatalf("audit history lost in backup: action=%s err=%v", action, err)
	}
}

func TestAuditMigrationPairsSchemaTenBeforeCreatingHistory(t *testing.T) {
	ctx := context.Background()
	st, cipher := schemaTenAuditFixture(t)
	before, err := inspectSchemaState(ctx, st.db)
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
	state, err := inspectSchemaState(ctx, current.db)
	if err != nil || state.Version != 11 {
		t.Fatalf("audit schema=%+v err=%v", state, err)
	}
	files, err := filepath.Glob(filepath.Join(filepath.Dir(path), "backups", "schema-10-to-11-*", "manifest.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("paired schema10 backup missing: files=%v err=%v", files, err)
	}
	m, err := CheckBackup(ctx, path, files[0], cipher)
	if err != nil || m.SourceSchema != 10 || m.TargetSchema != 11 || m.SourceFingerprint != before.Fingerprint || m.ReaderContract != "schema-10-security-scan-v1-reader" || m.SourceValidator != "schema-10-security-scan-v1" {
		t.Fatalf("schema10 backup contract changed: manifest=%+v err=%v", m, err)
	}
	if m.PairedBuildID == "" || m.PairedBuildID == "relay-gate-pre-p0" {
		t.Fatal("audit migration did not identify its actual reader binary")
	}
	backup := openDatabaseAtPath(t, filepath.Join(filepath.Dir(files[0]), m.DatabaseFile))
	defer backup.Close()
	var count int
	if err := backup.QueryRow(`SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='audit_event'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("audit DDL ran before the schema10 backup: count=%d err=%v", count, err)
	}
}
