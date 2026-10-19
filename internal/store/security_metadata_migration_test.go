package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/279814/relay-gate/internal/security"
)

func TestSecurityFindingPreservesScanMetadata(t *testing.T) {
	st := testStore(t)
	want := security.Finding{ID: "scan-metadata", AtMS: 1, Severity: security.SeverityHigh,
		Category: "credential", Summary: "bounded evidence", Detail: "redacted evidence",
		Source: "passive", ScannerVersion: "2", RuleVersion: "fixture", BytesScanned: 123,
		Truncated: true, DecodeDepth: 2, EvidenceHash: "fixture-evidence-hash", IncompleteReason: "capture_gap"}
	if err := st.InsertSecurityFinding(want); err != nil {
		t.Fatal(err)
	}
	rows, err := st.ListSecurityFindings("", 1)
	if err != nil || len(rows) != 1 {
		t.Fatalf("findings=%+v err=%v", rows, err)
	}
	if rows[0] != want {
		t.Fatalf("persisted metadata changed: got %+v want %+v", rows[0], want)
	}
}

func TestSchemaTenInspectionRejectsPartialChangedAndUnknownObjects(t *testing.T) {
	for _, kind := range []string{"partial", "changed", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			st, _ := schemaNineSecurityFixture(t)
			if kind == "partial" {
				if _, err := st.db.Exec(`ALTER TABLE security_finding ADD COLUMN truncated INTEGER NOT NULL DEFAULT 0; UPDATE schema_version SET version=10`); err != nil {
					t.Fatal(err)
				}
			} else {
				script, err := migrationFS.ReadFile("migrations/0010_security_scan_metadata.sql")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := st.db.Exec(string(script)); err != nil {
					t.Fatal(err)
				}
				if _, err := st.db.Exec(`UPDATE schema_version SET version=10`); err != nil {
					t.Fatal(err)
				}
				statement := `CREATE INDEX unreviewed_security ON security_finding(source)`
				if kind == "changed" {
					statement = `ALTER TABLE security_finding RENAME COLUMN decode_depth TO wrong_depth`
				}
				if _, err := st.db.Exec(statement); err != nil {
					t.Fatal(err)
				}
			}
			before := schemaCatalogSnapshot(t, st.db)
			if _, err := inspectSchemaState(context.Background(), st.db); !errors.Is(err, ErrUnknownSchema) {
				t.Fatalf("accepted %s schema10: %v", kind, err)
			}
			if after := schemaCatalogSnapshot(t, st.db); after != before {
				t.Fatal("inspection mutated rejected schema")
			}
		})
	}
}

func TestSchemaTenRotationBackupPinsReaderAndRestoresMetadata(t *testing.T) {
	st, cipher := schemaNineSecurityFixture(t)
	path := st.path
	st.Close()
	current, err := Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	f := security.Finding{ID: "metadata-backup", AtMS: 1, Severity: security.SeverityInfo, Category: "incomplete", Summary: "bounded", Source: "passive", Truncated: true, DecodeDepth: 2, EvidenceHash: "finite-redacted-evidence"}
	if err := current.InsertSecurityFinding(f); err != nil {
		t.Fatal(err)
	}
	backup, err := current.CreateRotationBackup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if m := backup.Manifest; m.SourceSchema != 10 || m.TargetSchema != 10 || m.SourceValidator != "schema-10-security-scan-v1" || m.ReaderContract != "schema-10-security-scan-v1-reader" {
		t.Fatalf("schema10 pairing=%+v", m)
	}
	if _, err := CheckBackup(context.Background(), path, backup.ManifestPath, cipher); err != nil {
		t.Fatal(err)
	}
	bad := backup.Manifest
	bad.ReaderContract = "schema-9-route-health-v1-reader"
	raw, _ := json.Marshal(bad)
	if err := os.WriteFile(backup.ManifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBackup(context.Background(), path, backup.ManifestPath, cipher); !errors.Is(err, ErrRestoreRejected) {
		t.Fatalf("schema10 accepted old reader: %v", err)
	}
	raw, _ = json.Marshal(backup.Manifest)
	if err := os.WriteFile(backup.ManifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	current.Close()
	result, err := RestoreDatabase(context.Background(), path, backup.ManifestPath, cipher, true, backup.Manifest.ReaderContract)
	if err != nil || result.RestoredSchemaVersion != 10 {
		t.Fatalf("restore=%+v err=%v", result, err)
	}
	restored, err := Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	rows, err := restored.ListSecurityFindings("", 1)
	if err != nil || len(rows) != 1 || rows[0] != f {
		t.Fatalf("restored scan metadata=%+v err=%v", rows, err)
	}
}

func schemaNineSecurityFixture(t *testing.T) (*Store, *Cipher) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.db")
	c, err := NewCipher("security-migration-master-long-enough")
	if err != nil {
		t.Fatal(err)
	}
	db := openDatabaseAtPath(t, path)
	if err := initializeEmptySchemaNine(context.Background(), db, c); err != nil {
		t.Fatal(err)
	}
	st := &Store{db: db, cipher: c, path: path}
	t.Cleanup(func() { st.Close() })
	return st, c
}

func TestSchemaNineSecurityMigrationPairsHistoricalReader(t *testing.T) {
	st, cipher := schemaNineSecurityFixture(t)
	if _, err := st.db.Exec(`INSERT INTO security_finding(id,at_ms,severity,category,summary) VALUES ('legacy',1,'low','fixture','historical scan')`); err != nil {
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
	if err != nil || state.Version != 10 {
		t.Fatalf("schema10=%+v err=%v", state, err)
	}
	rows, err := current.ListSecurityFindings("", 1)
	if err != nil || len(rows) != 1 {
		t.Fatalf("legacy finding=%+v err=%v", rows, err)
	}
	if rows[0].Truncated || rows[0].DecodeDepth != 0 || rows[0].EvidenceHash != "" || rows[0].ScannerVersion != "" {
		t.Fatalf("migration invented scan evidence: %+v", rows[0])
	}
	files, err := filepath.Glob(filepath.Join(filepath.Dir(path), "backups", "schema-9-to-10-*", "manifest.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("9→10 backup missing: %v %v", files, err)
	}
	m, err := CheckBackup(context.Background(), path, files[0], cipher)
	if err != nil || m.SourceSchema != 9 || m.TargetSchema != 10 || m.SourceValidator != "schema-9-route-health-v1" || m.ReaderContract != "schema-9-route-health-v1-reader" {
		t.Fatalf("schema9 reader contract changed: %+v %v", m, err)
	}
	old := openDatabaseAtPath(t, filepath.Join(filepath.Dir(files[0]), m.DatabaseFile))
	defer old.Close()
	oldState, err := inspectSchemaState(context.Background(), old)
	if err != nil || oldState.Version != 9 {
		t.Fatalf("backup changed schema: %+v %v", oldState, err)
	}
}

func TestSecurityMigrationBackupFailureStopsBeforeDDL(t *testing.T) {
	st, cipher := schemaNineSecurityFixture(t)
	path := st.path
	st.Close()
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "backups"), []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(path, cipher); err == nil {
		opened.Close()
		t.Fatal("migration ignored backup failure")
	}
	db := openDatabaseAtPath(t, path)
	defer db.Close()
	state, err := inspectSchemaState(context.Background(), db)
	if err != nil || state.Version != 9 {
		t.Fatalf("failed backup changed source: %+v %v", state, err)
	}
	if present, err := hasColumn(db, "security_finding", "truncated"); err != nil || present {
		t.Fatalf("security DDL ran before backup: present=%t err=%v", present, err)
	}
}
