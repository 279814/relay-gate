package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/security"
)

func schemaSixteenFixture(t *testing.T) (*Store, *Cipher) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "security-admin.db")
	cipher, err := NewCipher("security-admin-migration-master-long-enough")
	if err != nil {
		t.Fatal(err)
	}
	db := openDatabaseAtPath(t, path)
	if err := initializeEmptySchemaSixteen(context.Background(), db, cipher); err != nil {
		t.Fatal(err)
	}
	st := &Store{db: db, cipher: cipher, path: path}
	t.Cleanup(func() { st.Close() })
	return st, cipher
}

func TestSecurityAdminMigrationPairsSixteenAndPreservesEvidence(t *testing.T) {
	st, cipher := schemaSixteenFixture(t)
	legacyDetail, err := st.cipher.encryptDataBlob(securityKeyPurpose, []byte("finite encrypted evidence"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO security_finding(id,at_ms,severity,category,summary,detail,upstream,route_id) VALUES('legacy-finding',1,'high','fixture','finite evidence',?,'old label',7)`, legacyDetail); err != nil {
		t.Fatal(err)
	}
	before, err := inspectSchemaState(context.Background(), st.db)
	if err != nil {
		t.Fatal(err)
	}
	var oldDetail string
	if err := st.db.QueryRow(`SELECT detail FROM security_finding WHERE id='legacy-finding'`).Scan(&oldDetail); err != nil {
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
	if err != nil || state.Version != 17 {
		t.Fatalf("security admin schema=%+v err=%v", state, err)
	}
	var upstreamID int64
	var ruleID, detail string
	if err := current.db.QueryRow(`SELECT upstream_id,rule_id,detail FROM security_finding WHERE id='legacy-finding'`).Scan(&upstreamID, &ruleID, &detail); err != nil || upstreamID != 0 || ruleID != "" || detail != oldDetail {
		t.Fatalf("migration invented identity or rewrote evidence: upstream=%d rule=%q err=%v", upstreamID, ruleID, err)
	}
	files, err := filepath.Glob(filepath.Join(filepath.Dir(path), "backups", "schema-16-to-17-*", "manifest.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("paired16 backup=%v err=%v", files, err)
	}
	manifest, err := CheckBackup(context.Background(), path, files[0], cipher)
	if err != nil || manifest.SourceFingerprint != before.Fingerprint || manifest.ReaderContract != "schema-16-transform-admin-v1-reader" || manifest.SourceValidator != "schema-16-transform-admin-v1" || !strings.HasPrefix(manifest.PairedBuildID, "sha256:") {
		t.Fatalf("schema16 provenance/reader=%+v err=%v", manifest, err)
	}
	db := openDatabaseAtPath(t, filepath.Join(filepath.Dir(files[0]), manifest.DatabaseFile))
	defer db.Close()
	var added int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('security_finding') WHERE name IN ('upstream_id','rule_id')`).Scan(&added); err != nil || added != 0 {
		t.Fatalf("finding ALTER preceded paired backup: %d %v", added, err)
	}
}

func TestSecurityAdminBackupFailureLeavesSixteen(t *testing.T) {
	st, cipher := schemaSixteenFixture(t)
	path := st.path
	st.Close()
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "backups"), []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	if current, err := Open(path, cipher); err == nil {
		current.Close()
		t.Fatal("security migration ignored unavailable paired backup")
	}
	db := openDatabaseAtPath(t, path)
	defer db.Close()
	state, err := inspectSchemaState(context.Background(), db)
	if err != nil || state.Version != 16 {
		t.Fatalf("failed backup changed source: %+v %v", state, err)
	}
}

func TestSecurityAdminSchemaRejectsPartialChangedAndUnknownObjects(t *testing.T) {
	for _, mutation := range []string{
		`ALTER TABLE security_finding RENAME COLUMN upstream_id TO guessed_upstream`,
		`DROP TABLE security_finding_review`,
		`CREATE INDEX unknown_security_ignore ON security_ignore_rule(enabled)`,
		`PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=replace(sql,'AUTOINCREMENT','') WHERE name='security_ignore_rule'; PRAGMA writable_schema=OFF`,
	} {
		t.Run(mutation[:min(len(mutation), 48)], func(t *testing.T) {
			st := testStore(t)
			if _, err := st.db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			before := schemaCatalogSnapshot(t, st.db)
			if _, err := inspectSchemaState(context.Background(), st.db); !errors.Is(err, ErrUnknownSchema) {
				t.Fatalf("accepted modified Security Center schema: %v", err)
			}
			if schemaCatalogSnapshot(t, st.db) != before {
				t.Fatal("inspector repaired unknown schema")
			}
		})
	}
}

func TestSecurityAdminRotationPinsSeventeenAndRestoresRules(t *testing.T) {
	st := testStore(t)
	if _, err := st.db.Exec(`INSERT INTO security_ignore_rule(scope,rule_id,expires_at_ms,revision,created_at_ms,updated_at_ms) VALUES('rule','builtin:prompt_injection',0,3,1,2)`); err != nil {
		t.Fatal(err)
	}
	backup, err := st.CreateRotationBackup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if m := backup.Manifest; m.SourceSchema != 17 || m.TargetSchema != 17 || m.SourceValidator != "schema-17-security-admin-v1" || m.ReaderContract != "schema-17-security-admin-v1-reader" {
		t.Fatalf("security rotation backup=%+v", m)
	}
	bad := backup.Manifest
	bad.ReaderContract = "schema-16-transform-admin-v1-reader"
	raw, _ := json.Marshal(bad)
	if err := os.WriteFile(backup.ManifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBackup(context.Background(), st.path, backup.ManifestPath, st.cipher); !errors.Is(err, ErrRestoreRejected) {
		t.Fatalf("accepted wrong Security Center reader: %v", err)
	}
	bad = backup.Manifest
	bad.SourceValidator = "schema-16-transform-admin-v1"
	raw, _ = json.Marshal(bad)
	if err := os.WriteFile(backup.ManifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBackup(context.Background(), st.path, backup.ManifestPath, st.cipher); !errors.Is(err, ErrRestoreRejected) {
		t.Fatalf("accepted wrong Security Center validator: %v", err)
	}
	raw, _ = json.Marshal(backup.Manifest)
	if err := os.WriteFile(backup.ManifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	path, cipher := st.path, st.cipher
	st.Close()
	result, err := RestoreDatabase(context.Background(), path, backup.ManifestPath, cipher, true, backup.Manifest.ReaderContract)
	if err != nil || result.RestoredSchemaVersion != 17 {
		t.Fatalf("restore security=%+v err=%v", result, err)
	}
	db := openDatabaseAtPath(t, path)
	defer db.Close()
	var revision, expires int64
	if err := db.QueryRow(`SELECT revision,expires_at_ms FROM security_ignore_rule`).Scan(&revision, &expires); err != nil || revision != 3 || expires != 0 {
		t.Fatalf("restored policy changed: revision=%d expiry=%d err=%v", revision, expires, err)
	}
}

func TestSecurityAdminDDLRefusesInvalidStateAndIgnoreTargets(t *testing.T) {
	st := testStore(t)
	for _, values := range []string{
		`-1,'rule','builtin:prompt_injection',0,0,1,1,1,1`,
		`1,'route','builtin:prompt_injection',7,0,1,1,1,1`,
		`1,'route','',0,0,1,1,1,1`,
		`1,'rule','',0,0,1,1,1,1`,
		`1,'rule','builtin:prompt_injection',0,-1,1,1,1,1`,
		`1,'rule','builtin:prompt_injection',0,0,2,1,1,1`,
		`1,'rule','builtin:prompt_injection',0,0,1,0,1,1`,
		`1,'rule','builtin:prompt_injection',0,0,1,1,2,1`,
	} {
		if _, err := st.db.Exec(`INSERT INTO security_ignore_rule(id,scope,rule_id,route_id,expires_at_ms,enabled,revision,created_at_ms,updated_at_ms) VALUES (` + values + `)`); err == nil {
			t.Fatalf("accepted invalid ignore rule: %s", values)
		}
	}
	if _, err := st.db.Exec(`INSERT INTO security_finding_review(finding_id,status,updated_at_ms) VALUES('missing','false_positive',1)`); err == nil {
		t.Fatal("review accepted a nonexistent finding")
	}
	if err := st.InsertSecurityFinding(security.Finding{ID: "retained"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO security_finding_review(finding_id,status,updated_at_ms) VALUES('retained','silenced',1)`); err == nil {
		t.Fatal("review accepted an unknown status")
	}
}

func TestSecurityIgnoreDeletionCannotReuseAnOldCASIdentity(t *testing.T) {
	st := testStore(t)
	insert := func() int64 {
		t.Helper()
		result, err := st.db.Exec(`INSERT INTO security_ignore_rule(scope,route_id,created_at_ms,updated_at_ms) VALUES('route',7,1,1)`)
		if err != nil {
			t.Fatal(err)
		}
		id, err := result.LastInsertId()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	oldID := insert()
	if _, err := st.db.Exec(`DELETE FROM security_ignore_rule WHERE id=? AND revision=1`, oldID); err != nil {
		t.Fatal(err)
	}
	newID := insert()
	if newID <= oldID {
		t.Fatalf("deleted ignore ID reused: old=%d new=%d", oldID, newID)
	}
	stale, err := st.db.Exec(`DELETE FROM security_ignore_rule WHERE id=? AND revision=1`, oldID)
	if err != nil {
		t.Fatal(err)
	}
	count, err := stale.RowsAffected()
	if err != nil || count != 0 {
		t.Fatalf("old CAS affected a rebuilt rule: %d %v", count, err)
	}
}
