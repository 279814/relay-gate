package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAttemptMetadataRotationBackupPinsReaderAndRestoresFacts(t *testing.T) {
	ctx := context.Background()
	st, _ := schemaTwelveSMTPFixture(t)
	if _, err := st.db.Exec(`INSERT INTO request_log(req_id,attempt,attempts,ts_recv,ts_sent,ts_first_byte,ts_done,endpoint,model_in,model_out,model_name_id,route_id,upstream_id,upstream_name,resp_status,ttft_ms,bytes_written,outcome,retried,half_open,error) VALUES ('metadata',1,1,1,2,3,4,'','','',0,0,0,'',200,1,1,'ok',0,0,''); INSERT INTO request_log_metadata(owner_id,execution_id,capability_effect) VALUES (last_insert_rowid(),'exact-execution','pending')`); err != nil {
		t.Fatal(err)
	}
	backup, err := st.CreateRotationBackup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if m := backup.Manifest; m.SourceSchema != 12 || m.TargetSchema != 12 || m.SourceValidator != "schema-12-attempt-metadata-v1" || m.ReaderContract != "schema-12-attempt-metadata-v1-reader" {
		t.Fatalf("metadata backup pairing=%+v", m)
	}
	bad := backup.Manifest
	bad.ReaderContract = "schema-11-audit-v1-reader"
	raw, _ := json.Marshal(bad)
	if err := os.WriteFile(backup.ManifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBackup(ctx, st.path, backup.ManifestPath, st.cipher); !errors.Is(err, ErrRestoreRejected) {
		t.Fatalf("accepted old metadata reader: %v", err)
	}
	raw, _ = json.Marshal(backup.Manifest)
	if err := os.WriteFile(backup.ManifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	path, cipher := st.path, st.cipher
	st.Close()
	result, err := RestoreDatabase(ctx, path, backup.ManifestPath, cipher, true, backup.Manifest.ReaderContract)
	if err != nil || result.RestoredSchemaVersion != 12 {
		t.Fatalf("restored metadata=%+v err=%v", result, err)
	}
	restored := openDatabaseAtPath(t, path)
	defer restored.Close()
	var id string
	if err := restored.QueryRow(`SELECT execution_id FROM request_log_metadata`).Scan(&id); err != nil || id != "exact-execution" {
		t.Fatalf("lost metadata: %s %v", id, err)
	}
}

func schemaElevenAttemptFixture(t *testing.T) (*Store, *Cipher) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "attempt.db")
	cipher, err := NewCipher("attempt-migration-master-long-enough")
	if err != nil {
		t.Fatal(err)
	}
	db := openDatabaseAtPath(t, path)
	if err := initializeEmptySchemaEleven(context.Background(), db, cipher); err != nil {
		t.Fatal(err)
	}
	st := &Store{db: db, cipher: cipher, path: path}
	t.Cleanup(func() { st.Close() })
	return st, cipher
}

func TestAttemptMetadataMigrationPairsSchemaEleven(t *testing.T) {
	st, cipher := schemaElevenAttemptFixture(t)
	path := st.path
	before, err := inspectSchemaState(context.Background(), st.db)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	current, err := Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	state, err := inspectSchemaState(context.Background(), current.db)
	if err != nil || state.Version != developmentSchemaVersion {
		t.Fatalf("attempt schema=%+v err=%v", state, err)
	}
	files, err := filepath.Glob(filepath.Join(filepath.Dir(path), "backups", "schema-11-to-12-*", "manifest.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("schema11 paired backup=%v err=%v", files, err)
	}
	m, err := CheckBackup(context.Background(), path, files[0], cipher)
	if err != nil || m.SourceFingerprint != before.Fingerprint || m.SourceValidator != "schema-11-audit-v1" || m.ReaderContract != "schema-11-audit-v1-reader" {
		t.Fatalf("schema11 contract=%+v err=%v", m, err)
	}
	backup := openDatabaseAtPath(t, filepath.Join(filepath.Dir(files[0]), m.DatabaseFile))
	defer backup.Close()
	var count int
	if err := backup.QueryRow(`SELECT COUNT(*) FROM sqlite_schema WHERE name='request_log_metadata'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("metadata preceded backup: %d %v", count, err)
	}
}

func TestAttemptMetadataBackupFailureLeavesSchemaEleven(t *testing.T) {
	st, cipher := schemaElevenAttemptFixture(t)
	path := st.path
	st.Close()
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "backups"), []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(path, cipher); err == nil {
		opened.Close()
		t.Fatal("metadata migration ignored failed backup")
	}
	db := openDatabaseAtPath(t, path)
	defer db.Close()
	state, err := inspectSchemaState(context.Background(), db)
	if err != nil || state.Version != 11 {
		t.Fatalf("source changed: %+v %v", state, err)
	}
}

func TestAttemptMetadataSchemaRejectsPartialChangedUnknown(t *testing.T) {
	for _, mutation := range []string{
		`DROP TABLE sample_attempt_metadata`,
		`ALTER TABLE request_log_metadata RENAME COLUMN execution_id TO guessed_id`,
		`DROP INDEX idx_request_log_metadata_execution`,
		`CREATE INDEX unknown_metadata ON request_log_metadata(error_class)`,
	} {
		t.Run(mutation, func(t *testing.T) {
			st := testStore(t)
			if _, err := st.db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			before := schemaCatalogSnapshot(t, st.db)
			if _, err := inspectSchemaState(context.Background(), st.db); !errors.Is(err, ErrUnknownSchema) {
				t.Fatalf("accepted modified schema: %v", err)
			}
			if schemaCatalogSnapshot(t, st.db) != before {
				t.Fatal("inspection repaired unknown schema")
			}
		})
	}
}
