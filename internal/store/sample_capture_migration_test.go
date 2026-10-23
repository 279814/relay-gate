package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func schemaFourteenSampleFixture(t *testing.T) (*Store, *Cipher) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sample-view.db")
	cipher, err := NewCipher("sample-view-migration-master-long-enough")
	if err != nil {
		t.Fatal(err)
	}
	db := openDatabaseAtPath(t, path)
	if err := initializeEmptySchemaFourteen(context.Background(), db, cipher); err != nil {
		t.Fatal(err)
	}
	st := &Store{db: db, cipher: cipher, path: path}
	t.Cleanup(func() { st.Close() })
	return st, cipher
}

func TestSampleCaptureMigrationPairsFourteenAndPreservesLegacy(t *testing.T) {
	st, cipher := schemaFourteenSampleFixture(t)
	legacy := &model.Sample{ReqID: "legacy-client", Attempts: []*model.SampleAttempt{{RespBody: []byte("already-stored-client-view"), Metadata: model.AttemptMetadata{Version: 1}}}}
	if err := st.InsertSample(legacy); err != nil {
		t.Fatal(err)
	}
	before, err := inspectSchemaState(context.Background(), st.db)
	if err != nil {
		t.Fatal(err)
	}
	var oldBody []byte
	if err := st.db.QueryRow(`SELECT resp_body FROM sample_attempt WHERE request_id=?`, legacy.ID).Scan(&oldBody); err != nil {
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
	if err != nil || state.Version != 15 {
		t.Fatalf("sample capture schema=%+v err=%v", state, err)
	}
	var marker string
	var body []byte
	if err := current.db.QueryRow(`SELECT response_capture_view FROM sample_attempt_metadata`).Scan(&marker); err != nil || marker != "legacy" {
		t.Fatalf("migration invented historical raw view: %s %v", marker, err)
	}
	if err := current.db.QueryRow(`SELECT resp_body FROM sample_attempt WHERE request_id=?`, legacy.ID).Scan(&body); err != nil || string(body) != string(oldBody) {
		t.Fatalf("migration rewrote historical ciphertext: %v", err)
	}
	files, err := filepath.Glob(filepath.Join(filepath.Dir(path), "backups", "schema-14-to-15-*", "manifest.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("paired14 backup=%v %v", files, err)
	}
	m, err := CheckBackup(context.Background(), path, files[0], cipher)
	if err != nil || m.SourceFingerprint != before.Fingerprint || m.ReaderContract != "schema-14-canary-v1-reader" || m.SourceValidator != "schema-14-canary-v1" {
		t.Fatalf("schema14 contract=%+v %v", m, err)
	}
	db := openDatabaseAtPath(t, filepath.Join(filepath.Dir(files[0]), m.DatabaseFile))
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('sample_attempt_metadata') WHERE name='response_capture_view'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("sample ALTER preceded backup: %d %v", count, err)
	}
}

func TestSampleCaptureBackupFailureLeavesFourteen(t *testing.T) {
	st, cipher := schemaFourteenSampleFixture(t)
	path := st.path
	st.Close()
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "backups"), []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(path, cipher); err == nil {
		opened.Close()
		t.Fatal("sample view migration ignored failed paired backup")
	}
	db := openDatabaseAtPath(t, path)
	defer db.Close()
	state, err := inspectSchemaState(context.Background(), db)
	if err != nil || state.Version != 14 {
		t.Fatalf("failed backup changed source: %+v %v", state, err)
	}
}

func TestSampleCaptureSchemaRejectsPartialChangedUnknown(t *testing.T) {
	for _, mutation := range []string{`ALTER TABLE sample_attempt_metadata DROP COLUMN response_capture_view`, `ALTER TABLE sample_attempt_metadata RENAME COLUMN response_capture_view TO guessed_view`, `CREATE INDEX unknown_capture ON sample_attempt_metadata(response_capture_view)`, `PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=replace(sql,"DEFAULT 'legacy'","DEFAULT 'upstream_response'") WHERE name='sample_attempt_metadata'; PRAGMA writable_schema=OFF`} {
		t.Run(mutation[:min(len(mutation), 48)], func(t *testing.T) {
			st := testStore(t)
			if _, err := st.db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			before := schemaCatalogSnapshot(t, st.db)
			if _, err := inspectSchemaState(context.Background(), st.db); !errors.Is(err, ErrUnknownSchema) {
				t.Fatalf("accepted modified raw marker schema: %v", err)
			}
			if schemaCatalogSnapshot(t, st.db) != before {
				t.Fatal("inspector repaired unknown capture schema")
			}
		})
	}
}

func TestSampleCaptureRotationPinsFifteenReaderAndRestoresMarker(t *testing.T) {
	st := testStore(t)
	smp := &model.Sample{Attempts: []*model.SampleAttempt{{Metadata: model.AttemptMetadata{Version: 1}}}}
	if err := st.InsertSample(smp); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE sample_attempt_metadata SET response_capture_view='upstream_response'`); err != nil {
		t.Fatal(err)
	}
	backup, err := st.CreateRotationBackup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if m := backup.Manifest; m.SourceSchema != 15 || m.TargetSchema != 15 || m.SourceValidator != "schema-15-upstream-sample-v1" || m.ReaderContract != "schema-15-upstream-sample-v1-reader" {
		t.Fatalf("raw sample backup=%+v", m)
	}
	bad := backup.Manifest
	bad.ReaderContract = "schema-14-canary-v1-reader"
	raw, _ := json.Marshal(bad)
	if err := os.WriteFile(backup.ManifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBackup(context.Background(), st.path, backup.ManifestPath, st.cipher); !errors.Is(err, ErrRestoreRejected) {
		t.Fatalf("accepted old raw-sample reader: %v", err)
	}
	raw, _ = json.Marshal(backup.Manifest)
	if err := os.WriteFile(backup.ManifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	path, cipher := st.path, st.cipher
	st.Close()
	result, err := RestoreDatabase(context.Background(), path, backup.ManifestPath, cipher, true, backup.Manifest.ReaderContract)
	if err != nil || result.RestoredSchemaVersion != 15 {
		t.Fatalf("restore raw sample=%+v %v", result, err)
	}
	db := openDatabaseAtPath(t, path)
	defer db.Close()
	var marker string
	if err := db.QueryRow(`SELECT response_capture_view FROM sample_attempt_metadata`).Scan(&marker); err != nil || marker != "upstream_response" {
		t.Fatalf("lost persisted raw marker: %s %v", marker, err)
	}
}
