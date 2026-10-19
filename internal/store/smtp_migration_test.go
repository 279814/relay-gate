package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func schemaTwelveSMTPFixture(t *testing.T) (*Store, *Cipher) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "smtp.db")
	cipher, err := NewCipher("smtp-migration-master-long-enough")
	if err != nil {
		t.Fatal(err)
	}
	db := openDatabaseAtPath(t, path)
	if err := initializeEmptySchemaTwelve(context.Background(), db, cipher); err != nil {
		t.Fatal(err)
	}
	st := &Store{db: db, cipher: cipher, path: path}
	t.Cleanup(func() { st.Close() })
	return st, cipher
}

func TestSMTPMigrationPreservesCredentialsAndPairsSchemaTwelve(t *testing.T) {
	st, cipher := schemaTwelveSMTPFixture(t)
	encrypted, err := cipher.EncryptEnvelope("fixture-smtp-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE smtp_config SET host='smtp.example.test', password_enc=?`, encrypted); err != nil {
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
	if err != nil || state.Version != developmentSchemaVersion {
		t.Fatalf("smtp schema=%+v err=%v", state, err)
	}
	var host string
	var after []byte
	var aggregation, rate, revision int
	if err := current.db.QueryRow(`SELECT host,password_enc,aggregation_window_sec,rate_limit_window_sec,revision FROM smtp_config`).Scan(&host, &after, &aggregation, &rate, &revision); err != nil {
		t.Fatal(err)
	}
	if host != "smtp.example.test" || string(after) != string(encrypted) || aggregation != 300 || rate != 300 || revision != 1 {
		t.Fatal("SMTP migration altered credentials or missed defaults")
	}
	files, err := filepath.Glob(filepath.Join(filepath.Dir(path), "backups", "schema-12-to-13-*", "manifest.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("schema12 backup=%v err=%v", files, err)
	}
	m, err := CheckBackup(context.Background(), path, files[0], cipher)
	if err != nil || m.SourceFingerprint != before.Fingerprint || m.SourceValidator != "schema-12-attempt-metadata-v1" || m.ReaderContract != "schema-12-attempt-metadata-v1-reader" {
		t.Fatalf("schema12 contract=%+v err=%v", m, err)
	}
	backup := openDatabaseAtPath(t, filepath.Join(filepath.Dir(files[0]), m.DatabaseFile))
	defer backup.Close()
	var columns int
	if err := backup.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('smtp_config') WHERE name='revision'`).Scan(&columns); err != nil || columns != 0 {
		t.Fatalf("SMTP DDL preceded snapshot: %d %v", columns, err)
	}
}

func TestSMTPRotationBackupPinsReaderAndRestoresPolicy(t *testing.T) {
	st, _ := schemaThirteenCanaryFixture(t)
	if _, err := st.db.Exec(`UPDATE smtp_config SET aggregation_window_sec=7,rate_limit_window_sec=13,revision=5`); err != nil {
		t.Fatal(err)
	}
	backup, err := st.CreateRotationBackup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if m := backup.Manifest; m.SourceSchema != 13 || m.TargetSchema != 13 || m.SourceValidator != "schema-13-smtp-policy-v1" || m.ReaderContract != "schema-13-smtp-policy-v1-reader" {
		t.Fatalf("SMTP reader=%+v", m)
	}
	bad := backup.Manifest
	bad.ReaderContract = "schema-12-attempt-metadata-v1-reader"
	raw, _ := json.Marshal(bad)
	if err := os.WriteFile(backup.ManifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBackup(context.Background(), st.path, backup.ManifestPath, st.cipher); !errors.Is(err, ErrRestoreRejected) {
		t.Fatalf("accepted old SMTP reader: %v", err)
	}
	raw, _ = json.Marshal(backup.Manifest)
	if err := os.WriteFile(backup.ManifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	path, cipher := st.path, st.cipher
	st.Close()
	result, err := RestoreDatabase(context.Background(), path, backup.ManifestPath, cipher, true, backup.Manifest.ReaderContract)
	if err != nil || result.RestoredSchemaVersion != 13 {
		t.Fatalf("restored SMTP=%+v err=%v", result, err)
	}
	db := openDatabaseAtPath(t, path)
	defer db.Close()
	var aggregation, rate, revision int
	if err := db.QueryRow(`SELECT aggregation_window_sec,rate_limit_window_sec,revision FROM smtp_config`).Scan(&aggregation, &rate, &revision); err != nil || aggregation != 7 || rate != 13 || revision != 5 {
		t.Fatalf("lost SMTP policy: %d/%d/%d %v", aggregation, rate, revision, err)
	}
}

func TestSMTPBackupFailureLeavesSchemaTwelve(t *testing.T) {
	st, cipher := schemaTwelveSMTPFixture(t)
	path := st.path
	st.Close()
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "backups"), []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(path, cipher); err == nil {
		opened.Close()
		t.Fatal("SMTP migration ignored failed backup")
	}
	db := openDatabaseAtPath(t, path)
	defer db.Close()
	state, err := inspectSchemaState(context.Background(), db)
	if err != nil || state.Version != 12 {
		t.Fatalf("source changed: %+v %v", state, err)
	}
}

func TestSMTPSchemaRejectsPartialChangedUnknown(t *testing.T) {
	for _, mutation := range []string{
		`ALTER TABLE smtp_config DROP COLUMN revision`,
		`ALTER TABLE smtp_config RENAME COLUMN rate_limit_window_sec TO guessed_limit`,
		`CREATE INDEX unknown_smtp ON smtp_config(host)`,
	} {
		t.Run(mutation, func(t *testing.T) {
			st := testStore(t)
			if _, err := st.db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			before := schemaCatalogSnapshot(t, st.db)
			if _, err := inspectSchemaState(context.Background(), st.db); !errors.Is(err, ErrUnknownSchema) {
				t.Fatalf("accepted modified SMTP schema: %v", err)
			}
			if schemaCatalogSnapshot(t, st.db) != before {
				t.Fatal("inspection repaired SMTP schema")
			}
		})
	}
}
