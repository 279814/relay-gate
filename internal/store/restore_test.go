package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCheckBackupAndRestoreRoundTrip(t *testing.T) {
	root := t.TempDir()
	livePath := filepath.Join(root, "live.db")
	cipher, err := NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}

	// Build a schema-2 DB, then migrate to 3 so a schema-2 backup exists under backups/.
	v2 := openDatabaseAtPath(t, livePath)
	if err := initializeEmptySchemaTwo(context.Background(), v2); err != nil {
		t.Fatal(err)
	}
	enc, err := cipher.Encrypt("sk-restore-fixture-key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v2.Exec(`INSERT INTO upstream
		(name,base_url,api_key_enc,auth_style,full_url_mode,l1_path,probe_headers,created_at,updated_at)
		VALUES ('fixture','https://restore.example',?,'bearer',0,'','',1,1)`, enc); err != nil {
		t.Fatal(err)
	}
	result, err := migrateSchemaTwoToThree(context.Background(), v2, livePath, cipher, MigrationBackupIdentity{
		PairedBuildID:  "restore-test-build",
		ReaderContract: "schema-2-reader",
		CreatedAt:      time.Unix(100, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = v2.Close()

	manifest, err := CheckBackup(context.Background(), livePath, result.ManifestPath, cipher)
	if err != nil {
		t.Fatalf("CheckBackup: %v", err)
	}
	if manifest.SourceSchema != 2 || manifest.ReaderContract != "schema-2-reader" {
		t.Fatalf("manifest = %+v", manifest)
	}

	// Reject without authorizations.
	if _, err := RestoreDatabase(context.Background(), livePath, result.ManifestPath, cipher, false, ""); !errors.Is(err, ErrRestoreRejected) {
		t.Fatalf("expected rejected without flags, got %v", err)
	}
	if _, err := RestoreDatabase(context.Background(), livePath, result.ManifestPath, cipher, true, "wrong"); !errors.Is(err, ErrRestoreRejected) {
		t.Fatalf("expected rejected wrong contract, got %v", err)
	}

	restored, err := RestoreDatabase(context.Background(), livePath, result.ManifestPath, cipher, true, manifest.ReaderContract)
	if err != nil {
		t.Fatalf("RestoreDatabase: %v", err)
	}
	if restored.RestoredSchemaVersion != 2 {
		t.Fatalf("restored schema = %d", restored.RestoredSchemaVersion)
	}
	if restored.PairedBuildID != "restore-test-build" {
		t.Fatalf("paired build = %q", restored.PairedBuildID)
	}
	if restored.IsolationDirectory == "" {
		t.Fatal("expected isolation directory")
	}
	if _, err := os.Stat(restored.IsolationDirectory); err != nil {
		t.Fatalf("isolation dir missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(livePath), restoreIntentFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("intent should be removed after complete, err=%v", err)
	}

	// Open migrates restored schema-2 back to schema-3.
	st, err := Open(livePath, cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ok, err := st.CutoverCompleted(context.Background())
	if err != nil || !ok {
		t.Fatalf("cutover after reopen = %v %v", ok, err)
	}
}

func TestRestoreRejectsManifestOutsideBackups(t *testing.T) {
	root := t.TempDir()
	livePath := filepath.Join(root, "live.db")
	outside := filepath.Join(root, "manifest.json")
	if err := os.WriteFile(outside, []byte(`{"format_version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cipher, err := NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBackup(context.Background(), livePath, outside, cipher); !errors.Is(err, ErrRestoreRejected) {
		t.Fatalf("expected rejected outside backups, got %v", err)
	}
}

func TestOpenResumesPreparedRestoreIntent(t *testing.T) {
	root := t.TempDir()
	livePath := filepath.Join(root, "live.db")
	cipher, err := NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}

	v2 := openDatabaseAtPath(t, livePath)
	if err := initializeEmptySchemaTwo(context.Background(), v2); err != nil {
		t.Fatal(err)
	}
	result, err := migrateSchemaTwoToThree(context.Background(), v2, livePath, cipher, MigrationBackupIdentity{
		PairedBuildID:  "resume-build",
		ReaderContract: "schema-2-reader",
		CreatedAt:      time.Unix(200, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = v2.Close()

	// Simulate crash after prepared: staging ready, live still present, intent written.
	staging := livePath + ".restore-staging"
	if err := copyFileRestricted(result.DatabasePath, staging); err != nil {
		t.Fatal(err)
	}
	isolation, err := newIsolationDirectory(livePath)
	if err != nil {
		t.Fatal(err)
	}
	intent := restoreIntent{
		FormatVersion:      restoreIntentVersion,
		Phase:              restorePhasePrepared,
		DatabasePath:       livePath,
		ManifestPath:       result.ManifestPath,
		BackupDatabasePath: result.DatabasePath,
		StagingPath:        staging,
		IsolationDirectory: isolation,
		DatabaseSHA256:     result.Manifest.DatabaseSHA256,
		DatabaseSize:       result.Manifest.DatabaseSize,
		SourceSchema:       2,
		PairedBuildID:      "resume-build",
		ReaderContract:     "schema-2-reader",
		LegacyCipherID:     cipher.KeyID(),
		UpdatedAt:          time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := writeRestoreIntent(restoreIntentPath(livePath), intent); err != nil {
		t.Fatal(err)
	}

	st, err := Open(livePath, cipher)
	if err != nil {
		t.Fatalf("Open should resume restore: %v", err)
	}
	defer st.Close()
	if _, err := os.Stat(restoreIntentPath(livePath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("intent should be cleared, err=%v", err)
	}
	raw, _ := json.Marshal(intent)
	_ = raw
}
