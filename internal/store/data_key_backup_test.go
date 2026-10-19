package store

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/279814/relay-gate/internal/keyring"
)

func dataKeyBackupFixture(t *testing.T) (*Store, MigrationBackupResult, []byte) {
	return dataKeyBackupFixtureForSchema(t, 9)
}

// Historical readers must be tested against an actual schema-8 database, not
// a newer file with an old number written into its backup manifest.
func schemaEightDataKeyBackupFixture(t *testing.T) (*Store, MigrationBackupResult, []byte) {
	return dataKeyBackupFixtureForSchema(t, 8)
}

func dataKeyBackupFixtureForSchema(t *testing.T, schema int) (*Store, MigrationBackupResult, []byte) {
	t.Helper()
	dir := t.TempDir()
	c, _ := NewCipher("backup-data-key-master-long-enough")
	path := filepath.Join(dir, "relay.db")
	var st *Store
	var err error
	if schema == 8 || schema == 9 {
		lock, lockErr := acquireInstanceLock(path)
		if lockErr != nil {
			t.Fatal(lockErr)
		}
		db := openDatabaseAtPath(t, path)
		initialize := initializeEmptySchemaEight
		if schema == 9 {
			initialize = initializeEmptySchemaNine
		}
		if err := initialize(context.Background(), db, c); err != nil {
			lock.Close()
			t.Fatal(err)
		}
		st = &Store{db: db, cipher: c, lock: lock, path: path}
	} else {
		st, err = Open(path, c)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	kr := keyring.Open(dir)
	if err := kr.EnsureInitialized(c.KeyID(), "backup-data-key-master-long-enough"); err != nil {
		t.Fatal(err)
	}
	relay, err := c.EncryptEnvelope("rk-original-backup-relay-fixture")
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := json.Marshal(map[string]any{"format_version": 1, "relay_key": relay})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secrets", "bootstrap-credentials.json"), credentials, 0600); err != nil {
		t.Fatal(err)
	}
	sample := mkSample(42)
	sample.InBody = []byte("before backup body")
	if err := st.InsertSample(sample); err != nil {
		t.Fatal(err)
	}
	backup, err := st.CreateRotationBackup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return st, backup, credentials
}

func TestDataKey_BackupReaderContractRejectsSchemaSevenReader(t *testing.T) {
	st, backup, _ := dataKeyBackupFixture(t)
	backup.Manifest.ReaderContract = "schema-7-reader"
	raw, _ := json.Marshal(backup.Manifest)
	if err := os.WriteFile(backup.ManifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBackup(context.Background(), st.path, backup.ManifestPath, st.cipher); err == nil {
		t.Fatal("current backup accepted a schema7 reader contract")
	}
}

func TestDataKey_MigrationManifestPairsCanonicalAndExplicitReaders(t *testing.T) {
	for _, identity := range []MigrationBackupIdentity{{}, defaultMigrationBackupIdentity(), {PairedBuildID: "explicit-build-identity", ReaderContract: "schema-7-reviewed-reader"}} {
		t.Run(identity.PairedBuildID, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "source7.db")
			db := openDatabaseAtPath(t, path)
			defer db.Close()
			if err := initializeEmptySchemaSeven(context.Background(), db); err != nil {
				t.Fatal(err)
			}
			c, _ := NewCipher("pair-contract-master-long-enough")
			backup, err := migrateSchemaSevenToEight(context.Background(), db, path, c, identity)
			if err != nil {
				t.Fatal(err)
			}
			wantBuild, wantReader := "605a935", "schema-7-reader"
			if identity.PairedBuildID == "explicit-build-identity" {
				wantBuild, wantReader = identity.PairedBuildID, identity.ReaderContract
			}
			checked, err := CheckBackup(context.Background(), path, backup.ManifestPath, c)
			if err != nil {
				t.Fatal(err)
			}
			if checked.PairedBuildID != wantBuild || checked.ReaderContract != wantReader {
				t.Fatalf("reader pair changed: %+v", checked)
			}
		})
	}
}

func TestDataKey_RotationBackupRestoresDatabaseAndSecretRoot(t *testing.T) {
	st, backup, credentials := dataKeyBackupFixture(t)
	if backup.Manifest.SourceSchema != 9 || backup.Manifest.TargetSchema != 9 || backup.Manifest.SecretsFile != "secrets.json" {
		t.Fatal("rotation backup missing schema9/secret pairing")
	}
	if _, err := CheckBackup(context.Background(), st.path, backup.ManifestPath, st.cipher); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`DELETE FROM sample_request`); err != nil {
		t.Fatal(err)
	}
	credentialPath := filepath.Join(filepath.Dir(st.path), "secrets", "bootstrap-credentials.json")
	if err := os.WriteFile(credentialPath, []byte(`{"fixture":"after backup"}`), 0600); err != nil {
		t.Fatal(err)
	}
	st.Close()
	result, err := RestoreDatabase(context.Background(), st.path, backup.ManifestPath, st.cipher, true, backup.Manifest.ReaderContract)
	if err != nil {
		t.Fatal(err)
	}
	if result.RestoredSchemaVersion != 9 {
		t.Fatalf("restored schema=%d", result.RestoredSchemaVersion)
	}
	restored, err := os.ReadFile(credentialPath)
	if err != nil || !bytes.Equal(restored, credentials) {
		t.Fatal("restore mixed database and credential generations")
	}
	fresh, _ := NewCipher("backup-data-key-master-long-enough")
	reopened, err := Open(st.path, fresh)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	sample, err := reopened.GetSample(1)
	if err != nil || string(sample.InBody) != "before backup body" {
		t.Fatalf("restored Data Key cannot open sample: %v", err)
	}
	if _, err := os.Stat(filepath.Join(result.IsolationDirectory, "secrets", "bootstrap-credentials.json")); err != nil {
		t.Fatal("previous credential root not isolated")
	}
}

func TestDataKey_BackupRejectsSecretArchiveTamperingBeforeMoves(t *testing.T) {
	st, backup, credentials := dataKeyBackupFixture(t)
	st.Close()
	archive := filepath.Join(backup.Directory, backup.Manifest.SecretsFile)
	if err := os.WriteFile(archive, []byte("modified archive"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreDatabase(context.Background(), st.path, backup.ManifestPath, st.cipher, true, backup.Manifest.ReaderContract); err == nil {
		t.Fatal("tampered keyring archive accepted")
	}
	got, err := os.ReadFile(filepath.Join(filepath.Dir(st.path), "secrets", "bootstrap-credentials.json"))
	if err != nil || !bytes.Equal(got, credentials) {
		t.Fatal("rejected restore changed active credentials")
	}
	if _, err := os.Stat(st.path); err != nil {
		t.Fatal("rejected restore moved active database")
	}
}

func TestDataKey_ResumeRestoreAfterDatabaseRenameBeforeSecretsInstall(t *testing.T) {
	st, backup, credentials := dataKeyBackupFixture(t)
	st.Close()
	stage := st.path + ".restore-staging"
	if err := copyFileRestricted(backup.DatabasePath, stage); err != nil {
		t.Fatal(err)
	}
	secretStage, err := stageBackupSecrets(filepath.Dir(st.path), backup.Directory, &backup.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	isolation, err := newIsolationDirectory(st.path)
	if err != nil {
		t.Fatal(err)
	}
	intent := restoreIntent{FormatVersion: restoreIntentVersion, Phase: restorePhasePrepared, DatabasePath: st.path, ManifestPath: backup.ManifestPath, BackupDatabasePath: backup.DatabasePath, StagingPath: stage, IsolationDirectory: isolation, DatabaseSHA256: backup.Manifest.DatabaseSHA256, DatabaseSize: backup.Manifest.DatabaseSize, SourceSchema: 9, PairedBuildID: backup.Manifest.PairedBuildID, ReaderContract: backup.Manifest.ReaderContract, LegacyCipherID: backup.Manifest.LegacyCipherID, SecretsStagingDirectory: secretStage, SecretsFile: backup.Manifest.SecretsFile, SecretsSize: backup.Manifest.SecretsSize, SecretsSHA256: backup.Manifest.SecretsSHA256}
	if err := isolateLiveDatabaseGroup(intent); err != nil {
		t.Fatal(err)
	}
	intent.Phase = restorePhaseIsolated
	if err := writeRestoreIntent(restoreIntentPath(st.path), intent); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(stage, st.path); err != nil {
		t.Fatal(err)
	} // crash before the next secrets/ rename
	if err := ResumePendingRestore(st.path); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(filepath.Dir(st.path), "secrets", "bootstrap-credentials.json"))
	if err != nil || !bytes.Equal(got, credentials) {
		t.Fatal("resume did not install paired secrets before bootstrap")
	}
	if _, err := os.Stat(restoreIntentPath(st.path)); !os.IsNotExist(err) {
		t.Fatal("completed restore intent was retained")
	}
}
