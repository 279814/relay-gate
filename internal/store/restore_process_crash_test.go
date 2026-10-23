package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const restoreCrashExit = 86

func TestRestoreProcessCrashKeepsDatabaseAndSecretGenerationPaired(t *testing.T) {
	for _, phase := range []string{"prepared", "isolate-secrets", "isolated", "install-db", "install-secrets", "installed", "complete"} {
		t.Run(phase, func(t *testing.T) {
			st, backup, credentials := dataKeyBackupFixture(t)
			path := st.path
			st.Close()
			secret := filepath.Join(filepath.Dir(path), "secrets", "bootstrap-credentials.json")
			old := []byte(`{"fixture":"after-backup-generation"}`)
			if err := os.WriteFile(secret, old, 0600); err != nil {
				t.Fatal(err)
			}
			runRestoreCrashChild(t, path, backup.ManifestPath, "seed-wal")
			runRestoreCrashChild(t, path, backup.ManifestPath, phase)
			if err := ResumePendingRestore(path); err != nil {
				t.Fatal(err)
			}
			if err := ResumePendingRestore(path); err != nil {
				t.Fatalf("paired restore resume is not idempotent: %v", err)
			}
			got, err := os.ReadFile(secret)
			if err != nil || !bytes.Equal(got, credentials) {
				t.Fatalf("mixed credential generation: %v", err)
			}
			isolated, err := filepath.Glob(filepath.Join(filepath.Dir(path), "isolated-*", "secrets", "bootstrap-credentials.json"))
			if err != nil || len(isolated) != 1 {
				t.Fatalf("isolation=%v err=%v", isolated, err)
			}
			got, err = os.ReadFile(isolated[0])
			if err != nil || !bytes.Equal(got, old) {
				t.Fatalf("previous credentials lost: %v", err)
			}
			fresh, err := NewCipher("backup-data-key-master-long-enough")
			if err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(path, fresh)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			sample, err := reopened.GetSample(1)
			if err != nil || string(sample.InBody) != "before backup body" {
				t.Fatalf("restored body/key generation mismatch: %v", err)
			}
		})
	}
}

// Each child exits without deferred SQLite cleanup. These are real filesystem
// cut points, reconstructed with the same restore operations; no production
// environment flag or mutable global fault hook is introduced.
func TestRestoreProcessCrashMatrix(t *testing.T) {
	for _, phase := range []string{"prepared", "isolate-db", "isolate-wal", "isolate-shm", "isolated", "install-db", "installed", "directory-synced", "complete", "intent-removed"} {
		t.Run(phase, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "live.db")
			cipher, err := NewCipher("restore-process-fixture-master")
			if err != nil {
				t.Fatal(err)
			}
			db := openDatabaseAtPath(t, path)
			if err := initializeEmptySchemaTwo(context.Background(), db); err != nil {
				t.Fatal(err)
			}
			key, err := cipher.Encrypt("fixture-process-only")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`INSERT INTO upstream(name,base_url,api_key_enc,auth_style,full_url_mode,l1_path,probe_headers,created_at,updated_at) VALUES('backup-generation','https://fixture.invalid',?,'bearer',0,'','',1,1)`, key); err != nil {
				t.Fatal(err)
			}
			backup, err := migrateSchemaTwoToThree(context.Background(), db, path, cipher, MigrationBackupIdentity{PairedBuildID: "restore-process-build", ReaderContract: "schema-2-reader", CreatedAt: time.Unix(200, 0)})
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			runRestoreCrashChild(t, path, backup.ManifestPath, "seed-wal")
			oldEvidence := map[string]string{}
			for _, suffix := range []string{"", "-wal", "-shm"} {
				size, hash, err := fileEvidence(path + suffix)
				if err != nil || size == 0 {
					t.Fatalf("missing real old generation %q: size=%d err=%v", suffix, size, err)
				}
				oldEvidence[suffix] = hash
			}
			runRestoreCrashChild(t, path, backup.ManifestPath, phase)
			if err := ResumePendingRestore(path); err != nil {
				t.Fatalf("resume %s: %v", phase, err)
			}
			// A second resume must not move or rewrite the restored generation.
			if err := ResumePendingRestore(path); err != nil {
				t.Fatal(err)
			}
			size, hash, err := fileEvidence(path)
			if err != nil || size != backup.Manifest.DatabaseSize || hash != backup.Manifest.DatabaseSHA256 {
				t.Fatalf("restored wrong generation: size=%d hash=%s err=%v", size, hash, err)
			}
			for _, suffix := range []string{"-wal", "-shm"} {
				if _, err := os.Stat(path + suffix); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("old sidecar survived restore: %s %v", suffix, err)
				}
			}
			isolated, err := filepath.Glob(filepath.Join(filepath.Dir(path), "isolated-*"))
			if err != nil || len(isolated) != 1 {
				t.Fatalf("isolation=%v err=%v", isolated, err)
			}
			for suffix, want := range oldEvidence {
				_, got, err := fileEvidence(filepath.Join(isolated[0], filepath.Base(path)+suffix))
				if err != nil || got != want {
					t.Fatalf("old generation not preserved (%s): %v", suffix, err)
				}
			}
			if _, err := os.Stat(restoreIntentPath(path)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("intent not cleared: %v", err)
			}
			// Open is allowed only after the pair was completely installed. It may
			// migrate forward, but must retain the restored business generation.
			st, err := Open(path, cipher)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			var name, integrity string
			if err := st.db.QueryRow(`SELECT name FROM upstream WHERE id=1`).Scan(&name); err != nil || name != "backup-generation" {
				t.Fatalf("mixed/empty restored state: %q %v", name, err)
			}
			if err := st.db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
				t.Fatalf("integrity=%q err=%v", integrity, err)
			}
			if err := validateForeignKeys(context.Background(), st.db); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func runRestoreCrashChild(t *testing.T, path, manifest, phase string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRestoreProcessCrashChild$")
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "RELAY_TEST_RESTORE_") {
			command.Env = append(command.Env, value)
		}
	}
	command.Env = append(command.Env, "RELAY_TEST_RESTORE_PATH="+path, "RELAY_TEST_RESTORE_MANIFEST="+manifest, "RELAY_TEST_RESTORE_PHASE="+phase)
	output, err := command.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != restoreCrashExit {
		t.Fatalf("child %s did not reach cut point: %v: %s", phase, err, output)
	}
}

func TestRestoreProcessCrashChild(t *testing.T) {
	phase := os.Getenv("RELAY_TEST_RESTORE_PHASE")
	if phase == "" {
		return
	}
	path, manifestPath := os.Getenv("RELAY_TEST_RESTORE_PATH"), os.Getenv("RELAY_TEST_RESTORE_MANIFEST")
	crash := func(at string) {
		if phase == at {
			os.Exit(restoreCrashExit)
		}
	}
	if phase == "seed-wal" {
		db := openDatabaseAtPath(t, path)
		if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; INSERT INTO setting(key,value,updated_at) VALUES('restore_crash_fixture','after-backup-wal',1)`); err != nil {
			t.Fatal(err)
		}
		crash("seed-wal")
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var fixtureManifest BackupManifest
	if err := json.Unmarshal(raw, &fixtureManifest); err != nil {
		t.Fatal(err)
	}
	master := "restore-process-fixture-master"
	if fixtureManifest.SecretsFile != "" {
		master = "backup-data-key-master-long-enough"
	}
	cipher, err := NewCipher(master)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := CheckBackup(context.Background(), path, manifestPath, cipher)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := acquireInstanceLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	isolation, err := newIsolationDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	stage := path + ".restore-staging"
	backupPath := filepath.Join(filepath.Dir(manifestPath), manifest.DatabaseFile)
	if err := copyFileRestricted(backupPath, stage); err != nil {
		t.Fatal(err)
	}
	if err := syncAndRestrictFile(stage); err != nil {
		t.Fatal(err)
	}
	secretStage, err := stageBackupSecrets(filepath.Dir(path), filepath.Dir(manifestPath), manifest)
	if err != nil {
		t.Fatal(err)
	}
	intent := restoreIntent{FormatVersion: restoreIntentVersion, Phase: restorePhasePrepared, DatabasePath: path, ManifestPath: manifestPath, BackupDatabasePath: backupPath, StagingPath: stage, IsolationDirectory: isolation, DatabaseSHA256: manifest.DatabaseSHA256, DatabaseSize: manifest.DatabaseSize, SourceSchema: manifest.SourceSchema, PairedBuildID: manifest.PairedBuildID, ReaderContract: manifest.ReaderContract, LegacyCipherID: cipher.KeyID()}
	intent.SecretsStagingDirectory = secretStage
	intent.SecretsFile, intent.SecretsSize, intent.SecretsSHA256 = manifest.SecretsFile, manifest.SecretsSize, manifest.SecretsSHA256
	write := func() {
		t.Helper()
		if err := writeRestoreIntent(restoreIntentPath(path), intent); err != nil {
			t.Fatal(err)
		}
	}
	write()
	crash("prepared")
	for i, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Rename(path+suffix, filepath.Join(isolation, filepath.Base(path)+suffix)); err != nil {
			t.Fatal(err)
		}
		crash([]string{"isolate-db", "isolate-wal", "isolate-shm"}[i])
	}
	if secretStage != "" {
		if err := os.Rename(filepath.Join(filepath.Dir(path), "secrets"), filepath.Join(isolation, "secrets")); err != nil {
			t.Fatal(err)
		}
		crash("isolate-secrets")
	}
	if err := isolateLiveDatabaseGroup(intent); err != nil {
		t.Fatal(err)
	}
	intent.Phase = restorePhaseIsolated
	write()
	crash("isolated")
	if err := os.Rename(stage, path); err != nil {
		t.Fatal(err)
	}
	crash("install-db")
	if err := installStagedDatabase(intent); err != nil {
		t.Fatal(err)
	}
	crash("install-secrets")
	intent.Phase = restorePhaseInstalled
	write()
	crash("installed")
	if err := finalizeInstalledDatabase(intent); err != nil {
		t.Fatal(err)
	}
	crash("directory-synced")
	intent.Phase = restorePhaseComplete
	write()
	crash("complete")
	if err := os.Remove(restoreIntentPath(path)); err != nil {
		t.Fatal(err)
	}
	crash("intent-removed")
	t.Fatalf("unrecognized child cut point %s", phase)
}
