package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/279814/relay-gate/internal/keyring"
)

func rewriteBackupManifest(t *testing.T, backup *MigrationBackupResult) {
	t.Helper()
	raw, err := json.Marshal(backup.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup.ManifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func activeRestoreFiles(t *testing.T, directory string) map[string][32]byte {
	t.Helper()
	files := map[string][32]byte{}
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path == filepath.Join(directory, "backups") {
				return filepath.SkipDir
			}
			files[path] = [32]byte{}
			return nil
		}
		raw, err := os.ReadFile(path)
		if err == nil {
			files[path] = sha256.Sum256(raw)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// Reject before quarantining any live file, and prove the surviving credential
// root can still start the database. Matching file hashes alone cannot establish
// that encrypted values or an archived master are actually usable.
func assertBackupRejectedWithoutReplacement(t *testing.T, path string, backup MigrationBackupResult, current *Cipher) {
	t.Helper()
	before := activeRestoreFiles(t, filepath.Dir(path))
	if _, err := CheckBackup(context.Background(), path, backup.ManifestPath, current); !errors.Is(err, ErrRestoreRejected) {
		t.Errorf("check-backup must reject invalid encrypted backup: %v", err)
	}
	if _, err := RestoreDatabase(context.Background(), path, backup.ManifestPath, current, true, backup.Manifest.ReaderContract); !errors.Is(err, ErrRestoreRejected) {
		t.Errorf("restore must reject invalid encrypted backup: %v", err)
	}
	if !reflect.DeepEqual(before, activeRestoreFiles(t, filepath.Dir(path))) {
		t.Error("rejected backup changed active database/credentials or created restore artifacts")
	}
	_, active, err := keyring.Open(filepath.Dir(path)).LoadActive()
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := NewCipher(active)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, fresh)
	if err != nil {
		t.Fatalf("rejected restore made the existing database unstartable: %v", err)
	}
	reopened.Close()
}

func TestRestoreRejectsCorruptLegacyDirectSecretsBeforeReplacement(t *testing.T) {
	for _, test := range []struct {
		name    string
		version int
		init    func(context.Context, *sql.DB) error
		corrupt string
	}{
		{"schema2-probe", 2, initializeEmptySchemaTwo, `INSERT INTO probe_secret(name,value_enc,masked,fingerprint,created_at,updated_at) VALUES ('damaged','invalid','masked','fp',1,1)`},
		{"schema5-smtp", 5, initializeEmptySchemaFive, `UPDATE smtp_config SET password_enc='v1:broken:AAAA'`},
		{"schema6-probe", 6, initializeEmptySchemaSix, `INSERT INTO probe_secret(name,value_enc,masked,fingerprint,created_at,updated_at) VALUES ('damaged','invalid','masked','fp',1,1)`},
		{"schema7-smtp", 7, initializeEmptySchemaSeven, `UPDATE smtp_config SET password_enc='v1:broken:AAAA'`},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "live.db")
			const master = "restore-legacy-audit-master-long-enough"
			current, _ := NewCipher(master)
			if err := keyring.Open(filepath.Dir(path)).EnsureInitialized(current.KeyID(), master); err != nil {
				t.Fatal(err)
			}
			db := openDatabaseAtPath(t, path)
			if err := test.init(context.Background(), db); err != nil {
				t.Fatal(err)
			}
			state, err := inspectSchemaState(context.Background(), db)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := db.Conn(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			backup, err := createMigrationBackup(context.Background(), conn, path, MigrationBackupSpec{SourceSchema: test.version, TargetSchema: test.version + 1, SourceFingerprint: state.Fingerprint, LegacyCipherID: current.KeyID(), SourceValidator: fmt.Sprintf("schema-%d", test.version), PairedBuildID: "restore-audit-build", ReaderContract: fmt.Sprintf("schema-%d-reader", test.version)})
			conn.Close()
			db.Close()
			if err != nil {
				t.Fatal(err)
			}
			live, err := Open(path, current)
			if err != nil {
				t.Fatal(err)
			}
			live.Close()
			damaged := openDatabaseAtPath(t, backup.DatabasePath)
			if _, err := damaged.Exec(test.corrupt); err != nil {
				t.Fatal(err)
			}
			damaged.Close()
			backup.Manifest.DatabaseSize, backup.Manifest.DatabaseSHA256, err = fileEvidence(backup.DatabasePath)
			if err != nil {
				t.Fatal(err)
			}
			rewriteBackupManifest(t, &backup)
			assertBackupRejectedWithoutReplacement(t, path, backup, current)
		})
	}
}

func TestRestoreRejectsUnpairedOrUnstableArchivedKeyringBeforeReplacement(t *testing.T) {
	for _, invalid := range []string{"different-master", "pending", "invalid-json", "unknown-phase", "idle-with-rotation"} {
		t.Run(invalid, func(t *testing.T) {
			st, backup, _ := dataKeyBackupFixture(t)
			st.Close()
			values, err := readBackupSecrets(backup.Directory, &backup.Manifest)
			if err != nil {
				t.Fatal(err)
			}
			var root map[string]any
			if err := json.Unmarshal(values["keyring.json"], &root); err != nil {
				t.Fatal(err)
			}
			switch invalid {
			case "different-master":
				root["active"] = "unrelated-archived-master-long-enough"
			case "pending":
				root["pending"] = "uncommitted-archived-master-long-enough"
				root["phase"] = "prepared"
			case "unknown-phase":
				root["phase"] = "unsupported-phase"
			case "idle-with-rotation":
				root["rotation_id"] = "unfinished-rotation"
			}
			values["keyring.json"], err = json.Marshal(root)
			if err != nil {
				t.Fatal(err)
			}
			if invalid == "invalid-json" {
				values["keyring.json"] = []byte("invalid")
			}
			raw, err := json.Marshal(values)
			if err != nil {
				t.Fatal(err)
			}
			archive := filepath.Join(backup.Directory, backup.Manifest.SecretsFile)
			if err := os.WriteFile(archive, raw, 0600); err != nil {
				t.Fatal(err)
			}
			backup.Manifest.SecretsSize, backup.Manifest.SecretsSHA256, err = fileEvidence(archive)
			if err != nil {
				t.Fatal(err)
			}
			rewriteBackupManifest(t, &backup)
			assertBackupRejectedWithoutReplacement(t, st.path, backup, st.cipher)
		})
	}
}

func TestRestoreAcceptsPairedBackupAfterCompletedMasterRotation(t *testing.T) {
	for _, retainHistoricalID := range []bool{false, true} {
		t.Run(fmt.Sprintf("historical-id-%t", retainHistoricalID), func(t *testing.T) {
			st, _, _ := dataKeyBackupFixture(t)
			kr := keyring.Open(filepath.Dir(st.path))
			const master = "rotated-backup-master-long-enough"
			rid, err := kr.BeginRotation(master)
			if err != nil {
				t.Fatal(err)
			}
			if err := st.RewrapDirectSecrets(master, rid); err != nil {
				t.Fatal(err)
			}
			relay, err := SealEnvelopeUnder(master, "rk-original-backup-relay-fixture")
			if err != nil {
				t.Fatal(err)
			}
			credentials, err := json.Marshal(map[string]any{"format_version": 1, "relay_key": relay})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(filepath.Dir(st.path), "secrets", "bootstrap-credentials.json"), credentials, 0600); err != nil {
				t.Fatal(err)
			}
			if err := kr.MarkDBCommitted(rid); err != nil {
				t.Fatal(err)
			}
			if _, err := kr.ActivatePending(rid); err != nil {
				t.Fatal(err)
			}
			if err := st.ActivateMaster(master); err != nil {
				t.Fatal(err)
			}
			if err := st.ValidateEncryptedState(); err != nil {
				t.Fatal(err)
			}
			if err := kr.MarkCleaned(rid); err != nil {
				t.Fatal(err)
			}
			st.ForgetRetiredMasterKeys()
			if retainHistoricalID {
				// Older cleaned documents can retain their historical rotation ID.
				raw, err := os.ReadFile(kr.Path())
				if err != nil {
					t.Fatal(err)
				}
				var root map[string]any
				if err := json.Unmarshal(raw, &root); err != nil {
					t.Fatal(err)
				}
				root["rotation_id"] = rid
				raw, err = json.Marshal(root)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(kr.Path(), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			backup, err := st.CreateRotationBackup(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := CheckBackup(context.Background(), st.path, backup.ManifestPath, st.cipher); err != nil {
				t.Fatalf("completed rotation backup rejected: %v", err)
			}
			archived, err := CipherFromBackupKeyring(st.path, backup.ManifestPath)
			if err != nil || archived.KeyID() != st.cipher.KeyID() {
				t.Fatalf("archive selector could not recover rotated master: %v", err)
			}
			st.Close()
			if _, err := RestoreDatabase(context.Background(), st.path, backup.ManifestPath, archived, true, backup.Manifest.ReaderContract); err != nil {
				t.Fatal(err)
			}
			_, active, err := keyring.Open(filepath.Dir(st.path)).LoadActive()
			if err != nil || active != master {
				t.Fatalf("restored keyring lost rotated master: %v", err)
			}
			fresh, _ := NewCipher(active)
			reopened, err := Open(st.path, fresh)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			sample, err := reopened.GetSample(1)
			if err != nil || string(sample.InBody) != "before backup body" {
				t.Fatalf("restored rotated data key lost sample body: %v", err)
			}
		})
	}
}

func TestRestoreRejectsInvalidArchivedRelayBeforeReplacement(t *testing.T) {
	for _, damage := range []string{"invalid-json", "null-json", "wrong-master", "corrupt-envelope", "wrong-master-without-keyring", "plaintext", "bad-magic"} {
		t.Run(damage, func(t *testing.T) {
			st, backup, _ := dataKeyBackupFixture(t)
			st.Close()
			values, err := readBackupSecrets(backup.Directory, &backup.Manifest)
			if err != nil {
				t.Fatal(err)
			}
			if damage == "invalid-json" {
				values["bootstrap-credentials.json"] = []byte("invalid")
			} else if damage == "null-json" {
				values["bootstrap-credentials.json"] = []byte("null")
			} else {
				envelope := "v1:damaged:AAAA"
				if damage == "plaintext" {
					envelope = "rk-legacy-plaintext-not-valid-for-schema-eight"
				} else if damage == "bad-magic" {
					envelope = "w1:damaged:AAAA"
				} else if damage != "corrupt-envelope" {
					envelope, err = SealEnvelopeUnder("unrelated-archived-relay-master", "rk-archived-relay-fixture")
					if err != nil {
						t.Fatal(err)
					}
				}
				values["bootstrap-credentials.json"], err = json.Marshal(map[string]any{"format_version": 1, "relay_key": envelope})
				if err != nil {
					t.Fatal(err)
				}
			}
			if damage == "wrong-master-without-keyring" {
				delete(values, "keyring.json")
			}
			raw, err := json.Marshal(values)
			if err != nil {
				t.Fatal(err)
			}
			archive := filepath.Join(backup.Directory, backup.Manifest.SecretsFile)
			if err := os.WriteFile(archive, raw, 0600); err != nil {
				t.Fatal(err)
			}
			backup.Manifest.SecretsSize, backup.Manifest.SecretsSHA256, err = fileEvidence(archive)
			if err != nil {
				t.Fatal(err)
			}
			rewriteBackupManifest(t, &backup)
			if _, err := CipherFromBackupKeyring(st.path, backup.ManifestPath); err == nil {
				t.Error("archive key selector accepted unusable archived relay credentials")
			}
			assertBackupRejectedWithoutReplacement(t, st.path, backup, st.cipher)
		})
	}
}

func TestCheckBackupAcceptsVerifiedRelayWithoutArchivedKeyring(t *testing.T) {
	st, backup, _ := dataKeyBackupFixture(t)
	values, err := readBackupSecrets(backup.Directory, &backup.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	delete(values, "keyring.json")
	raw, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(backup.Directory, backup.Manifest.SecretsFile)
	if err := os.WriteFile(archive, raw, 0600); err != nil {
		t.Fatal(err)
	}
	backup.Manifest.SecretsSize, backup.Manifest.SecretsSHA256, err = fileEvidence(archive)
	if err != nil {
		t.Fatal(err)
	}
	rewriteBackupManifest(t, &backup)
	if _, err := CheckBackup(context.Background(), st.path, backup.ManifestPath, st.cipher); err != nil {
		t.Fatalf("environment-managed archive rejected despite correct supplied master: %v", err)
	}
}

func TestRestorePreservesLegacyPlaintextRelayForSchemaSevenReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	const master = "restore-legacy-relay-master-long-enough"
	c, _ := NewCipher(master)
	kr := keyring.Open(filepath.Dir(path))
	if err := kr.EnsureInitialized(c.KeyID(), master); err != nil {
		t.Fatal(err)
	}
	credentials := []byte(`{"format_version":1,"relay_key":"rk-legacy-schema-seven-relay"}`)
	credentialsPath := filepath.Join(filepath.Dir(path), "secrets", "bootstrap-credentials.json")
	if err := os.WriteFile(credentialsPath, credentials, 0600); err != nil {
		t.Fatal(err)
	}
	db := openDatabaseAtPath(t, path)
	if err := initializeEmptySchemaSeven(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	backup, err := migrateSchemaSevenToEight(context.Background(), db, path, c, MigrationBackupIdentity{})
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBackup(context.Background(), path, backup.ManifestPath, c); err != nil {
		t.Fatalf("historical reader lost its plaintext Relay compatibility: %v", err)
	}
	if _, err := RestoreDatabase(context.Background(), path, backup.ManifestPath, c, true, backup.Manifest.ReaderContract); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(credentialsPath)
	if err != nil || string(raw) != string(credentials) {
		t.Fatal("legacy restore changed persisted Relay bytes")
	}
	fresh, _ := NewCipher(master)
	reopened, err := Open(path, fresh)
	if err != nil {
		t.Fatal(err)
	}
	reopened.Close()
}
