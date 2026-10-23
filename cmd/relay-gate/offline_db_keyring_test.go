package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/keyring"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

const offlineTargetMaster = "fixture-offline-target-master-20261023"
const offlineOtherMaster = "fixture-offline-other-master-20261023"

func offlineDBFixture(t *testing.T) (string, store.MigrationBackupResult) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.db")
	cipher, err := store.NewCipher(offlineTargetMaster)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.Open(dir).EnsureInitialized("fixture-target", offlineTargetMaster); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertSample(&model.Sample{ReqID: "offline-cli-fixture", InMethod: "POST", InBody: []byte("fixture-private-body")}); err != nil {
		t.Fatal(err)
	}
	backup, err := st.CreateRotationBackup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateModelName(&model.ModelName{Name: "created-after-backup", Protocol: model.ProtoAnthropic, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	return path, backup
}

// Execute the actual command dispatcher in another process so cwd and service
// environment cannot accidentally be supplied by another test's setup.
func runOfflineDBChild(t *testing.T, cwd string, env map[string]string, args ...string) (int, string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, append([]string{"-test.run=^TestOfflineDBCLIChildProcess$", "--"}, args...)...)
	command.Dir = cwd
	command.Env = []string{}
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(name) {
		case "RELAY_DB", "RELAY_KEYS", "ADMIN_PASSWORD", "ENCRYPTION_KEY", "RELAY_OFFLINE_DB_CHILD":
			continue
		}
		command.Env = append(command.Env, entry)
	}
	command.Env = append(command.Env, "RELAY_OFFLINE_DB_CHILD=1")
	for name, value := range env {
		command.Env = append(command.Env, name+"="+value)
	}
	output, err := command.CombinedOutput()
	code := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	for _, secret := range []string{offlineTargetMaster, offlineOtherMaster, "fixture-private-body"} {
		if bytes.Contains(output, []byte(secret)) {
			t.Fatal("offline CLI leaked sensitive fixture data")
		}
	}
	return code, string(output)
}
func TestOfflineDBCLIChildProcess(t *testing.T) {
	if os.Getenv("RELAY_OFFLINE_DB_CHILD") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Exit(runMain(append([]string{"relay-gate"}, os.Args[i+1:]...), nil, os.Stdout, os.Stderr))
		}
	}
	os.Exit(99)
}
func offlineFileHashes(t *testing.T, paths ...string) map[string][32]byte {
	t.Helper()
	result := map[string][32]byte{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		result[path] = sha256.Sum256(data)
	}
	return result
}
func assertOfflineHashes(t *testing.T, want map[string][32]byte) {
	t.Helper()
	for path, hash := range want {
		raw, err := os.ReadFile(path)
		if err != nil || sha256.Sum256(raw) != hash {
			t.Fatalf("offline refusal/check modified source %s", filepath.Base(path))
		}
	}
}

func TestOfflineDBCLITargetKeyringNeedsNoServerIdentityOrWorkingDirectory(t *testing.T) {
	for _, mode := range []string{"check-backup", "restore"} {
		t.Run(mode, func(t *testing.T) {
			path, backup := offlineDBFixture(t)
			cwd := t.TempDir()
			if err := keyring.Open(filepath.Join(cwd, "data")).EnsureInitialized("fixture-cwd", offlineOtherMaster); err != nil {
				t.Fatal(err)
			}
			before := offlineFileHashes(t, path, keyring.Open(filepath.Dir(path)).Path(), backup.ManifestPath, backup.DatabasePath)
			args := []string{"db", mode, "--database", path, "--manifest", backup.ManifestPath}
			if mode == "restore" {
				args = append(args, "--execute", "--accept-data-replacement", "--accept-reader-contract", backup.Manifest.ReaderContract)
			}
			code, output := runOfflineDBChild(t, cwd, map[string]string{"RELAY_DB": filepath.Join(cwd, "data", "different.db")}, args...)
			if code != exitOK {
				t.Fatalf("target-directory offline %s rejected without unrelated service credentials: code=%d %s", mode, code, output)
			}
			if mode == "check-backup" {
				assertOfflineHashes(t, before)
				if !strings.Contains(output, "ReaderContract=") {
					t.Fatal("check did not output paired reader")
				}
			} else {
				cipher, _ := store.NewCipher(offlineTargetMaster)
				restored, err := store.Open(path, cipher)
				if err != nil {
					t.Fatal(err)
				}
				defer restored.Close()
				var n int
				if err := restored.DB().QueryRow(`SELECT COUNT(*) FROM model_name WHERE name='created-after-backup'`).Scan(&n); err != nil || n != 0 {
					t.Fatalf("restore did not install backed-up generation: n=%d err=%v", n, err)
				}
			}
		})
	}
}

func TestOfflineDBCLIExplicitMasterWinsAndWrongMasterNeverFallsBack(t *testing.T) {
	path, backup := offlineDBFixture(t)
	cwd := t.TempDir()
	kr := keyring.Open(filepath.Dir(path))
	raw := fmt.Sprintf(`{"format_version":1,"key_id":"fixture-other","active":%q}`, offlineOtherMaster)
	if err := os.WriteFile(kr.Path(), []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"db", "check-backup", "--database", path, "--manifest", backup.ManifestPath}
	if code, output := runOfflineDBChild(t, cwd, map[string]string{"ENCRYPTION_KEY": offlineTargetMaster}, args...); code != exitOK {
		t.Fatalf("explicit correct master was ignored: %d %s", code, output)
	}
	if err := os.WriteFile(kr.Path(), []byte(fmt.Sprintf(`{"format_version":1,"key_id":"fixture-target","active":%q}`, offlineTargetMaster)), 0600); err != nil {
		t.Fatal(err)
	}
	before := offlineFileHashes(t, path, kr.Path(), backup.ManifestPath)
	if code, output := runOfflineDBChild(t, cwd, map[string]string{"ENCRYPTION_KEY": offlineOtherMaster}, args...); code != exitFail || !strings.Contains(output, "check-backup") {
		t.Fatalf("wrong override was silently replaced by target key: %d %s", code, output)
	}
	assertOfflineHashes(t, before)
}

func TestOfflineDBCLIRejectsUnstableOrUnknownTargetKeyringWithoutChangingIt(t *testing.T) {
	for _, name := range []string{"prepared", "db_committed", "key_activated", "unknown_phase", "unknown_format", "pending_idle", "idle_rotation_id", "empty_id", "empty_active", "corrupt_current_with_previous", "missing_current_with_previous", "wrong_active"} {
		t.Run(name, func(t *testing.T) {
			path, backup := offlineDBFixture(t)
			kr := keyring.Open(filepath.Dir(path))
			previous := filepath.Join(filepath.Dir(kr.Path()), "keyring.previous")
			stable := fmt.Sprintf(`{"format_version":1,"key_id":"fixture-target","active":%q}`, offlineTargetMaster)
			raw := stable
			switch name {
			case "prepared", "db_committed", "key_activated":
				raw = fmt.Sprintf(`{"format_version":1,"key_id":"fixture-target","active":%q,"pending":%q,"rotation_id":"fixture-rotation","phase":%q}`, offlineTargetMaster, offlineOtherMaster, name)
			case "unknown_phase":
				raw = fmt.Sprintf(`{"format_version":1,"key_id":"fixture-target","active":%q,"phase":"future-format"}`, offlineTargetMaster)
			case "unknown_format":
				raw = fmt.Sprintf(`{"format_version":2,"key_id":"fixture-target","active":%q}`, offlineTargetMaster)
			case "idle_rotation_id":
				raw = fmt.Sprintf(`{"format_version":1,"key_id":"fixture-target","active":%q,"rotation_id":"unfinished-id"}`, offlineTargetMaster)
			case "pending_idle":
				raw = fmt.Sprintf(`{"format_version":1,"key_id":"fixture-target","active":%q,"pending":%q}`, offlineTargetMaster, offlineOtherMaster)
			case "empty_id":
				raw = fmt.Sprintf(`{"format_version":1,"active":%q}`, offlineTargetMaster)
			case "empty_active":
				raw = `{"format_version":1,"key_id":"fixture-target","active":""}`
			case "wrong_active":
				raw = fmt.Sprintf(`{"format_version":1,"key_id":"fixture-target","active":%q}`, offlineOtherMaster)
			case "corrupt_current_with_previous", "missing_current_with_previous":
				if err := os.WriteFile(previous, []byte(stable), 0600); err != nil {
					t.Fatal(err)
				}
				raw = "{broken-current"
			}
			if err := os.WriteFile(kr.Path(), []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			paths := []string{path, backup.ManifestPath, backup.DatabasePath}
			if name == "missing_current_with_previous" {
				if err := os.Remove(kr.Path()); err != nil {
					t.Fatal(err)
				}
			} else {
				paths = append(paths, kr.Path())
			}
			if _, err := os.Stat(previous); err == nil {
				paths = append(paths, previous)
			}
			before := offlineFileHashes(t, paths...)
			code, output := runOfflineDBChild(t, t.TempDir(), nil, "db", "check-backup", "--database", path, "--manifest", backup.ManifestPath)
			if code != exitFail {
				t.Fatalf("unsafe target keyring %s accepted: %d", name, code)
			}
			if name == "prepared" && !strings.Contains(output, "未完成") {
				t.Fatalf("rotation refusal not explicit: %s", output)
			}
			assertOfflineHashes(t, before)
			if name == "missing_current_with_previous" {
				if _, err := os.Lstat(kr.Path()); !os.IsNotExist(err) {
					t.Fatal("offline check recovered or rewrote missing current keyring")
				}
			}
		})
	}
}

func TestOfflineDBCLIAcceptsStableCleanedTargetWithoutServiceFiles(t *testing.T) {
	path, backup := offlineDBFixture(t)
	current := keyring.Open(filepath.Dir(path)).Path()
	document := fmt.Sprintf(`{"format_version":1,"key_id":"fixture-cleaned","active":%q,"phase":"cleaned","rotation_id":"finished-rotation"}`, offlineTargetMaster)
	if err := os.WriteFile(current, []byte(document), 0600); err != nil {
		t.Fatal(err)
	}
	before := offlineFileHashes(t, path, current, backup.ManifestPath, backup.DatabasePath)
	if code, output := runOfflineDBChild(t, t.TempDir(), nil, "db", "check-backup", "--database", path, "--manifest", backup.ManifestPath); code != exitOK {
		t.Fatalf("stable cleaned target rejected: %d %s", code, output)
	}
	assertOfflineHashes(t, before)
}
