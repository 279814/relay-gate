package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/keyring"
	"github.com/279814/relay-gate/internal/store"
)

func holdInstanceLock(t *testing.T, dbPath string) {
	t.Helper()
	held, err := store.AcquireInstanceLock(dbPath)
	if err != nil {
		t.Fatalf("AcquireInstanceLock: %v", err)
	}
	t.Cleanup(func() { _ = held.Close() })
}

func TestRunServer_LockedDataDirWritesNoBootstrapSecrets(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "relay-gate.db")
	t.Setenv("RELAY_DB", dbPath)
	t.Setenv("ENCRYPTION_KEY", "")
	t.Setenv("ADMIN_PASSWORD", "")
	t.Setenv("RELAY_KEYS", "")
	holdInstanceLock(t, dbPath)

	if err := runServer(); !errors.Is(err, store.ErrInstanceLocked) {
		t.Fatalf("runServer error = %v, want ErrInstanceLocked", err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "secrets"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("second process wrote secrets/%s while instance lock was held", e.Name())
	}
}

func TestRunServer_CustomDBStillTakesDataDirLock(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RELAY_DB", filepath.Join(dir, "custom.db"))
	t.Setenv("RELAY_ADDR", "invalid-listen-address")
	t.Setenv("ENCRYPTION_KEY", "")
	t.Setenv("ADMIN_PASSWORD", "")
	t.Setenv("RELAY_KEYS", "")
	holdInstanceLock(t, filepath.Join(dir, "relay-gate.db"))

	if err := runServer(); !errors.Is(err, store.ErrInstanceLocked) {
		t.Fatalf("runServer error = %v, want ErrInstanceLocked", err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "secrets"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("server wrote secrets/%s while data dir lock was held", e.Name())
	}
}

func TestRunServer_LockedDataDirLeavesRotationUntouched(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "relay-gate.db")
	const master = "test-master-key-at-least-16-chars"
	t.Setenv("RELAY_DB", dbPath)
	t.Setenv("ENCRYPTION_KEY", master)
	t.Setenv("ADMIN_PASSWORD", "test-admin-password")
	t.Setenv("RELAY_KEYS", "test-relay-key")

	kr := keyring.Open(dir)
	if err := kr.EnsureInitialized("mk_test", master); err != nil {
		t.Fatal(err)
	}
	if _, err := kr.BeginRotation("test-pending-key-at-least-16-chars"); err != nil {
		t.Fatal(err)
	}
	secretsDir := filepath.Join(dir, "secrets")
	before := readDirFiles(t, secretsDir)
	holdInstanceLock(t, dbPath)

	if err := runServer(); !errors.Is(err, store.ErrInstanceLocked) {
		t.Fatalf("runServer error = %v, want ErrInstanceLocked", err)
	}
	after := readDirFiles(t, secretsDir)
	if len(after) != len(before) {
		t.Fatalf("secrets files before=%d after=%d, second process must not create files", len(before), len(after))
	}
	for name, raw := range before {
		if !bytes.Equal(raw, after[name]) {
			t.Errorf("second process rewrote secrets/%s (live rotation) while instance lock was held", name)
		}
	}
	if st, err := kr.Status(); err != nil || st.Phase != keyring.PhasePrepared {
		t.Fatalf("keyring status = %+v, %v; want phase prepared", st, err)
	}
}

func TestCredentialsCLI_LockedDataDirWritesNoSecrets(t *testing.T) {
	cases := []struct {
		name string
		args func(dir, dbPath string) []string
	}{
		{"bootstrap", func(dir, _ string) []string {
			return []string{"relay-gate", "credentials", "bootstrap", "--data-dir", dir}
		}},
		{"migrate", func(dir, dbPath string) []string {
			return []string{"relay-gate", "credentials", "migrate", "--data-dir", dir, "--db", dbPath}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			dbPath := filepath.Join(dir, "relay-gate.db")
			if err := os.WriteFile(dbPath, []byte("sqlite-placeholder"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("RELAY_DB", "")
			t.Setenv("ENCRYPTION_KEY", "legacy-encryption-key-32bytes!!")
			t.Setenv("ADMIN_PASSWORD", "legacy-admin-password")
			t.Setenv("RELAY_KEYS", "rk-legacy-cli-key")
			holdInstanceLock(t, dbPath)

			if _, err := acquireDataDirLock(dir); !errors.Is(err, store.ErrInstanceLocked) {
				t.Fatalf("acquireDataDirLock error = %v, want ErrInstanceLocked", err)
			}
			var stdout, stderr bytes.Buffer
			code := runMain(tc.args(dir, dbPath), strings.NewReader(""), &stdout, &stderr)
			if code != exitFail || !strings.Contains(stderr.String(), store.ErrInstanceLocked.Error()) {
				t.Fatalf("code=%d stderr=%s, want ErrInstanceLocked", code, stderr.String())
			}
			entries, err := os.ReadDir(filepath.Join(dir, "secrets"))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			for _, e := range entries {
				t.Errorf("credentials %s wrote secrets/%s while instance lock was held", tc.name, e.Name())
			}
			if stdout.Len() != 0 {
				t.Errorf("credentials %s printed output while instance lock was held: %s", tc.name, stdout.String())
			}
		})
	}
}

func TestCredentialsResetAdminCLI_LockedDataDirLeavesSecretsUntouched(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "custom.db")
	t.Setenv("RELAY_DB", dbPath)
	var stdout, stderr bytes.Buffer
	if code := runMain([]string{"relay-gate", "credentials", "bootstrap", "--data-dir", dir},
		strings.NewReader(""), &stdout, &stderr); code != exitOK {
		t.Fatalf("bootstrap code=%d stderr=%s", code, stderr.String())
	}
	secretsDir := filepath.Join(dir, "secrets")
	before := readDirFiles(t, secretsDir)
	holdInstanceLock(t, dbPath)

	stdout.Reset()
	stderr.Reset()
	code := runMain([]string{"relay-gate", "credentials", "reset-admin", "--data-dir", dir},
		strings.NewReader(""), &stdout, &stderr)
	if code != exitFail || !strings.Contains(stderr.String(), store.ErrInstanceLocked.Error()) {
		t.Fatalf("code=%d stderr=%s, want ErrInstanceLocked", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "ADMIN_PASSWORD=") {
		t.Fatalf("reset-admin printed a new password while instance lock was held")
	}
	after := readDirFiles(t, secretsDir)
	if len(after) != len(before) {
		t.Fatalf("secrets files before=%d after=%d, reset-admin must not create files", len(before), len(after))
	}
	for name, raw := range before {
		if !bytes.Equal(raw, after[name]) {
			t.Errorf("reset-admin rewrote secrets/%s while instance lock was held", name)
		}
	}
}

func TestCredentialsCLI_ServerCustomDBLockBlocksDataDirOnlyCLI(t *testing.T) {
	for _, sub := range []string{"bootstrap", "migrate", "reset-admin"} {
		t.Run(sub, func(t *testing.T) {
			dir := t.TempDir()
			serverDB := filepath.Join(dir, "custom.db")
			t.Setenv("RELAY_DB", "")
			t.Setenv("ENCRYPTION_KEY", "legacy-encryption-key-32bytes!!")
			t.Setenv("ADMIN_PASSWORD", "legacy-admin-password")
			t.Setenv("RELAY_KEYS", "rk-legacy-cli-key")
			secretsDir := filepath.Join(dir, "secrets")
			var stdout, stderr bytes.Buffer
			if sub == "reset-admin" {
				if code := runMain([]string{"relay-gate", "credentials", "bootstrap", "--data-dir", dir},
					strings.NewReader(""), &stdout, &stderr); code != exitOK {
					t.Fatalf("bootstrap code=%d stderr=%s", code, stderr.String())
				}
				stdout.Reset()
				stderr.Reset()
			}
			before := map[string][]byte{}
			if _, err := os.Stat(secretsDir); err == nil {
				before = readDirFiles(t, secretsDir)
			}

			// 与 runServer 相同的取锁：RELAY_DB=<dir>/custom.db。
			held, err := lockDataDir(dir, serverDB)
			if err != nil {
				t.Fatalf("lockDataDir: %v", err)
			}
			t.Cleanup(func() { _ = held.Close() })

			code := runMain([]string{"relay-gate", "credentials", sub, "--data-dir", dir},
				strings.NewReader(""), &stdout, &stderr)
			if code != exitFail || !strings.Contains(stderr.String(), store.ErrInstanceLocked.Error()) {
				t.Fatalf("code=%d stderr=%s, want ErrInstanceLocked", code, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Errorf("credentials %s printed output while server held the data dir: %s", sub, stdout.String())
			}
			after := map[string][]byte{}
			if _, err := os.Stat(secretsDir); err == nil {
				after = readDirFiles(t, secretsDir)
			}
			if len(after) != len(before) {
				t.Fatalf("secrets files before=%d after=%d, credentials %s must not write", len(before), len(after), sub)
			}
			for name, raw := range before {
				if !bytes.Equal(raw, after[name]) {
					t.Errorf("credentials %s rewrote secrets/%s while server held the data dir", sub, name)
				}
			}
		})
	}
}

func readDirFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string][]byte, len(entries))
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files[e.Name()] = raw
	}
	return files
}
