package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
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
