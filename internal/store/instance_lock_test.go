package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInstanceLockIsExclusiveAndReleased(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "relay.db")
	first, err := acquireInstanceLock(databasePath)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}

	if _, err := acquireInstanceLock(databasePath); !errors.Is(err, ErrInstanceLocked) {
		t.Fatalf("second lock error = %v, want ErrInstanceLocked", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("release first lock: %v", err)
	}

	third, err := acquireInstanceLock(databasePath)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	if err := third.Close(); err != nil {
		t.Fatalf("release third lock: %v", err)
	}
}

func TestInstanceLockRejectsSymlinkLockFile(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("do not lock through this file"), 0o600); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(directory, "relay.db.lock")
	if err := os.Symlink(target, lockPath); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	if _, err := acquireInstanceLock(filepath.Join(directory, "relay.db")); !errors.Is(err, ErrUnsafeLockPath) {
		t.Fatalf("symlink lock error = %v, want ErrUnsafeLockPath", err)
	}
}
