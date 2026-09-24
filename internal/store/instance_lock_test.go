package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestInstanceLockRejectsSymlinkDatabasePath(t *testing.T) {
	directory := t.TempDir()
	realPath := filepath.Join(directory, "relay.db")
	if err := os.WriteFile(realPath, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	aliasPath := filepath.Join(directory, "alias.db")
	if err := os.Symlink(realPath, aliasPath); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	realLock, err := acquireInstanceLock(realPath)
	if err != nil {
		t.Fatalf("lock real database path: %v", err)
	}
	defer realLock.Close()

	if _, err := acquireInstanceLock(aliasPath); !errors.Is(err, ErrUnsafeLockPath) {
		t.Fatalf("symlink database path error = %v, want ErrUnsafeLockPath", err)
	}
}

func TestRejectSymlinkDatabasePathAllowsMissingAndRegular(t *testing.T) {
	directory := t.TempDir()
	missing := filepath.Join(directory, "missing.db")
	if err := rejectSymlinkDatabasePath(missing); err != nil {
		t.Fatalf("missing path: %v", err)
	}

	regular := filepath.Join(directory, "relay.db")
	if err := os.WriteFile(regular, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rejectSymlinkDatabasePath(regular); err != nil {
		t.Fatalf("regular path: %v", err)
	}
}

func TestIsSymlinkOrReparse(t *testing.T) {
	if isSymlinkOrReparse(modeOnlyInfo{mode: 0o600}) {
		t.Fatal("regular file reported as symlink/reparse")
	}
	if !isSymlinkOrReparse(modeOnlyInfo{mode: os.ModeSymlink | 0o777}) {
		t.Fatal("ModeSymlink not detected")
	}
}

type modeOnlyInfo struct {
	mode os.FileMode
}

func (m modeOnlyInfo) Name() string       { return "stub" }
func (m modeOnlyInfo) Size() int64        { return 0 }
func (m modeOnlyInfo) Mode() os.FileMode  { return m.mode }
func (m modeOnlyInfo) ModTime() time.Time { return time.Time{} }
func (m modeOnlyInfo) IsDir() bool        { return m.mode.IsDir() }
func (m modeOnlyInfo) Sys() any           { return nil }
