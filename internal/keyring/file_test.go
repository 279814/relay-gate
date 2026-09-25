package keyring

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestKeyringRoundTrip(t *testing.T) {
	dir := t.TempDir()
	f := Open(dir)
	if err := f.EnsureInitialized("k1", "master-secret-value-32b!!!!"); err != nil {
		t.Fatal(err)
	}
	// Second ensure is no-op.
	if err := f.EnsureInitialized("k2", "other"); err != nil {
		t.Fatal(err)
	}
	id, secret, err := f.LoadActive()
	if err != nil {
		t.Fatal(err)
	}
	if id != "k1" || secret != "master-secret-value-32b!!!!" {
		t.Fatalf("got %q %q", id, secret)
	}
	info, err := os.Stat(f.Path())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("keyring perms too open: %v", info.Mode())
	}
	dirInfo, err := os.Stat(filepath.Dir(f.Path()))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && dirInfo.Mode().Perm()&0o077 != 0 {
		t.Fatalf("secrets dir perms too open: %v", dirInfo.Mode())
	}
}

func TestKeyringMissing(t *testing.T) {
	f := Open(t.TempDir())
	if _, _, err := f.LoadActive(); err != ErrNotInitialized {
		t.Fatalf("err = %v", err)
	}
}

func TestWriteKeepsVerifiedPrevious(t *testing.T) {
	const firstMaster = "master-secret-value-32b!!!!"
	const secondMaster = "master-second-secret-32b!!!"
	f := Open(t.TempDir())
	if err := f.EnsureInitialized("k1", firstMaster); err != nil {
		t.Fatal(err)
	}
	priorRaw, err := os.ReadFile(f.Path())
	if err != nil {
		t.Fatal(err)
	}
	var prior document
	if err := json.Unmarshal(priorRaw, &prior); err != nil {
		t.Fatal(err)
	}

	if _, err := f.BeginRotation(secondMaster); err != nil {
		t.Fatal(err)
	}

	prevPath := filepath.Join(filepath.Dir(f.Path()), "keyring.previous")
	prevRaw, err := os.ReadFile(prevPath)
	if err != nil {
		t.Fatalf("keyring.previous missing after successful write: %v", err)
	}
	var prev document
	if err := json.Unmarshal(prevRaw, &prev); err != nil {
		t.Fatalf("keyring.previous must parse: %v", err)
	}
	if prev.KeyID != prior.KeyID || prev.Active != prior.Active || prev.Phase != prior.Phase {
		t.Fatalf("previous=%+v want prior=%+v", prev, prior)
	}
	id, active, err := f.LoadActive()
	if err != nil || id != "k1" || active != firstMaster {
		t.Fatalf("current still loads: id=%q active=%q err=%v", id, active, err)
	}
}

func TestFailedWriteLeavesCurrentAndPreviousIntact(t *testing.T) {
	const firstMaster = "master-secret-value-32b!!!!"
	f := Open(t.TempDir())
	if err := f.EnsureInitialized("k1", firstMaster); err != nil {
		t.Fatal(err)
	}
	if _, err := f.BeginRotation("master-second-secret-32b!!!"); err != nil {
		t.Fatal(err)
	}
	beforeCurrent, err := os.ReadFile(f.Path())
	if err != nil {
		t.Fatal(err)
	}
	prevPath := filepath.Join(filepath.Dir(f.Path()), "keyring.previous")
	beforePrev, err := os.ReadFile(prevPath)
	if err != nil {
		t.Fatal(err)
	}

	// Non-empty directory at path.tmp makes writeSyncedFile fail before
	// preservePrevious or rename; current and previous must stay untouched.
	tmp := f.Path() + ".tmp"
	if err := os.MkdirAll(filepath.Join(tmp, "blocker"), 0o700); err != nil {
		t.Fatal(err)
	}

	st, err := f.Status()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.MarkDBCommitted(st.RotationID); err == nil {
		t.Fatal("expected write failure")
	}

	afterCurrent, err := os.ReadFile(f.Path())
	if err != nil {
		t.Fatal(err)
	}
	afterPrev, err := os.ReadFile(prevPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterCurrent) != string(beforeCurrent) {
		t.Fatal("failed write replaced current keyring")
	}
	if string(afterPrev) != string(beforePrev) {
		t.Fatal("failed write replaced keyring.previous")
	}
	var prev document
	if err := json.Unmarshal(afterPrev, &prev); err != nil {
		t.Fatalf("previous must still parse: %v", err)
	}
	id, active, err := f.LoadActive()
	if err != nil || id != "k1" || active != firstMaster {
		t.Fatalf("current still loads: id=%q active=%q err=%v", id, active, err)
	}
}
