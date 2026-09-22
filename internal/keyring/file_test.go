package keyring

import (
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
