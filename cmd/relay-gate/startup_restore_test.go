package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestStartupRejectsInvalidRestoreBeforeBootstrapCreatesSecrets(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RELAY_DB", filepath.Join(dir, "custom.db"))
	for _, name := range []string{"ENCRYPTION_KEY", "RELAY_KEYS", "ADMIN_PASSWORD"} {
		t.Setenv(name, "")
	}
	if err := os.WriteFile(filepath.Join(dir, "restore-intent.json"), []byte(`{"format_version":-1}`), 0600); err != nil {
		t.Fatal(err)
	}
	// Capture first-run output so a failed ordering regression cannot print
	// even the temporary fixture's generated credentials into test logs.
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = writer
	err = runServer()
	os.Stdout = previous
	_ = writer.Close()
	_, _ = io.Copy(io.Discard, reader)
	_ = reader.Close()
	if err == nil {
		t.Fatal("invalid pending restore was ignored")
	}
	if _, err := os.Stat(filepath.Join(dir, "secrets")); !os.IsNotExist(err) {
		t.Fatal("bootstrap touched secrets before pending restore validation")
	}
}
