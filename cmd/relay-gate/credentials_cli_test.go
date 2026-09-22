package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCredentialsBootstrapCLI(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := runMain([]string{"relay-gate", "credentials", "bootstrap", "--data-dir", dir},
		strings.NewReader(""), &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "ADMIN_PASSWORD=") ||
		!strings.Contains(out, "RELAY_KEYS=") ||
		!strings.Contains(out, "ENCRYPTION_KEY=") {
		t.Fatalf("stdout missing credentials: %s", out)
	}
	if _, err := filepath.Glob(filepath.Join(dir, "secrets", "*")); err != nil {
		t.Fatal(err)
	}
	code = runMain([]string{"relay-gate", "credentials", "bootstrap", "--data-dir", dir},
		strings.NewReader(""), &stdout, &stderr)
	if code != exitFail {
		t.Fatalf("second bootstrap should fail, code=%d stderr=%s", code, stderr.String())
	}
}

func TestCredentialsMigrateAndResetAdminCLI(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "relay-gate.db")
	if err := os.WriteFile(dbPath, []byte("sqlite-placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENCRYPTION_KEY", "legacy-encryption-key-32bytes!!")
	t.Setenv("ADMIN_PASSWORD", "legacy-admin-password")
	t.Setenv("RELAY_KEYS", "rk-legacy-cli-key")

	var stdout, stderr bytes.Buffer
	code := runMain([]string{"relay-gate", "credentials", "migrate",
		"--data-dir", dir, "--db", dbPath},
		strings.NewReader(""), &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("migrate code=%d stderr=%s", code, stderr.String())
	}
	tip := stdout.String()
	if strings.Contains(tip, "legacy-admin-password") ||
		strings.Contains(tip, "legacy-encryption-key") ||
		strings.Contains(tip, "rk-legacy-cli-key") {
		t.Fatalf("migrate must not print secrets: %s", tip)
	}

	stdout.Reset()
	stderr.Reset()
	code = runMain([]string{"relay-gate", "credentials", "reset-admin", "--data-dir", dir},
		strings.NewReader(""), &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("reset-admin code=%d stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "ADMIN_PASSWORD=") {
		t.Fatalf("reset-admin must print new password once: %s", out)
	}
	if strings.Contains(out, "legacy-admin-password") {
		t.Fatal("reset-admin must not print old password")
	}
}

func TestCredentialsCLIUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMain([]string{"relay-gate", "credentials"}, strings.NewReader(""), &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("code=%d", code)
	}
}
