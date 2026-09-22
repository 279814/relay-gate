package main

import (
	"bytes"
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

func TestCredentialsCLIUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMain([]string{"relay-gate", "credentials"}, strings.NewReader(""), &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("code=%d", code)
	}
}
