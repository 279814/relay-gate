package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseDBFlagsRequiresPaths(t *testing.T) {
	if _, err := parseDBFlags([]string{"check-backup"}); err == nil {
		t.Fatal("expected error without paths")
	}
	f, err := parseDBFlags([]string{
		"restore",
		"--database", `D:\data\relay.db`,
		"--manifest", `D:\data\backups\m\manifest.json`,
		"--execute",
		"--accept-data-replacement",
		"--accept-reader-contract", "schema-2-reader",
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.cmd != "restore" || !f.execute || !f.acceptDataReplacement || f.acceptReaderContract != "schema-2-reader" {
		t.Fatalf("flags = %+v", f)
	}
}

func TestRunDBCLIRejectsRestoreWithoutAuth(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runDBCLI([]string{
		"restore",
		"--database", "x.db",
		"--manifest", "m.json",
	}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--execute") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestRunMainDispatchesDBBeforeServer(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMain([]string{"relay-gate", "db"}, nil, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "check-backup") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}
