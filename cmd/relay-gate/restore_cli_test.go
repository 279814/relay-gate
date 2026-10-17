package main

import (
	"bytes"
	"context"
	"github.com/279814/relay-gate/internal/keyring"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
	"os"
	"path/filepath"
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

func TestRunDBCLIRestoresOldMasterBackupUsingExplicitArchivedKeyring(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.db")
	const oldMaster = "cli-old-backup-master-never-print"
	const newMaster = "cli-new-active-master-never-print"
	c, _ := store.NewCipher(oldMaster)
	st, err := store.Open(path, c)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	kr := keyring.Open(dir)
	// Later rotations use a journal key ID, deliberately distinct from the
	// encryption derivation's identifier in BackupManifest.LegacyCipherID.
	if err := kr.EnsureInitialized("mk_previous_rotation", oldMaster); err != nil {
		t.Fatal(err)
	}
	smp := &model.Sample{ReqID: "cli-backup", TSRecv: 42, InMethod: "POST", InPath: "/v1/messages", InBody: []byte("private original body"), Outcome: model.OutcomeOK}
	if err := st.InsertSample(smp); err != nil {
		t.Fatal(err)
	}
	backup, err := st.CreateRotationBackup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RewrapDirectSecrets(newMaster, "cli-next-rotation"); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if err := os.WriteFile(kr.Path(), []byte(`{"format_version":1,"key_id":"mk_new","active":"`+newMaster+`","phase":"cleaned"}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENCRYPTION_KEY", newMaster)
	t.Setenv("RELAY_KEYS", "")
	t.Setenv("ADMIN_PASSWORD", "")
	var stdout, stderr bytes.Buffer
	args := []string{"relay-gate", "db", "check-backup", "--database", path, "--manifest", backup.ManifestPath, "--use-backup-keyring"}
	if code := runMain(args, nil, &stdout, &stderr); code != exitOK {
		t.Fatalf("archived keyring check failed: code=%d %s", code, stderr.String())
	}
	args = []string{"relay-gate", "db", "restore", "--database", path, "--manifest", backup.ManifestPath, "--use-backup-keyring", "--execute", "--accept-data-replacement", "--accept-reader-contract", backup.Manifest.ReaderContract}
	if code := runMain(args, nil, &stdout, &stderr); code != exitOK {
		t.Fatalf("archived keyring restore failed: code=%d %s", code, stderr.String())
	}
	for _, secret := range []string{oldMaster, newMaster, "private original body"} {
		if strings.Contains(stdout.String()+stderr.String(), secret) {
			t.Fatal("CLI exposed archived key material or sample text")
		}
	}
	fresh, _ := store.NewCipher(oldMaster)
	reopened, err := store.Open(path, fresh)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.GetSample(smp.ID)
	if err != nil || string(got.InBody) != "private original body" {
		t.Fatalf("archived pair failed after restore: %v", err)
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
