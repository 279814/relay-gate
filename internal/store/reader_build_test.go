package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRotationBackupIdentifiesActualReaderArtifactInsteadOfSymbolicMarker(t *testing.T) {
	_, backup, _ := dataKeyBackupFixture(t)
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(raw)
	if !strings.Contains(backup.Manifest.PairedBuildID, "sha256:"+hex.EncodeToString(want[:])) {
		t.Fatalf("backup cannot identify its actual paired reader binary: %q", backup.Manifest.PairedBuildID)
	}
	if !strings.Contains(backup.Manifest.PairedBuildID, "version=dev") {
		t.Fatalf("unversioned test build must remain dev: %s", backup.Manifest.PairedBuildID)
	}
}

func TestReaderBuildIDLabelsAreDiagnosticAndDoNotClaimARelease(t *testing.T) {
	for _, label := range []string{"", "dev", "custom-not-a-release", "fixture\nnewline"} {
		id, err := CurrentReaderBuildID(label)
		if err != nil {
			t.Fatal(err)
		}
		if len(strings.SplitN(id, " ", 2)[0]) != len("sha256:")+64 {
			t.Fatalf("not full artifact SHA: %s", id)
		}
		if strings.ContainsAny(id, "\r\n") {
			t.Fatal("build label injected a log line")
		}
		if !strings.Contains(id, "platform="+runtime.GOOS+"/"+runtime.GOARCH) || !strings.Contains(id, " vcs=") || !strings.Contains(id, " modified=") {
			t.Fatalf("missing build diagnostics: %s", id)
		}
		if (label == "" || label == "dev") && !strings.Contains(id, "version=dev") {
			t.Fatal("unversioned build claimed a release")
		}
	}
}

func TestRotationBackupCarriesStartupIdentityAndOldMarkerRemainsReadable(t *testing.T) {
	st, old, _ := schemaEightDataKeyBackupFixture(t)
	path := st.path
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	identity, err := CurrentReaderBuildID("fixture-startup-label")
	if err != nil {
		t.Fatal(err)
	}
	lock, err := AcquireInstanceLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	cipher, _ := NewCipher("backup-data-key-master-long-enough")
	opened, err := OpenLockedWithReaderBuildID(path, cipher, lock, identity)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	migrations, err := filepath.Glob(filepath.Join(filepath.Dir(path), "backups", "schema-8-to-9-*", "manifest.json"))
	if err != nil || len(migrations) != 1 {
		t.Fatalf("schema9 migration backup=%v err=%v", migrations, err)
	}
	migrated, err := CheckBackup(context.Background(), path, migrations[0], cipher)
	if err != nil || migrated.PairedBuildID != identity || migrated.ReaderContract != "schema-8-data-key-v2-reader" {
		t.Fatalf("schema9 migration lost actual startup reader: %+v err=%v", migrated, err)
	}
	backup, err := opened.CreateRotationBackup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if backup.Manifest.PairedBuildID != identity || backup.Manifest.ReaderContract != "schema-9-route-health-v1-reader" {
		t.Fatalf("startup identity lost: %+v", backup.Manifest)
	}
	checked, err := CheckBackup(context.Background(), path, backup.ManifestPath, cipher)
	if err != nil || checked.PairedBuildID != identity {
		t.Fatalf("new backup not readable: %+v %v", checked, err)
	}
	// Historical manifests have the symbolic marker. Read-only validation and
	// explicit restore must remain compatible; the creator's artifact hash is
	// provenance, not an equality gate on a compatible reader.
	old.Manifest.PairedBuildID = "relay-gate-schema-8-data-key-v2"
	raw, err := json.Marshal(old.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(old.ManifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(old.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBackup(context.Background(), path, old.ManifestPath, cipher); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(old.DatabasePath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("checking old marker changed backup")
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := RestoreDatabase(context.Background(), path, old.ManifestPath, cipher, true, old.Manifest.ReaderContract)
	if err != nil || result.PairedBuildID != old.Manifest.PairedBuildID {
		t.Fatalf("old marker restore failed: %+v %v", result, err)
	}
	fresh, _ := NewCipher("backup-data-key-master-long-enough")
	reopened, err := Open(path, fresh)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
}
