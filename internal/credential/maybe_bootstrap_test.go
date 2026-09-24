package credential

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/keyring"
)

func TestMaybeBootstrap_FreshPrintsOnceThenRefusesReprint(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ENCRYPTION_KEY", "")
	t.Setenv("RELAY_KEYS", "")
	t.Setenv("ADMIN_PASSWORD", "")

	var first bytes.Buffer
	if err := MaybeBootstrap(dir, &first); err != nil {
		t.Fatal(err)
	}
	out := first.String()
	if !strings.Contains(out, "ADMIN_PASSWORD=") ||
		!strings.Contains(out, "RELAY_KEYS=") ||
		!strings.Contains(out, "ENCRYPTION_KEY=") {
		t.Fatalf("first start must print three secrets once, got %q", out)
	}

	var second bytes.Buffer
	if err := MaybeBootstrap(dir, &second); err != nil {
		t.Fatal(err)
	}
	if second.Len() != 0 {
		t.Fatalf("later restart must not reprint secrets, got %q", second.String())
	}

	// Existing crash-safe Bootstrap also refuses a second Run.
	b := &Bootstrap{DataDir: dir, Out: &bytes.Buffer{}}
	_, err := b.Run()
	if err == nil {
		t.Fatal("Bootstrap.Run must refuse when secrets already exist")
	}
}

func TestMaybeBootstrap_EnvSecretsSkipGeneration(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ENCRYPTION_KEY", "env-encryption-key-32bytes!!!!")
	t.Setenv("RELAY_KEYS", "rk-env-provided")
	t.Setenv("ADMIN_PASSWORD", "env-admin-password")

	var out bytes.Buffer
	if err := MaybeBootstrap(dir, &out); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("env-provided secrets must not trigger bootstrap print, got %q", out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "secrets", "credentials-bootstrap.journal")); !os.IsNotExist(err) {
		t.Fatalf("env path must not write bootstrap journal, err=%v", err)
	}
}

func TestMaybeBootstrap_ExistingArtifactsSkipGeneration(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ENCRYPTION_KEY", "")
	t.Setenv("RELAY_KEYS", "")
	t.Setenv("ADMIN_PASSWORD", "")

	// Simulate migrate/manual artifacts without a bootstrap journal.
	kr := keyring.Open(dir)
	if err := kr.EnsureInitialized("kid", "master-key-from-artifacts-32b!!"); err != nil {
		t.Fatal(err)
	}
	hash, err := HashAdminPassword("already-set-admin-pw")
	if err != nil {
		t.Fatal(err)
	}
	if err := WritePersisted(dir, Persisted{
		FormatVersion:     1,
		AdminPasswordHash: hash,
		RelayKey:          "rk-already-on-disk",
		MasterKeyID:       "kid",
	}); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := MaybeBootstrap(dir, &out); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("existing artifacts must not regenerate, got %q", out.String())
	}
}
