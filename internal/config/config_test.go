package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/credential"
	"github.com/279814/relay-gate/internal/keyring"
)

func clearCredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("ENCRYPTION_KEY", "")
	t.Setenv("RELAY_KEYS", "")
	t.Setenv("ADMIN_PASSWORD", "")
}

func writeSecretsArtifacts(t *testing.T, dataDir, master, relay, adminHash string) {
	t.Helper()
	kr := keyring.Open(dataDir)
	if err := kr.EnsureInitialized("kid-test", master); err != nil {
		t.Fatal(err)
	}
	if err := credential.WritePersisted(dataDir, credential.Persisted{
		FormatVersion:     1,
		AdminPasswordHash: adminHash,
		RelayKey:          relay,
		MasterKeyID:       "kid-test",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLoad_EnvOnlyStillWorks(t *testing.T) {
	clearCredEnv(t)
	dir := t.TempDir()
	t.Setenv("RELAY_DB", filepath.Join(dir, "relay-gate.db"))
	t.Setenv("ENCRYPTION_KEY", "env-encryption-key-32bytes!!!!")
	t.Setenv("RELAY_KEYS", "rk-env-only")
	t.Setenv("ADMIN_PASSWORD", "env-admin-password")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EncKey != "env-encryption-key-32bytes!!!!" {
		t.Fatalf("enc=%q", cfg.EncKey)
	}
	if len(cfg.RelayKeys) != 1 || cfg.RelayKeys[0] != "rk-env-only" {
		t.Fatalf("relay=%v", cfg.RelayKeys)
	}
}

func TestLoad_FromSecretsArtifactsWhenEnvAbsent(t *testing.T) {
	clearCredEnv(t)
	dir := t.TempDir()
	master := "file-master-key-at-least-16"
	relay := "rk-from-bootstrap-file"
	writeSecretsArtifacts(t, dir, master, relay, "argon2id$placeholder$hash")
	t.Setenv("RELAY_DB", filepath.Join(dir, "relay-gate.db"))

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EncKey != master {
		t.Fatalf("want master from keyring, got %q", cfg.EncKey)
	}
	if len(cfg.RelayKeys) != 1 || cfg.RelayKeys[0] != relay {
		t.Fatalf("want relay from credentials file, got %v", cfg.RelayKeys)
	}
}

func TestLoad_EnvPrecedesSecretsArtifacts(t *testing.T) {
	clearCredEnv(t)
	dir := t.TempDir()
	writeSecretsArtifacts(t, dir, "file-master-key-at-least-16", "rk-from-file", "argon2id$x")
	t.Setenv("RELAY_DB", filepath.Join(dir, "relay-gate.db"))
	t.Setenv("ENCRYPTION_KEY", "env-wins-encryption-key!!")
	t.Setenv("RELAY_KEYS", "rk-env-wins")
	t.Setenv("ADMIN_PASSWORD", "env-admin-password")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EncKey != "env-wins-encryption-key!!" {
		t.Fatalf("env must precede keyring: got %q", cfg.EncKey)
	}
	if len(cfg.RelayKeys) != 1 || cfg.RelayKeys[0] != "rk-env-wins" {
		t.Fatalf("env must precede credentials file: got %v", cfg.RelayKeys)
	}
}

func TestLoad_MissingBothFailsWithoutLeakingSecrets(t *testing.T) {
	clearCredEnv(t)
	dir := t.TempDir()
	t.Setenv("RELAY_DB", filepath.Join(dir, "relay-gate.db"))

	_, err := Load()
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "ENCRYPTION_KEY") || !strings.Contains(msg, "RELAY_KEYS") {
		t.Fatalf("want missing creds named, got %q", msg)
	}
	// No accidental dump of a fabricated secret path content.
	if strings.Contains(msg, "active") && strings.Contains(msg, "key_id") {
		t.Fatalf("error must not dump keyring JSON: %q", msg)
	}
}

func TestLoad_CorruptKeyringDoesNotEchoSecret(t *testing.T) {
	clearCredEnv(t)
	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets")
	if err := os.MkdirAll(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	secretPayload := "super-secret-master-key-value-zzzz"
	if err := os.WriteFile(filepath.Join(secrets, "keyring.json"),
		[]byte("{not-json "+secretPayload), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RELAY_DB", filepath.Join(dir, "relay-gate.db"))

	_, err := Load()
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), secretPayload) {
		t.Fatalf("must not echo secret bytes: %v", err)
	}
	if !strings.Contains(err.Error(), "未回显密钥") {
		t.Fatalf("want safe error wording, got %v", err)
	}
}
