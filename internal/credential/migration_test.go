package credential

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/keyring"
	"github.com/279814/relay-gate/internal/store"
)

func TestMigrationImportsEnvAsArgon2NoSecretsInOutput(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "relay-gate.db")
	// Minimal DB file as legacy evidence (schema presence, not empty-keyring guess).
	if err := os.WriteFile(dbPath, []byte("sqlite-placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	enc := "legacy-encryption-key-32bytes!!"
	admin := "legacy-admin-password"
	relay := "rk-legacy-relay-key-value"
	var out bytes.Buffer
	m := &Migration{
		DataDir:   dir,
		DBPath:    dbPath,
		EncKey:    enc,
		AdminPW:   admin,
		RelayKeys: []string{relay},
		Out:       &out,
	}
	if err := m.Run(); err != nil {
		t.Fatal(err)
	}
	tip := out.String()
	if strings.Contains(tip, admin) || strings.Contains(tip, enc) || strings.Contains(tip, relay) {
		t.Fatalf("migration output must not contain secrets: %q", tip)
	}
	if !strings.Contains(tip, "迁移完成") {
		t.Fatalf("want completion tip, got %q", tip)
	}
	hash, err := LoadAdminHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyAdminPassword(admin, hash) {
		t.Fatal("imported ADMIN_PASSWORD must verify against Argon2id hash")
	}
	doc, err := LoadPersistedFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if doc.RelayKey != relay {
		t.Fatalf("relay=%q", doc.RelayKey)
	}
	kr := keyring.Open(dir)
	_, master, err := kr.LoadActive()
	if err != nil {
		t.Fatal(err)
	}
	if master != enc {
		t.Fatal("ENCRYPTION_KEY must be preserved in keyring (SHA-256 decrypt path)")
	}
	// Cipher still decrypts with the same passphrase.
	c, err := store.NewCipher(enc)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := c.Encrypt("sk-upstream")
	if err != nil {
		t.Fatal(err)
	}
	pt, err := c.Decrypt(ct)
	if err != nil || pt != "sk-upstream" {
		t.Fatalf("legacy SHA-256 cipher broken: %v %q", err, pt)
	}
	if err := m.Run(); !errors.Is(err, ErrMigrationComplete) {
		t.Fatalf("second run err=%v", err)
	}
	hash2, _ := LoadAdminHash(dir)
	if hash2 != hash {
		t.Fatal("completed migration must not re-import / overwrite hash")
	}
}

func TestMigrationAmbiguousWithoutDB(t *testing.T) {
	dir := t.TempDir()
	m := &Migration{
		DataDir:   dir,
		EncKey:    "legacy-encryption-key-32bytes!!",
		AdminPW:   "legacy-admin-password",
		RelayKeys: []string{"rk-x"},
		Out:       ioDiscard{},
	}
	if err := m.Run(); !errors.Is(err, ErrMigrationAmbiguous) {
		t.Fatalf("err=%v", err)
	}
}

func TestMigrationAmbiguousWithoutEnv(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "db")
	_ = os.WriteFile(dbPath, []byte("x"), 0o600)
	m := &Migration{DataDir: dir, DBPath: dbPath, Out: ioDiscard{}}
	if err := m.Run(); !errors.Is(err, ErrMigrationAmbiguous) {
		t.Fatalf("err=%v", err)
	}
}

func TestMigrationRefusesAfterBootstrap(t *testing.T) {
	dir := t.TempDir()
	b := &Bootstrap{DataDir: dir, Out: ioDiscard{}}
	if _, err := b.Run(); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "db")
	_ = os.WriteFile(dbPath, []byte("x"), 0o600)
	m := &Migration{
		DataDir: dir, DBPath: dbPath,
		EncKey: "legacy-encryption-key-32bytes!!", AdminPW: "legacy-admin-password",
		RelayKeys: []string{"rk-x"}, Out: ioDiscard{},
	}
	if err := m.Run(); !errors.Is(err, ErrMigrationRefused) {
		t.Fatalf("err=%v", err)
	}
}

func TestMigrationCrashAfterImportedResumesWithoutRegen(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "db")
	_ = os.WriteFile(dbPath, []byte("x"), 0o600)
	admin := "legacy-admin-password"
	crash := &Migration{
		DataDir: dir, DBPath: dbPath,
		EncKey: "legacy-encryption-key-32bytes!!", AdminPW: admin,
		RelayKeys: []string{"rk-legacy"}, Out: ioDiscard{},
		CrashAfter: MigCrashAfterImported,
	}
	if err := crash.Run(); !errors.Is(err, errInjectedMigrationCrash) {
		t.Fatalf("err=%v", err)
	}
	phase, _ := crash.Phase()
	if phase != MigPhaseImported {
		t.Fatalf("phase=%q", phase)
	}
	hash1, err := LoadAdminHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	resume := &Migration{
		DataDir: dir, DBPath: dbPath,
		EncKey: "legacy-encryption-key-32bytes!!", AdminPW: admin,
		RelayKeys: []string{"rk-legacy"}, Out: ioDiscard{},
	}
	if err := resume.Run(); err != nil {
		t.Fatal(err)
	}
	hash2, _ := LoadAdminHash(dir)
	if hash1 != hash2 {
		t.Fatal("resume after imported must not regenerate hash")
	}
	if !VerifyAdminPassword(admin, hash2) {
		t.Fatal("hash must still match original ADMIN_PASSWORD")
	}
	ok, _ := resume.Completed()
	if !ok {
		t.Fatal("want completed")
	}
}

func TestResetAdminReplacesHashNeverPrintsOld(t *testing.T) {
	dir := t.TempDir()
	old := "original-admin-password"
	hash, err := HashAdminPassword(old)
	if err != nil {
		t.Fatal(err)
	}
	if err := WritePersisted(dir, Persisted{
		FormatVersion: 1, AdminPasswordHash: hash, RelayKey: "rk-keep", MasterKeyID: "kid",
	}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	newPW, err := ResetAdmin(dir, &out)
	if err != nil {
		t.Fatal(err)
	}
	if newPW == "" || newPW == old {
		t.Fatalf("new password empty or same as old")
	}
	if strings.Contains(out.String(), old) {
		t.Fatal("must not print old password")
	}
	if !strings.Contains(out.String(), "ADMIN_PASSWORD="+newPW) {
		t.Fatalf("stdout=%s", out.String())
	}
	newHash, err := LoadAdminHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyAdminPassword(old, newHash) {
		t.Fatal("old password must no longer verify")
	}
	if !VerifyAdminPassword(newPW, newHash) {
		t.Fatal("new password must verify")
	}
	doc, _ := LoadPersistedFile(dir)
	if doc.RelayKey != "rk-keep" {
		t.Fatal("reset-admin must preserve relay key")
	}
}

func TestResetAdminRequiresExistingHash(t *testing.T) {
	dir := t.TempDir()
	_, err := ResetAdmin(dir, ioDiscard{})
	if !errors.Is(err, ErrResetNoHash) {
		t.Fatalf("err=%v", err)
	}
}
