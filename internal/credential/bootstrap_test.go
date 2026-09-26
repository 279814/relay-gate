package credential

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/keyring"
)

func TestHashAdminPasswordRoundTrip(t *testing.T) {
	hash, err := HashAdminPassword("test-admin-password")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("want PHC argon2id, got %q", hash)
	}
	if !VerifyAdminPassword("test-admin-password", hash) {
		t.Fatal("verify should succeed")
	}
	if VerifyAdminPassword("wrong-password!!", hash) {
		t.Fatal("verify should fail for wrong password")
	}
}

func TestBootstrapFreshDisplayOnce(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	b := &Bootstrap{DataDir: dir, Out: &out}
	d, err := b.Run()
	if err != nil {
		t.Fatal(err)
	}
	if d.AdminPassword == "" || d.RelayKey == "" || d.MasterKey == "" {
		t.Fatalf("empty credentials: %+v", d)
	}
	if !strings.HasPrefix(d.RelayKey, "rk-") {
		t.Fatalf("relay key prefix: %q", d.RelayKey)
	}
	if !strings.Contains(out.String(), "ADMIN_PASSWORD="+d.AdminPassword) {
		t.Fatalf("stdout missing admin: %s", out.String())
	}
	phase, err := b.Phase()
	if err != nil || phase != PhaseDisplayed {
		t.Fatalf("phase=%q err=%v", phase, err)
	}
	persisted, err := b.LoadPersisted()
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyAdminPassword(d.AdminPassword, persisted.AdminPasswordHash) {
		t.Fatal("persisted hash must match displayed admin password")
	}
	if persisted.RelayKey != d.RelayKey {
		t.Fatal("persisted relay mismatch")
	}
	_, err = b.Run()
	if !errors.Is(err, ErrBootstrapComplete) {
		t.Fatalf("second run err=%v", err)
	}
}

func TestBootstrapCrashAfterPersistedRegeneratesAdminRelayKeepsMaster(t *testing.T) {
	dir := t.TempDir()
	crash := &Bootstrap{DataDir: dir, Out: ioDiscard{}, CrashAfter: CrashAfterCredentialsPersisted}
	_, err := crash.Run()
	if !errors.Is(err, errInjectedCrash) {
		t.Fatalf("want injected crash, got %v", err)
	}
	phase, err := crash.Phase()
	if err != nil || phase != PhaseCredentialsPersisted {
		t.Fatalf("phase=%q err=%v", phase, err)
	}
	kr := keyring.Open(dir)
	keyID1, master1, err := kr.LoadActive()
	if err != nil {
		t.Fatal(err)
	}
	raw1, err := os.ReadFile(crash.credentialsPath())
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	resume := &Bootstrap{DataDir: dir, Out: &out}
	d, err := resume.Run()
	if err != nil {
		t.Fatal(err)
	}
	keyID2, master2, err := kr.LoadActive()
	if err != nil {
		t.Fatal(err)
	}
	if keyID1 != keyID2 || master1 != master2 || d.MasterKey != master1 {
		t.Fatalf("master must be kept: %q/%q vs %q/%q displayed=%q",
			keyID1, master1, keyID2, master2, d.MasterKey)
	}
	raw2, err := os.ReadFile(resume.credentialsPath())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(raw1, raw2) {
		t.Fatal("undelivered admin/relay must be regenerated (credentials file unchanged)")
	}
	if !VerifyAdminPassword(d.AdminPassword, mustLoadHash(t, resume)) {
		t.Fatal("new admin must match new hash")
	}
	if resumePhase, _ := resume.Phase(); resumePhase != PhaseDisplayed {
		t.Fatalf("phase=%q", resumePhase)
	}
}

func TestBootstrapCrashAfterPreparedCanComplete(t *testing.T) {
	dir := t.TempDir()
	crash := &Bootstrap{DataDir: dir, Out: ioDiscard{}, CrashAfter: CrashAfterPrepared}
	_, err := crash.Run()
	if !errors.Is(err, errInjectedCrash) {
		t.Fatalf("want injected crash, got %v", err)
	}
	phase, _ := crash.Phase()
	if phase != PhasePrepared {
		t.Fatalf("phase=%q", phase)
	}
	var out bytes.Buffer
	b := &Bootstrap{DataDir: dir, Out: &out}
	d, err := b.Run()
	if err != nil {
		t.Fatal(err)
	}
	if d.MasterKey == "" {
		t.Fatal("expected master")
	}
	if p, _ := b.Phase(); p != PhaseDisplayed {
		t.Fatalf("phase=%q", p)
	}
}

func TestBootstrapLockFileExclusive(t *testing.T) {
	dir := t.TempDir()
	b1 := &Bootstrap{DataDir: dir}
	unlock, err := b1.acquireLock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	b2 := &Bootstrap{DataDir: dir}
	_, err = b2.acquireLock()
	if err == nil {
		t.Fatal("second lock should fail")
	}
}

func mustLoadHash(t *testing.T, b *Bootstrap) string {
	t.Helper()
	doc, err := b.LoadPersisted()
	if err != nil {
		t.Fatal(err)
	}
	return doc.AdminPasswordHash
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }

func TestBootstrapSecretsDirPermissions(t *testing.T) {
	dir := t.TempDir()
	b := &Bootstrap{DataDir: dir, Out: ioDiscard{}}
	if _, err := b.Run(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		// On Windows permission bits are approximate; only soft-check unix.
		if filepath.Separator == '/' {
			t.Fatalf("secrets dir should be 0700, got %v", info.Mode())
		}
	}
}

func TestWriteJSON0600SyncsDirectoryAfterRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	called := false
	prev := syncDirAfterJSONRename
	syncDirAfterJSONRename = func(p string) error {
		called = true
		if p != dir {
			t.Fatalf("sync dir want %q got %q", dir, p)
		}
		return prev(p)
	}
	defer func() { syncDirAfterJSONRename = prev }()

	if err := writeJSON0600(path, map[string]any{"format_version": 1}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("writeJSON0600 must fsync the parent directory after rename")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"format_version"`)) {
		t.Fatalf("expected JSON written, got %q", raw)
	}
}

func TestWritePersistedRoundTripAndFailedWriteLeavesBytes(t *testing.T) {
	dir := t.TempDir()
	first := Persisted{
		FormatVersion:     1,
		AdminPasswordHash: "$argon2id$v=19$m=65536,t=1,p=4$aaaaaaaaaaaaaaaaaaaaaa$bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		RelayKey:          "rk-roundtrip-relay-key-value",
		MasterKeyID:       "mkid-roundtrip-01",
		UpdatedAt:         "2026-01-01T00:00:00Z",
	}
	if err := WritePersisted(dir, first); err != nil {
		t.Fatal(err)
	}
	got, err := LoadPersistedFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.AdminPasswordHash != first.AdminPasswordHash ||
		got.RelayKey != first.RelayKey ||
		got.MasterKeyID != first.MasterKeyID {
		t.Fatalf("successful write must round-trip three values: got %+v want %+v", got, first)
	}
	before, err := os.ReadFile(CredentialsFile(dir))
	if err != nil {
		t.Fatal(err)
	}

	// Non-empty directory at path.tmp makes writeSyncedFile fail before rename;
	// an existing secrets file must stay byte-identical.
	tmp := CredentialsFile(dir) + ".tmp"
	if err := os.MkdirAll(filepath.Join(tmp, "blocker"), 0o700); err != nil {
		t.Fatal(err)
	}
	err = WritePersisted(dir, Persisted{
		FormatVersion:     1,
		AdminPasswordHash: "$argon2id$v=19$m=65536,t=1,p=4$cccccccccccccccccccccc$ddddddddddddddddddddddddddddddddddddddddddd",
		RelayKey:          "rk-should-not-replace",
		MasterKeyID:       "mkid-should-not-replace",
	})
	if err == nil {
		t.Fatal("expected write failure")
	}
	after, err := os.ReadFile(CredentialsFile(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("failed write must leave existing secrets file bytes unchanged")
	}
	still, err := LoadPersistedFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if still.AdminPasswordHash != first.AdminPasswordHash ||
		still.RelayKey != first.RelayKey ||
		still.MasterKeyID != first.MasterKeyID {
		t.Fatalf("after failed write got %+v want %+v", still, first)
	}
}
