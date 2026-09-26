package credential

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/keyring"
	"github.com/279814/relay-gate/internal/store"
)

func TestRelayRotateGraceAndRevoke(t *testing.T) {
	s := New()
	if err := s.SetActiveRelayKey("rk_old"); err != nil {
		t.Fatal(err)
	}
	newKey, grace, err := s.RotateRelayKey()
	if err != nil || newKey == "" || grace != 600 {
		t.Fatalf("new=%q grace=%d err=%v", newKey, grace, err)
	}
	if !s.ValidRelayKey("rk_old") || !s.ValidRelayKey(newKey) {
		t.Fatal("both keys should work during grace")
	}
	if err := s.RevokeGrace(); err != nil {
		t.Fatal(err)
	}
	if s.ValidRelayKey("rk_old") {
		t.Fatal("old should be revoked")
	}
	if !s.ValidRelayKey(newKey) {
		t.Fatal("new should remain")
	}
}

func TestRelayGraceExpiry(t *testing.T) {
	s := New()
	now := time.Now()
	s.WithNow(func() time.Time { return now })
	if err := s.SetActiveRelayKey("rk_old"); err != nil {
		t.Fatal(err)
	}
	newKey, _, err := s.RotateRelayKey()
	if err != nil {
		t.Fatal(err)
	}
	if !s.ValidRelayKey("rk_old") {
		t.Fatal("old should work during grace")
	}
	now = now.Add(10*time.Minute + time.Second)
	if s.ValidRelayKey("rk_old") {
		t.Fatal("old should be rejected after grace expiry")
	}
	if !s.ValidRelayKey(newKey) {
		t.Fatal("new should remain after grace expiry")
	}
}

func TestRelayAlsoKeysSurviveRotate(t *testing.T) {
	s := New()
	if err := s.SetActiveRelayKeys([]string{"rk_a", "rk_b"}); err != nil {
		t.Fatal(err)
	}
	newKey, _, err := s.RotateRelayKey()
	if err != nil {
		t.Fatal(err)
	}
	if !s.ValidRelayKey(newKey) || !s.ValidRelayKey("rk_a") || !s.ValidRelayKey("rk_b") {
		t.Fatalf("new+old-grace+also should work; activeKeys=%v", s.ActiveRelayKeys())
	}
	if err := s.RevokeGrace(); err != nil {
		t.Fatal(err)
	}
	if s.ValidRelayKey("rk_a") {
		t.Fatal("rotated-away primary must not survive revoke")
	}
	if !s.ValidRelayKey("rk_b") || !s.ValidRelayKey(newKey) {
		t.Fatal("also-key and new active must remain")
	}
}

// TestRelayDigestSnapshotAuth covers §6.1 / §12.6: hot-path snapshot holds
// irreversible digests (not raw keys); right/grace accepted; wrong/empty and
// unconfigured snapshots rejected.
func TestRelayDigestSnapshotAuth(t *testing.T) {
	empty := New()
	if empty.ValidRelayKey("rk_anything") || empty.ValidRelayKey("") {
		t.Fatal("unconfigured snapshot must reject all keys including empty")
	}

	const raw = "rk_digest_primary"
	s := New()
	if err := s.SetActiveRelayKeys([]string{raw, "rk_also"}); err != nil {
		t.Fatal(err)
	}
	if !s.ValidRelayKey(raw) {
		t.Fatal("correct key must be accepted")
	}
	if !s.ValidRelayKey("rk_also") {
		t.Fatal("also-key must be accepted")
	}
	if s.ValidRelayKey("rk_wrong") || s.ValidRelayKey("") {
		t.Fatal("wrong and empty keys must be rejected")
	}
	for _, snap := range s.ActiveRelayKeys() {
		if snap == raw || snap == "rk_also" {
			t.Fatalf("snapshot must not store raw key; got %q", snap)
		}
		if snap != digestRelayKey(raw) && snap != digestRelayKey("rk_also") {
			t.Fatalf("unexpected snapshot digest %q", snap)
		}
	}

	newKey, _, err := s.RotateRelayKey()
	if err != nil {
		t.Fatal(err)
	}
	if !s.ValidRelayKey(raw) {
		t.Fatal("grace key must be accepted during overlap")
	}
	if !s.ValidRelayKey(newKey) {
		t.Fatal("rotated active key must be accepted")
	}
	for _, snap := range s.ActiveRelayKeys() {
		if snap == raw || snap == newKey || snap == "rk_also" {
			t.Fatalf("snapshot must not equal raw key after rotate; got %q", snap)
		}
	}
}

func TestMasterRevealWindow(t *testing.T) {
	s := New()
	now := time.Now()
	s.now = func() time.Time { return now }
	s.BeginMasterReveal("master-secret", time.Second)
	got, err := s.TakeMasterReveal()
	if err != nil || got != "master-secret" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	now = now.Add(2 * time.Second)
	if _, err := s.TakeMasterReveal(); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("err=%v", err)
	}
}

type memEnvelope struct {
	plain string
}

func (m *memEnvelope) EncryptEnvelope(plain string) (string, error) {
	m.plain = plain
	return "v1:test:" + plain, nil
}

func (m *memEnvelope) DecryptEnvelope(encoded string) (string, error) {
	const p = "v1:test:"
	if !strings.HasPrefix(encoded, p) {
		return "", errors.New("bad envelope")
	}
	return strings.TrimPrefix(encoded, p), nil
}

func TestRevealActiveRelayKey_SealedBesideDigest(t *testing.T) {
	env := &memEnvelope{}
	s := New().WithEnvelope(env)
	const raw = "rk_sealed_primary"
	if err := s.SetActiveRelayKey(raw); err != nil {
		t.Fatal(err)
	}
	if env.plain != raw {
		t.Fatalf("envelope seal want %q got %q", raw, env.plain)
	}
	st := s.Status()
	rawJSON, _ := json.Marshal(st)
	if strings.Contains(string(rawJSON), raw) || strings.Contains(string(rawJSON), "v1:test:") {
		t.Fatalf("Status must not leak key or ciphertext: %s", rawJSON)
	}
	got, err := s.RevealActiveRelayKey()
	if err != nil || got != raw {
		t.Fatalf("reveal=%q err=%v", got, err)
	}
	if !s.ValidRelayKey(got) {
		t.Fatal("revealed key must still authorize")
	}
	newKey, _, err := s.RotateRelayKey()
	if err != nil {
		t.Fatal(err)
	}
	got2, err := s.RevealActiveRelayKey()
	if err != nil || got2 != newKey {
		t.Fatalf("after rotate reveal=%q want %q err=%v", got2, newKey, err)
	}
	if !s.ValidRelayKey(got2) {
		t.Fatal("rotated revealed key must authorize")
	}
}

// TestRelayGraceSurvivesRestart covers §12.6: unexpired grace digest/deadline
// persist in bootstrap-credentials.json and reload after SetActiveRelayKeys
// (startup clears the in-memory snapshot).
func TestRelayGraceSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	const oldKey = "rk_grace_restart_old"
	env := &memEnvelope{}
	if err := WritePersisted(dir, Persisted{
		FormatVersion: 1, AdminPasswordHash: "hash", RelayKey: oldKey, MasterKeyID: "kid",
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	s1 := New().WithEnvelope(env).WithDataDir(dir).WithNow(func() time.Time { return now })
	if err := s1.SetActiveRelayKey(oldKey); err != nil {
		t.Fatal(err)
	}
	newKey, _, err := s1.RotateRelayKey()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := LoadPersistedFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	gotActive, err := OpenPersistedRelayKey(doc.RelayKey, env)
	if err != nil || gotActive != newKey {
		t.Fatalf("persisted active open=%q want %q err=%v", gotActive, newKey, err)
	}
	if !IsRelayKeyEnvelope(doc.RelayKey) {
		t.Fatal("rotate must persist envelope, not plaintext")
	}
	if doc.RelayGraceDigest != digestRelayKey(oldKey) {
		t.Fatalf("persisted grace digest=%q", doc.RelayGraceDigest)
	}
	if doc.RelayGraceUntil == "" {
		t.Fatal("persisted grace deadline missing")
	}
	if strings.Contains(doc.RelayGraceDigest, oldKey) || doc.RelayGraceDigest == oldKey {
		t.Fatal("must not persist raw previous key")
	}

	// Simulate process restart: SetActiveRelayKeys clears grace; restore reloads it.
	s2 := New().WithEnvelope(env).WithDataDir(dir).WithNow(func() time.Time { return now.Add(2 * time.Minute) })
	if err := s2.SetActiveRelayKeys([]string{gotActive}); err != nil {
		t.Fatal(err)
	}
	if s2.ValidRelayKey(oldKey) {
		t.Fatal("without RestorePersistedGrace, previous key must die after reload")
	}
	if err := s2.RestorePersistedGrace(dir); err != nil {
		t.Fatal(err)
	}
	if !s2.ValidRelayKey(newKey) {
		t.Fatal("current key must work after reload")
	}
	if !s2.ValidRelayKey(oldKey) {
		t.Fatal("unexpired grace key must work after reload")
	}

	// Deadline already passed stays rejected.
	s3 := New().WithEnvelope(env).WithDataDir(dir).WithNow(func() time.Time { return now.Add(11 * time.Minute) })
	if err := s3.SetActiveRelayKeys([]string{gotActive}); err != nil {
		t.Fatal(err)
	}
	if err := s3.RestorePersistedGrace(dir); err != nil {
		t.Fatal(err)
	}
	if s3.ValidRelayKey(oldKey) {
		t.Fatal("expired grace must stay rejected after reload")
	}
	if !s3.ValidRelayKey(newKey) {
		t.Fatal("current key must remain after expired grace reload")
	}

	// Revoke before restart stays revoked after restart.
	s4 := New().WithEnvelope(env).WithDataDir(dir).WithNow(func() time.Time { return now.Add(3 * time.Minute) })
	if err := s4.SetActiveRelayKeys([]string{gotActive}); err != nil {
		t.Fatal(err)
	}
	if err := s4.RestorePersistedGrace(dir); err != nil {
		t.Fatal(err)
	}
	if err := s4.RevokeGrace(); err != nil {
		t.Fatal(err)
	}
	afterRevoke, err := LoadPersistedFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if afterRevoke.RelayGraceDigest != "" || afterRevoke.RelayGraceUntil != "" {
		t.Fatal("revoke must clear persisted grace fields")
	}
	activeAfter, err := OpenPersistedRelayKey(afterRevoke.RelayKey, env)
	if err != nil {
		t.Fatal(err)
	}
	s5 := New().WithEnvelope(env).WithDataDir(dir).WithNow(func() time.Time { return now.Add(4 * time.Minute) })
	if err := s5.SetActiveRelayKeys([]string{activeAfter}); err != nil {
		t.Fatal(err)
	}
	if err := s5.RestorePersistedGrace(dir); err != nil {
		t.Fatal(err)
	}
	if s5.ValidRelayKey(oldKey) {
		t.Fatal("revoked grace must stay revoked after restart")
	}
	if !s5.ValidRelayKey(newKey) {
		t.Fatal("active key must remain after revoke restart")
	}
}

// TestResealActiveRelayUnder_BeforeActivateSurvivesRecovery pins §12.7: the
// persisted Relay Key must be resealed under pending before ActivatePending
// drops the old active key. Crash at db_committed + RecoverUnfinished must
// still open bootstrap-credentials.json with only the new master.
func TestResealActiveRelayUnder_BeforeActivateSurvivesRecovery(t *testing.T) {
	const (
		oldMaster = "old-master-relay-reseal-aaa"
		newMaster = "new-master-relay-reseal-bbb"
		rawRelay  = "rk_fixture_master_rot_relay_32"
	)
	dir := t.TempDir()
	oldCipher, err := store.NewCipher(oldMaster)
	if err != nil {
		t.Fatal(err)
	}
	sealedOld, err := oldCipher.EncryptEnvelope(rawRelay)
	if err != nil {
		t.Fatal(err)
	}
	if err := WritePersisted(dir, Persisted{
		FormatVersion: 1, AdminPasswordHash: "hash", MasterKeyID: "mk_old",
		RelayKey: sealedOld,
	}); err != nil {
		t.Fatal(err)
	}
	creds := New().WithEnvelope(oldCipher).WithDataDir(dir)
	if err := creds.SetActiveRelayKey(rawRelay); err != nil {
		t.Fatal(err)
	}
	doc, err := LoadPersistedFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !IsRelayKeyEnvelope(doc.RelayKey) {
		t.Fatal("setup: want sealed relay_key")
	}
	// Old master alone opens; new master alone must not (precondition).
	if got, err := OpenPersistedRelayKey(doc.RelayKey, oldCipher); err != nil || got != rawRelay {
		t.Fatalf("old open=%q err=%v", got, err)
	}
	newOnly, err := store.NewCipher(newMaster)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPersistedRelayKey(doc.RelayKey, newOnly); err == nil {
		t.Fatal("precondition: new master must not open old envelope")
	}

	kr := keyring.Open(filepath.Join(dir, "kr"))
	if err := kr.EnsureInitialized("mk_old", oldMaster); err != nil {
		t.Fatal(err)
	}
	rid, err := kr.BeginRotation(newMaster)
	if err != nil {
		t.Fatal(err)
	}
	// §12.7 step 7 order: reseal under pending while old active still present.
	if err := creds.ResealActiveRelayUnder(func(plain string) (string, error) {
		return store.SealEnvelopeUnder(newMaster, plain)
	}); err != nil {
		t.Fatal(err)
	}
	if err := kr.MarkDBCommitted(rid); err != nil {
		t.Fatal(err)
	}
	// Crash window: db_committed, then RecoverUnfinished → ActivatePending
	// drops old active. Persisted relay must already be under new.
	hold, st, err := kr.RecoverUnfinished()
	if err != nil {
		t.Fatal(err)
	}
	if hold {
		t.Fatalf("recovery hold=%v status=%+v", hold, st)
	}
	if st.Phase != keyring.PhaseKeyActivated {
		t.Fatalf("db_committed recovery must activate forward, phase=%q", st.Phase)
	}
	kid, active, err := kr.LoadActive()
	if err != nil {
		t.Fatal(err)
	}
	if active != newMaster {
		t.Fatalf("active after recovery must be new master (kid=%s)", kid)
	}

	restartCipher, err := store.NewCipher(newMaster)
	if err != nil {
		t.Fatal(err)
	}
	after, err := LoadPersistedFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenPersistedRelayKey(after.RelayKey, restartCipher)
	if err != nil {
		t.Fatalf("new master alone must open resealed relay: %v", err)
	}
	if got != rawRelay {
		t.Fatalf("relay after recovery=%q want %q", got, rawRelay)
	}
	if strings.Contains(after.RelayKey, rawRelay) {
		t.Fatal("must not persist relay plaintext")
	}
}

// TestRotateRelayKey_PersistsEnvelopeNotPlaintext is the focused §2.4 writer
// check: ReplaceRelayRotation via RotateRelayKey must seal relay_key under the
// Master Key and keep dual-read of legacy plaintext on load.
func TestRotateRelayKey_PersistsEnvelopeNotPlaintext(t *testing.T) {
	dir := t.TempDir()
	const legacy = "rk_legacy_plain_on_disk"
	if err := WritePersisted(dir, Persisted{
		FormatVersion: 1, AdminPasswordHash: "hash", RelayKey: legacy, MasterKeyID: "kid",
	}); err != nil {
		t.Fatal(err)
	}
	// Dual-read: legacy plaintext field still opens without decrypt.
	gotLegacy, err := OpenPersistedRelayKey(legacy, nil)
	if err != nil || gotLegacy != legacy {
		t.Fatalf("legacy dual-read=%q err=%v", gotLegacy, err)
	}

	c, err := store.NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	s := New().WithEnvelope(c).WithDataDir(dir)
	if err := s.SetActiveRelayKey(legacy); err != nil {
		t.Fatal(err)
	}
	newKey, _, err := s.RotateRelayKey()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := LoadPersistedFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !IsRelayKeyEnvelope(doc.RelayKey) {
		t.Fatalf("want v1 envelope, got %q", doc.RelayKey)
	}
	if strings.Contains(doc.RelayKey, newKey) || strings.Contains(doc.RelayKey, legacy) {
		t.Fatal("recoverable plaintext must not remain in relay_key")
	}
	opened, err := OpenPersistedRelayKey(doc.RelayKey, c)
	if err != nil || opened != newKey {
		t.Fatalf("open=%q want %q err=%v", opened, newKey, err)
	}
	raw, err := os.ReadFile(CredentialsFile(dir))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), newKey) || strings.Contains(string(raw), legacy) {
		t.Fatal("credentials file must not contain relay plaintext after rotate")
	}
}
