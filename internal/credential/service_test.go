package credential

import (
	"errors"
	"testing"
	"time"
)

func TestRelayRotateGraceAndRevoke(t *testing.T) {
	s := New()
	s.SetActiveRelayKey("rk_old")
	newKey, grace, err := s.RotateRelayKey()
	if err != nil || newKey == "" || grace != 600 {
		t.Fatalf("new=%q grace=%d err=%v", newKey, grace, err)
	}
	if !s.ValidRelayKey("rk_old") || !s.ValidRelayKey(newKey) {
		t.Fatal("both keys should work during grace")
	}
	s.RevokeGrace()
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
	s.SetActiveRelayKey("rk_old")
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
	s.SetActiveRelayKeys([]string{"rk_a", "rk_b"})
	newKey, _, err := s.RotateRelayKey()
	if err != nil {
		t.Fatal(err)
	}
	if !s.ValidRelayKey(newKey) || !s.ValidRelayKey("rk_a") || !s.ValidRelayKey("rk_b") {
		t.Fatalf("new+old-grace+also should work; activeKeys=%v", s.ActiveRelayKeys())
	}
	s.RevokeGrace()
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
	s.SetActiveRelayKeys([]string{raw, "rk_also"})
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
