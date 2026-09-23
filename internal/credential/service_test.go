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
