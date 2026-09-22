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
