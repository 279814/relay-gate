package acmeip

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeRenewer struct {
	supportErr, renewErr, validateErr error
	notAfter                          time.Time
	certIP                            string
	renewCalls                        int
}

func (f *fakeRenewer) RenewIP(ip string) (string, string, time.Time, error) {
	f.renewCalls++
	if f.renewErr != nil {
		return "", "", time.Time{}, f.renewErr
	}
	use := f.certIP
	if use == "" {
		use = ip
	}
	na := f.notAfter
	if na.IsZero() {
		na = time.Now().UTC().Add(160 * time.Hour)
	}
	return "CERT:" + use, "KEY:" + use, na, nil
}

func (f *fakeRenewer) Validate(certPEM, keyPEM, expectIP string) error {
	if f.validateErr != nil {
		return f.validateErr
	}
	if !strings.Contains(certPEM, expectIP) {
		return errors.New("SAN missing IP")
	}
	return nil
}

type fakeReload struct {
	err   error
	calls int
}

func (f *fakeReload) Reload() error {
	f.calls++
	return f.err
}

func TestRenewWatch_SuccessUpdatesObservability(t *testing.T) {
	fixed := time.Date(2026, 9, 23, 6, 0, 0, 0, time.UTC)
	notAfter := fixed.Add(160 * time.Hour)
	bot := &fakeRenewer{notAfter: notAfter}
	reload := &fakeReload{}
	w := NewRenewWatch(bot, reload, "203.0.113.50", DefaultLowValidity)
	w.SetClock(func() time.Time { return fixed })

	if err := w.TryRenew(); err != nil {
		t.Fatal(err)
	}
	snap := w.Snapshot()
	if bot.renewCalls != 1 || reload.calls != 1 {
		t.Fatalf("renew=%d reload=%d", bot.renewCalls, reload.calls)
	}
	if snap["renew_successes"] != 1 {
		t.Fatalf("successes=%v", snap["renew_successes"])
	}
	if snap["alert_low_validity"] != false {
		t.Fatalf("should not alert with 160h left: %+v", snap)
	}
	if snap["reload_failed_keep_old"] != false {
		t.Fatal("reload ok")
	}
	if snap["not_after"] != notAfter.UTC().Format(time.RFC3339) {
		t.Fatalf("not_after=%v", snap["not_after"])
	}
	rh, _ := snap["remaining_hours"].(float64)
	if rh < 159 || rh > 161 {
		t.Fatalf("remaining_hours=%v", rh)
	}
}

func TestRenewWatch_ReloadFailureKeepsOldAndAlerts(t *testing.T) {
	fixed := time.Date(2026, 9, 23, 6, 0, 0, 0, time.UTC)
	oldNotAfter := fixed.Add(100 * time.Hour)
	bot := &fakeRenewer{notAfter: fixed.Add(160 * time.Hour)}
	reload := &fakeReload{err: errors.New("nginx reload refused")}
	w := NewRenewWatch(bot, reload, "198.51.100.9", DefaultLowValidity)
	w.SetClock(func() time.Time { return fixed })
	w.ObserveCurrent(oldNotAfter)

	err := w.TryRenew()
	if err == nil || !strings.Contains(err.Error(), "保留旧证书") {
		t.Fatalf("err=%v", err)
	}
	snap := w.Snapshot()
	if snap["reload_failed_keep_old"] != true {
		t.Fatalf("want keep old: %+v", snap)
	}
	if snap["renew_successes"] != 0 {
		t.Fatalf("reload fail must not count success: %+v", snap)
	}
	// NotAfter must stay on the previous live cert (not the rejected new one).
	if snap["not_after"] != oldNotAfter.UTC().Format(time.RFC3339) {
		t.Fatalf("must keep old not_after, got %v", snap["not_after"])
	}
	if snap["last_error"] == "" {
		t.Fatal("expected last_error recorded")
	}
}

func TestRenewWatch_RenewFailureRecordsErrorKeepsService(t *testing.T) {
	fixed := time.Date(2026, 9, 23, 6, 0, 0, 0, time.UTC)
	liveUntil := fixed.Add(80 * time.Hour)
	bot := &fakeRenewer{renewErr: errors.New("acme rate limited")}
	w := NewRenewWatch(bot, &fakeReload{}, "203.0.113.7", DefaultLowValidity)
	w.SetClock(func() time.Time { return fixed })
	w.ObserveCurrent(liveUntil)

	err := w.TryRenew()
	if err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("err=%v", err)
	}
	snap := w.Snapshot()
	if snap["renew_successes"] != 0 {
		t.Fatal("no success")
	}
	if snap["not_after"] != liveUntil.UTC().Format(time.RFC3339) {
		t.Fatalf("live cert NotAfter must remain: %v", snap["not_after"])
	}
	if snap["reload_failed_keep_old"] != false {
		t.Fatal("reload not attempted as success path")
	}
}

func TestRenewWatch_LowValidityAlert(t *testing.T) {
	fixed := time.Date(2026, 9, 23, 6, 0, 0, 0, time.UTC)
	w := NewRenewWatch(&fakeRenewer{}, nil, "203.0.113.1", 48*time.Hour)
	w.SetClock(func() time.Time { return fixed })

	w.ObserveCurrent(fixed.Add(47 * time.Hour))
	if !w.Snapshot()["alert_low_validity"].(bool) {
		t.Fatal("expected low-validity alert under threshold")
	}

	w.ObserveCurrent(fixed.Add(49 * time.Hour))
	if w.Snapshot()["alert_low_validity"].(bool) {
		t.Fatal("49h remaining should clear alert at 48h threshold")
	}
}

func TestRenewWatch_ValidateFailureDoesNotReload(t *testing.T) {
	bot := &fakeRenewer{validateErr: errors.New("chain incomplete")}
	reload := &fakeReload{}
	w := NewRenewWatch(bot, reload, "203.0.113.2", 0)
	if err := w.TryRenew(); err == nil {
		t.Fatal("expected validate error")
	}
	if reload.calls != 0 {
		t.Fatalf("reload must not run after validate fail: %d", reload.calls)
	}
}
