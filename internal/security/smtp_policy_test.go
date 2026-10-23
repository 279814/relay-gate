package security

import (
	"net/smtp"
	"strings"
	"testing"
	"time"
)

func smtpPolicyFixture(t *testing.T) MailConfig {
	t.Helper()
	cfg := MailConfig{Enabled: true, Host: "smtp.example.test", Port: 587, UseSTARTTLS: true,
		From: "relay@example.test", Recipients: []string{"ops@example.test"}, MinSeverity: SeverityInfo}
	cfg.AggregationWindowSec = 7
	cfg.RateLimitWindowSec = 13
	return cfg
}

func TestSMTPPolicyHasIndependentAggregationAndRateIntervals(t *testing.T) {
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	var sent []string
	mailer := NewAlertMailer().WithNowForTest(func() time.Time { return now }).WithSendForTest(func(_ string, _ smtp.Auth, _ string, _ []string, body []byte) error {
		sent = append(sent, string(body))
		return nil
	})
	mailer.SetConfig(smtpPolicyFixture(t))
	critical := Finding{Severity: SeverityCritical, Category: "credential_leak", Upstream: "site-a"}
	if err := mailer.MaybeNotify(critical, ""); err != nil {
		t.Fatal(err)
	}
	medium := Finding{Severity: SeverityMedium, Category: "prompt_injection", Upstream: "site-b"}
	if err := mailer.MaybeNotify(medium, ""); err != nil {
		t.Fatal(err)
	}
	now = now.Add(7 * time.Second)
	if err := mailer.MaybeNotify(critical, ""); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 2 || !strings.Contains(sent[1], "security digest") {
		t.Fatalf("7s digest was not independent of rate interval: deliveries=%d", len(sent))
	}
	now = now.Add(6 * time.Second)
	if err := mailer.MaybeNotify(critical, ""); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 3 || !strings.Contains(sent[2], "security alert") {
		t.Fatalf("13s critical interval not applied: deliveries=%d", len(sent))
	}
	if err := mailer.SendTest(""); err != nil {
		t.Fatal(err)
	}
	if err := mailer.SendTest(""); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 5 {
		t.Fatalf("explicit tests were incorrectly rate limited: %d", len(sent))
	}
}

func TestSMTPPolicyOwnsRecipientsSnapshot(t *testing.T) {
	cfg := smtpPolicyFixture(t)
	mailer := NewAlertMailer()
	mailer.SetConfig(cfg)
	cfg.Recipients[0] = "changed@example.test"
	read := mailer.Config()
	if read.Recipients[0] != "ops@example.test" {
		t.Fatal("installed configuration aliases caller's recipients")
	}
	read.Recipients[0] = "read-mutated@example.test"
	if mailer.Config().Recipients[0] != "ops@example.test" {
		t.Fatal("returned snapshot aliases runtime recipients")
	}
}

func TestSMTPReconfigurationChecksCurrentDueTimeAndMonotonicRevision(t *testing.T) {
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	deliveries := 0
	mailer := NewAlertMailer().WithNowForTest(func() time.Time { return now }).WithSendForTest(func(string, smtp.Auth, string, []string, []byte) error { deliveries++; return nil })
	cfg := smtpPolicyFixture(t)
	cfg.Revision = 2
	if err := mailer.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if err := mailer.MaybeNotify(Finding{Severity: SeverityMedium, Category: "prompt_injection", Upstream: "site"}, ""); err != nil {
		t.Fatal(err)
	}
	now = now.Add(6 * time.Second)
	cfg.AggregationWindowSec = 20
	cfg.Revision = 3
	if err := mailer.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}
	// A callback already queued for the retired 7s window must inspect the
	// current due time, just as the wall timer's callback does.
	now = now.Add(time.Second)
	mailer.mu.Lock()
	err := mailer.flushDigestIfDueLocked(now)
	mailer.mu.Unlock()
	if err != nil || deliveries != 0 {
		t.Fatalf("retired timer sent early: %d %v", deliveries, err)
	}
	stale := cfg
	stale.Revision = 2
	stale.AggregationWindowSec = 1
	if err := mailer.SetConfig(stale); err != nil {
		t.Fatal(err)
	}
	if mailer.Config().AggregationWindowSec != 20 {
		t.Fatal("slower reload replaced newer committed policy")
	}
	invalid := cfg
	invalid.RateLimitWindowSec = MaxSMTPWindowSec + 1
	if err := mailer.SetConfig(invalid); err == nil {
		t.Fatal("accepted invalid runtime policy")
	}
	if mailer.Config().RateLimitWindowSec != 13 {
		t.Fatal("invalid configuration changed runtime")
	}
	now = now.Add(13 * time.Second)
	mailer.mu.Lock()
	err = mailer.flushDigestIfDueLocked(now)
	mailer.mu.Unlock()
	if err != nil || deliveries != 1 {
		t.Fatalf("current deadline not delivered: %d %v", deliveries, err)
	}
	mailer.mu.Lock()
	err = mailer.flushDigestIfDueLocked(now)
	mailer.mu.Unlock()
	if err != nil || deliveries != 1 {
		t.Fatal("queued callback delivered duplicate digest")
	}
}
