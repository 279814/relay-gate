package security

import (
	"errors"
	"fmt"
	"net/smtp"
	"testing"
	"time"
)

func TestAlertFailureDoesNotConsumeSuccessfulRateWindow(t *testing.T) {
	attempts := 0
	m := NewAlertMailer().WithNowForTest(func() time.Time { return time.Unix(100, 0) }).WithSendForTest(func(string, smtp.Auth, string, []string, []byte) error {
		attempts++
		if attempts == 1 {
			return errors.New("transport failed")
		}
		return nil
	})
	if err := m.SetConfig(smtpPolicyFixture(t)); err != nil {
		t.Fatal(err)
	}
	f := Finding{Severity: SeverityCritical, RuleID: "custom:a", UpstreamID: 1, RouteID: 1}
	if err := m.MaybeNotify(f, ""); err == nil {
		t.Fatal("missing delivery failure")
	}
	if err := m.MaybeNotify(f, ""); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("failed delivery consumed rate window: attempts=%d", attempts)
	}
}

func TestAlertRuleRouteAndUpstreamIdentityIsIndependent(t *testing.T) {
	attempts := 0
	m := NewAlertMailer().WithNowForTest(func() time.Time { return time.Unix(100, 0) }).WithSendForTest(func(string, smtp.Auth, string, []string, []byte) error { attempts++; return nil })
	m.SetConfig(smtpPolicyFixture(t))
	for _, f := range []Finding{
		{RuleID: "custom:a", UpstreamID: 1, RouteID: 1}, {RuleID: "custom:b", UpstreamID: 1, RouteID: 1}, {RuleID: "custom:a", UpstreamID: 2, RouteID: 1}, {RuleID: "custom:a", UpstreamID: 1, RouteID: 2},
	} {
		f.Severity = SeverityCritical
		f.Category = "prompt_injection"
		f.Upstream = "same-label"
		if err := m.MaybeNotify(f, ""); err != nil {
			t.Fatal(err)
		}
	}
	if attempts != 4 {
		t.Fatalf("distinct captured identities were suppressed: %d", attempts)
	}
}

func TestAlertStateIsBounded(t *testing.T) {
	m := NewAlertMailer().WithNowForTest(func() time.Time { return time.Unix(100, 0) }).WithSendForTest(func(string, smtp.Auth, string, []string, []byte) error { return nil })
	m.SetConfig(smtpPolicyFixture(t))
	for i := 0; i < 1100; i++ {
		_ = m.MaybeNotify(Finding{Severity: SeverityMedium, Category: fmt.Sprint(i)}, "")
	}
	if len(m.pending) > 1024 {
		t.Fatalf("unbounded pending=%d", len(m.pending))
	}
}

func TestAlertIgnoreRechecksPendingAndKeepsFailuresOutsideLock(t *testing.T) {
	now := time.Unix(100, 0)
	deliveries := 0
	blocked := false
	fail := false
	m := NewAlertMailer().WithNowForTest(func() time.Time { return now }).WithSendForTest(func(string, smtp.Auth, string, []string, []byte) error { deliveries++; return nil })
	m.SetConfig(smtpPolicyFixture(t))
	m.SetIgnorePolicy(func(f Finding, _ int64) (bool, error) {
		_ = m.Config()
		if fail {
			return false, errors.New("private driver detail")
		}
		return blocked && f.RuleID == "custom:a", nil
	})
	a := Finding{RuleID: "custom:a", UpstreamID: 1, RouteID: 1, Severity: SeverityMedium, Category: "same"}
	b := a
	b.RuleID = "custom:b"
	m.MaybeNotify(a, "")
	m.MaybeNotify(b, "")
	blocked = true
	fail = true
	if err := m.FlushDigest(); err == nil || err.Error() == "private driver detail" {
		t.Fatalf("policy error not finite: %v", err)
	}
	if deliveries != 0 || len(m.pending) != 2 || len(m.lastAt) != 2 || m.Status().PolicyFailures != 1 {
		t.Fatal("policy failure consumed pending or fabricated delivery")
	}
	fail = false
	if err := m.FlushDigest(); err != nil {
		t.Fatal(err)
	}
	if deliveries != 1 || len(m.pending) != 0 || m.Status().Suppressed != 1 {
		t.Fatal("pending ignore was not re-evaluated separately by rule")
	}
	if err := m.SendTest(""); err != nil {
		t.Fatal(err)
	}
	if err := m.SendTest(""); err != nil {
		t.Fatal(err)
	}
	if deliveries != 3 {
		t.Fatal("explicit test did not deliver every call")
	}
	now = now.Add(14 * time.Second)
	blocked = false
	if err := m.MaybeNotify(a, ""); err != nil {
		t.Fatal(err)
	}
	if err := m.FlushDigest(); err != nil {
		t.Fatal(err)
	}
	if deliveries != 4 {
		t.Fatal("expired ignore suppressed future findings")
	}
}

func TestAlertDigestFailureRetainsPendingAndConcurrentFlushSendsOnce(t *testing.T) {
	now := time.Unix(100, 0)
	entered := make(chan struct{})
	release := make(chan struct{})
	attempts := 0
	m := NewAlertMailer().WithNowForTest(func() time.Time { return now }).WithSendForTest(func(string, smtp.Auth, string, []string, []byte) error {
		attempts++
		if attempts == 1 {
			return errors.New("delivery failed")
		}
		close(entered)
		<-release
		return nil
	})
	m.SetConfig(smtpPolicyFixture(t))
	f := Finding{Severity: SeverityMedium, Category: "x"}
	m.MaybeNotify(f, "")
	if err := m.FlushDigest(); err == nil || len(m.pending) != 1 || !m.lastAt[findingKey(f)].IsZero() {
		t.Fatal("failed digest falsely committed rate or discarded items")
	}
	done := make(chan error, 1)
	go func() { done <- m.FlushDigest() }()
	<-entered
	if err := m.FlushDigest(); err != nil {
		t.Fatal(err)
	}
	if err := m.MaybeNotify(f, ""); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || len(m.pending) != 1 || m.pending[findingKey(f)].count != 1 {
		t.Fatal("inflight digest duplicated delivery or lost later arrival")
	}
}

func TestAlertDigestAndImmediateShareOneInflightIdentity(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	deliveries := 0
	m := NewAlertMailer().WithNowForTest(func() time.Time { return time.Unix(100, 0) }).WithSendForTest(func(string, smtp.Auth, string, []string, []byte) error {
		deliveries++
		if deliveries == 1 {
			close(entered)
			<-release
		}
		return nil
	})
	m.SetConfig(smtpPolicyFixture(t))
	f := Finding{Severity: SeverityMedium, RuleID: "custom:a", UpstreamID: 1, RouteID: 1}
	m.MaybeNotify(f, "")
	done := make(chan error, 1)
	go func() { done <- m.FlushDigest() }()
	<-entered
	f.Severity = SeverityCritical
	if err := m.MaybeNotify(f, ""); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if deliveries != 1 {
		t.Fatalf("same in-flight identity delivered twice: %d", deliveries)
	}
}
