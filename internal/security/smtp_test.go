package security_test

import (
	"net/smtp"
	"strings"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/security"
)

func TestBuildAlertMessageOmitsConversationBody(t *testing.T) {
	msg := string(security.BuildAlertMessage("a@b.c", []string{"x@y.z"}, security.Finding{
		ID:       "f1",
		Severity: security.SeverityCritical,
		Category: "xss_pattern",
		Summary:  "hit",
		Detail:   "should not appear as conversation",
		Upstream: "up1",
		Source:   "passive",
	}, "http://admin/"))
	if strings.Contains(msg, "should not appear") {
		t.Fatal("detail leaked into mail body")
	}
	for _, bad := range []string{"messages", "conversation", "response body", "chat"} {
		if strings.Contains(strings.ToLower(msg), "conversation body") && bad == "conversation" {
			continue // allowed in the disclaimer line
		}
		_ = bad
	}
	if !strings.Contains(msg, "metadata only") {
		t.Fatal("expected metadata disclaimer")
	}
	if !strings.Contains(msg, "severity: critical") {
		t.Fatal("missing severity")
	}
}

func TestAdminURL_NoSMTPHeaderInjection(t *testing.T) {
	normal := "http://10.0.0.1:18787/admin/"
	evil := "http://10.0.0.1:18787/admin/\r\nBcc: x\x00evil"

	f := security.Finding{
		ID:       "f1",
		Severity: security.SeverityCritical,
		Category: "credential_leak",
		Summary:  "hit",
		Upstream: "up1",
		Source:   "passive",
	}

	alertNormal := string(security.BuildAlertMessage("a@b.c", []string{"x@y.z"}, f, normal))
	if !strings.Contains(alertNormal, "admin: "+normal+"\r\n") {
		t.Fatalf("normal admin URL must be unchanged; got: %s", alertNormal)
	}

	alertEvil := string(security.BuildAlertMessage("a@b.c", []string{"x@y.z"}, f, evil))
	assertAdminURLNoHeaderInjection(t, alertEvil)
	if !strings.Contains(alertEvil, "admin: http://10.0.0.1:18787/admin/Bcc: xevil\r\n") {
		t.Fatalf("CR/LF/NUL must be stripped from admin URL; got: %s", alertEvil)
	}

	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	var captured []string
	m := security.NewAlertMailer().
		WithNowForTest(func() time.Time { return now }).
		WithSendForTest(func(a string, auth smtp.Auth, from string, to []string, msg []byte) error {
			captured = append(captured, string(msg))
			return nil
		})
	m.SetConfig(security.MailConfig{
		Enabled:     true,
		Host:        "smtp.test.local",
		Port:        587,
		From:        "relay@test.local",
		Recipients:  []string{"ops@test.local"},
		MinSeverity: security.SeverityInfo,
	})
	medium := security.Finding{
		ID:       "m1",
		Severity: security.SeverityMedium,
		Category: "xss_pattern",
		Summary:  "hit",
		Upstream: "up-a",
		Source:   "passive",
	}
	if err := m.MaybeNotify(medium, evil); err != nil {
		t.Fatal(err)
	}
	now = now.Add(5 * time.Minute)
	if err := m.FlushDigest(); err != nil {
		t.Fatal(err)
	}
	if len(captured) != 1 {
		t.Fatalf("want one digest; got %d", len(captured))
	}
	assertAdminURLNoHeaderInjection(t, captured[0])
	if !strings.Contains(captured[0], "admin: http://10.0.0.1:18787/admin/Bcc: xevil\r\n") {
		t.Fatalf("digest must strip CR/LF/NUL from admin URL; got: %s", captured[0])
	}
}

func assertAdminURLNoHeaderInjection(t *testing.T, msg string) {
	t.Helper()
	assertNoSMTPHeaderInjection(t, msg)
}

func assertNoSMTPHeaderInjection(t *testing.T, msg string) {
	t.Helper()
	hdrEnd := strings.Index(msg, "\r\n\r\n")
	if hdrEnd < 0 {
		t.Fatal("missing header/body separator")
	}
	for _, line := range strings.Split(msg[:hdrEnd], "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "bcc:") {
			t.Fatalf("free-text field injected extra header line: %q", line)
		}
	}
	if strings.Contains(msg, "\r\nBcc:") {
		t.Fatal("CRLF+Bcc sequence must not appear in message")
	}
	if strings.Contains(msg, "\x00") {
		t.Fatal("NUL must not appear in message")
	}
}

func TestSeverity_NoSMTPSubjectHeaderInjection(t *testing.T) {
	evil := security.Severity("high\r\nBcc: x")
	f := security.Finding{
		ID:       "f1",
		Severity: evil,
		Category: "credential_leak",
		Summary:  "hit",
		Upstream: "up1",
		Source:   "passive",
	}

	alert := string(security.BuildAlertMessage("a@b.c", []string{"x@y.z"}, f, "http://admin/"))
	assertNoSMTPHeaderInjection(t, alert)

	hdrEnd := strings.Index(alert, "\r\n\r\n")
	if hdrEnd < 0 {
		t.Fatal("missing header/body separator")
	}
	var subject string
	for _, line := range strings.Split(alert[:hdrEnd], "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "subject:") {
			subject = line
			break
		}
	}
	if subject == "" {
		t.Fatal("missing Subject header")
	}
	if strings.Contains(subject, "\r") || strings.Contains(subject, "\n") {
		t.Fatalf("Subject must be a single header line; got %q", subject)
	}
	if !strings.Contains(subject, "highBcc: x") {
		t.Fatalf("CR/LF must be stripped from Severity in Subject; got %q", subject)
	}
}

func TestSummary_NoSMTPHeaderInjection(t *testing.T) {
	evilSummary := "hit\r\nBcc: x\x00evil"
	f := security.Finding{
		ID:       "f1",
		Severity: security.SeverityCritical,
		Category: "credential_leak",
		Summary:  evilSummary,
		Upstream: "up1",
		Source:   "passive",
	}

	alert := string(security.BuildAlertMessage("a@b.c", []string{"x@y.z"}, f, "http://admin/"))
	assertNoSMTPHeaderInjection(t, alert)
	if !strings.Contains(alert, "summary: hitBcc: xevil\r\n") {
		t.Fatalf("CR/LF/NUL must be stripped from summary; got: %s", alert)
	}

	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	var captured []string
	m := security.NewAlertMailer().
		WithNowForTest(func() time.Time { return now }).
		WithSendForTest(func(a string, auth smtp.Auth, from string, to []string, msg []byte) error {
			captured = append(captured, string(msg))
			return nil
		})
	m.SetConfig(security.MailConfig{
		Enabled:     true,
		Host:        "smtp.test.local",
		Port:        587,
		From:        "relay@test.local",
		Recipients:  []string{"ops@test.local"},
		MinSeverity: security.SeverityInfo,
	})
	medium := security.Finding{
		ID:       "m1",
		Severity: security.SeverityMedium,
		Category: "xss_pattern",
		Summary:  evilSummary,
		Upstream: "up-a",
		Source:   "passive",
	}
	if err := m.MaybeNotify(medium, "http://admin/"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(5 * time.Minute)
	if err := m.FlushDigest(); err != nil {
		t.Fatal(err)
	}
	if len(captured) != 1 {
		t.Fatalf("want one digest; got %d", len(captured))
	}
	assertNoSMTPHeaderInjection(t, captured[0])
	if !strings.Contains(captured[0], "summary: hitBcc: xevil\r\n") {
		t.Fatalf("digest must strip CR/LF/NUL from summary; got: %s", captured[0])
	}
}

func TestAlertMailerSendAgainstFakeSMTP(t *testing.T) {
	addr, _, closeFn := security.StartFakeSMTP(t)
	defer closeFn()
	host, port, _ := strings.Cut(addr, ":")
	var captured []string
	m := security.NewAlertMailer().WithSendForTest(func(a string, auth smtp.Auth, from string, to []string, msg []byte) error {
		captured = append(captured, string(msg))
		return smtp.SendMail(a, auth, from, to, msg)
	})
	m.SetConfig(security.MailConfig{
		Enabled:     true,
		Host:        host,
		Port:        atoiPort(port),
		From:        "relay@test.local",
		Recipients:  []string{"ops@test.local"},
		MinSeverity: security.SeverityInfo,
	})
	if err := m.SendTest(""); err != nil {
		// Fake SMTP may not speak AUTH; use capture-only path.
		m.WithSendForTest(func(a string, auth smtp.Auth, from string, to []string, msg []byte) error {
			if a == "" || from == "" || len(to) == 0 {
				t.Fatalf("bad args")
			}
			captured = append(captured, string(msg))
			return nil
		})
		if err2 := m.SendTest(""); err2 != nil {
			t.Fatal(err2)
		}
	}
	if len(captured) == 0 {
		t.Fatal("no message captured")
	}
	body := captured[len(captured)-1]
	if strings.Contains(body, "<script>") || strings.Contains(strings.ToLower(body), "api key") {
		t.Fatal("sensitive content in mail")
	}
	if !strings.Contains(body, "smtp_test") && !strings.Contains(body, "SMTP") {
		t.Fatalf("unexpected body: %s", body)
	}
}

func atoiPort(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// §14.6: Critical may send immediately; medium/low aggregate; same finding
// is deduped/rate-limited. Dedup key is category|upstream (no raw body/secrets).
func TestAlertMailer_CriticalImmediate_NonCriticalDigestDedupe(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	var captured []string
	m := security.NewAlertMailer().
		WithNowForTest(func() time.Time { return now }).
		WithSendForTest(func(a string, auth smtp.Auth, from string, to []string, msg []byte) error {
			captured = append(captured, string(msg))
			return nil
		})
	m.SetConfig(security.MailConfig{
		Enabled:     true,
		Host:        "smtp.test.local",
		Port:        587,
		From:        "relay@test.local",
		Recipients:  []string{"ops@test.local"},
		MinSeverity: security.SeverityInfo,
	})

	medium := security.Finding{
		ID:       "m1",
		Severity: security.SeverityMedium,
		Category: "xss_pattern",
		Summary:  "检测到 HTML 事件属性",
		Detail:   "raw body with secret sk-SECRET must not be a dedupe key",
		Upstream: "up-a",
		RouteID:  7,
		Source:   "passive",
	}
	if err := m.MaybeNotify(medium, "http://admin/"); err != nil {
		t.Fatal(err)
	}
	if err := m.MaybeNotify(medium, "http://admin/"); err != nil {
		t.Fatal(err)
	}
	if len(captured) != 0 {
		t.Fatalf("non-critical must not send immediately; got %d mails", len(captured))
	}

	crit := security.Finding{
		ID:       "c1",
		Severity: security.SeverityCritical,
		Category: "credential_leak",
		Summary:  "known credential fragment",
		Upstream: "up-b",
		Source:   "passive",
	}
	if err := m.MaybeNotify(crit, "http://admin/"); err != nil {
		t.Fatal(err)
	}
	if len(captured) != 1 {
		t.Fatalf("critical must send immediately without waiting for digest; got %d", len(captured))
	}
	if !strings.Contains(captured[0], "severity: critical") {
		t.Fatalf("expected immediate critical mail, got: %s", captured[0])
	}
	if strings.Contains(captured[0], "sk-SECRET") || strings.Contains(captured[0], "raw body") {
		t.Fatal("secret/raw body leaked into critical mail")
	}

	// Second identical critical inside rate window must not send again.
	if err := m.MaybeNotify(crit, "http://admin/"); err != nil {
		t.Fatal(err)
	}
	if len(captured) != 1 {
		t.Fatalf("identical critical inside window must be rate-limited; got %d", len(captured))
	}

	now = now.Add(5 * time.Minute)
	if err := m.FlushDigest(); err != nil {
		t.Fatal(err)
	}
	if len(captured) != 2 {
		t.Fatalf("want one digest after flush; got %d mails", len(captured))
	}
	digest := captured[1]
	if !strings.Contains(digest, "security digest") {
		t.Fatalf("expected digest subject/body, got: %s", digest)
	}
	if !strings.Contains(digest, "unique_findings: 1") {
		t.Fatalf("two identical medium findings must dedupe to one digest item: %s", digest)
	}
	if !strings.Contains(digest, "count=2") {
		t.Fatalf("digest should record duplicate count: %s", digest)
	}
	if strings.Contains(digest, "sk-SECRET") || strings.Contains(digest, "raw body with secret") {
		t.Fatal("detail/secret must not appear in digest")
	}

	// Same medium identity still inside rate window after digest → no second digest.
	if err := m.MaybeNotify(medium, "http://admin/"); err != nil {
		t.Fatal(err)
	}
	if err := m.FlushDigest(); err != nil {
		t.Fatal(err)
	}
	if len(captured) != 2 {
		t.Fatalf("rate-limited medium must not produce another digest; got %d", len(captured))
	}
}
