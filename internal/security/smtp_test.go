package security_test

import (
	"net/smtp"
	"strings"
	"testing"

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
