package security

import (
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"time"
)

// MailConfig is runtime SMTP settings for alerts (§14.6).
type MailConfig struct {
	Enabled     bool
	Host        string
	Port        int
	UseSTARTTLS bool
	UseSMTPS    bool
	From        string
	Recipients  []string
	Username    string
	Password    string
	MinSeverity Severity
}

// AlertMailer sends metadata-only alert emails (no conversation body).
type AlertMailer struct {
	mu     sync.Mutex
	cfg    MailConfig
	dial   func(addr string) (net.Conn, error)
	send   func(addr string, a smtp.Auth, from string, to []string, msg []byte) error
	lastAt map[string]time.Time // category|upstream dedupe
	window time.Duration
}

// NewAlertMailer constructs a mailer. dial/send nil → net defaults.
func NewAlertMailer() *AlertMailer {
	return &AlertMailer{
		dial:   func(addr string) (net.Conn, error) { return net.DialTimeout("tcp", addr, 10*time.Second) },
		send:   smtp.SendMail,
		lastAt: map[string]time.Time{},
		window: 5 * time.Minute,
	}
}

// SetConfig replaces SMTP settings (password held in memory only).
func (m *AlertMailer) SetConfig(c MailConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = c
}

// Config returns a copy without password.
func (m *AlertMailer) Config() MailConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.cfg
	c.Password = ""
	return c
}

// WithSendForTest injects smtp.SendMail replacement (local fake SMTP).
func (m *AlertMailer) WithSendForTest(fn func(addr string, a smtp.Auth, from string, to []string, msg []byte) error) *AlertMailer {
	m.send = fn
	return m
}

// BuildAlertMessage builds a metadata-only MIME message (no response/conversation body).
func BuildAlertMessage(from string, to []string, f Finding, adminURL string) []byte {
	subj := fmt.Sprintf("[relay-gate] %s %s", f.Severity, f.Category)
	body := strings.Builder{}
	body.WriteString("relay-gate security alert (metadata only; no conversation body)\r\n\r\n")
	body.WriteString(fmt.Sprintf("severity: %s\r\n", f.Severity))
	body.WriteString(fmt.Sprintf("category: %s\r\n", f.Category))
	body.WriteString(fmt.Sprintf("summary: %s\r\n", clip(f.Summary, 200)))
	body.WriteString(fmt.Sprintf("upstream: %s\r\n", f.Upstream))
	body.WriteString(fmt.Sprintf("route_id: %d\r\n", f.RouteID))
	body.WriteString(fmt.Sprintf("req_id: %s\r\n", f.ReqID))
	body.WriteString(fmt.Sprintf("source: %s\r\n", f.Source))
	body.WriteString(fmt.Sprintf("finding_id: %s\r\n", f.ID))
	if adminURL != "" {
		body.WriteString(fmt.Sprintf("admin: %s\r\n", adminURL))
	}
	body.WriteString("\r\nThis message intentionally omits response bodies, secrets, and chat text.\r\n")
	var msg strings.Builder
	msg.WriteString("From: " + from + "\r\n")
	msg.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	msg.WriteString("Subject: " + subj + "\r\n")
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(body.String())
	return []byte(msg.String())
}

// MaybeNotify sends if enabled, severity >= min, and not rate-limited.
// Failures are returned but must never affect forwarding.
func (m *AlertMailer) MaybeNotify(f Finding, adminURL string) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	cfg := m.cfg
	m.mu.Unlock()
	if !cfg.Enabled || cfg.Host == "" || len(cfg.Recipients) == 0 || cfg.From == "" {
		return nil
	}
	if !severityAtLeast(f.Severity, cfg.MinSeverity) {
		return nil
	}
	key := f.Category + "|" + f.Upstream
	m.mu.Lock()
	if t, ok := m.lastAt[key]; ok && time.Since(t) < m.window {
		m.mu.Unlock()
		return nil
	}
	m.lastAt[key] = time.Now()
	m.mu.Unlock()

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}
	msg := BuildAlertMessage(cfg.From, cfg.Recipients, f, adminURL)
	return m.send(addr, auth, cfg.From, cfg.Recipients, msg)
}

// SendTest sends a test alert with smtp_test source.
func (m *AlertMailer) SendTest(adminURL string) error {
	return m.MaybeNotify(Finding{
		ID:       "smtp-test",
		Severity: SeverityCritical,
		Category: "smtp_test",
		Summary:  "SMTP 测试邮件",
		Source:   "smtp_test",
	}, adminURL)
}

func severityAtLeast(got, min Severity) bool {
	rank := map[Severity]int{
		SeverityInfo: 1, SeverityLow: 2, SeverityMedium: 3,
		SeverityHigh: 4, SeverityCritical: 5,
	}
	if min == "" {
		min = SeverityCritical
	}
	return rank[got] >= rank[min]
}
