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

type digestItem struct {
	finding  Finding
	count    int
	adminURL string
}

// AlertMailer sends metadata-only alert emails (no conversation body).
// Critical findings may send immediately; other severities default to an
// aggregated digest (§14.6). Same finding identity is deduped and rate-limited.
type AlertMailer struct {
	mu     sync.Mutex
	cfg    MailConfig
	dial   func(addr string) (net.Conn, error)
	send   func(addr string, a smtp.Auth, from string, to []string, msg []byte) error
	lastAt map[string]time.Time // finding identity → last notify/digest
	window time.Duration

	pending       map[string]digestItem
	digestStarted time.Time
	digestTimer   *time.Timer
	now           func() time.Time
	testClock     bool // WithNowForTest: tests drive FlushDigest; no wall timer
}

// NewAlertMailer constructs a mailer. dial/send nil → net defaults.
func NewAlertMailer() *AlertMailer {
	return &AlertMailer{
		dial:    func(addr string) (net.Conn, error) { return net.DialTimeout("tcp", addr, 10*time.Second) },
		send:    smtp.SendMail,
		lastAt:  map[string]time.Time{},
		pending: map[string]digestItem{},
		window:  5 * time.Minute,
		now:     time.Now,
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

// WithNowForTest injects a clock for deterministic rate-limit / digest tests.
// Real wall timers are disabled; call FlushDigest after advancing the clock.
func (m *AlertMailer) WithNowForTest(fn func() time.Time) *AlertMailer {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = fn
	m.testClock = true
	return m
}

// sanitizeAdminURL strips CR, LF, and NUL so an admin link cannot inject
// extra SMTP header lines when written into alert/digest messages.
func sanitizeAdminURL(u string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return -1
		}
		return r
	}, u)
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
	if u := sanitizeAdminURL(adminURL); u != "" {
		body.WriteString(fmt.Sprintf("admin: %s\r\n", u))
	}
	body.WriteString("\r\nThis message intentionally omits response bodies, secrets, and chat text.\r\n")
	return buildMIME(from, to, subj, body.String())
}

// BuildDigestMessage builds a metadata-only aggregated digest for non-critical findings.
func BuildDigestMessage(from string, to []string, items []digestItem, adminURL string) []byte {
	subj := "[relay-gate] security digest"
	body := strings.Builder{}
	body.WriteString("relay-gate security digest (metadata only; no conversation body)\r\n\r\n")
	body.WriteString(fmt.Sprintf("unique_findings: %d\r\n\r\n", len(items)))
	for i, it := range items {
		f := it.finding
		body.WriteString(fmt.Sprintf("--- item %d (count=%d) ---\r\n", i+1, it.count))
		body.WriteString(fmt.Sprintf("severity: %s\r\n", f.Severity))
		body.WriteString(fmt.Sprintf("category: %s\r\n", f.Category))
		body.WriteString(fmt.Sprintf("summary: %s\r\n", clip(f.Summary, 200)))
		body.WriteString(fmt.Sprintf("upstream: %s\r\n", f.Upstream))
		body.WriteString(fmt.Sprintf("route_id: %d\r\n", f.RouteID))
		body.WriteString(fmt.Sprintf("source: %s\r\n", f.Source))
		body.WriteString("\r\n")
	}
	if u := sanitizeAdminURL(adminURL); u != "" {
		body.WriteString(fmt.Sprintf("admin: %s\r\n", u))
	}
	body.WriteString("\r\nThis message intentionally omits response bodies, secrets, and chat text.\r\n")
	return buildMIME(from, to, subj, body.String())
}

func buildMIME(from string, to []string, subj, body string) []byte {
	var msg strings.Builder
	msg.WriteString("From: " + from + "\r\n")
	msg.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	msg.WriteString("Subject: " + subj + "\r\n")
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(body)
	return []byte(msg.String())
}

// findingKey is the existing-style dedupe identity: category|upstream.
// It must not include raw body, Detail, or secrets.
func findingKey(f Finding) string {
	return f.Category + "|" + f.Upstream
}

// MaybeNotify sends if enabled, severity >= min, and not rate-limited.
// Critical may send immediately; other severities queue into a digest (§14.6).
// Failures are returned but must never affect forwarding.
func (m *AlertMailer) MaybeNotify(f Finding, adminURL string) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	cfg := m.cfg
	now := m.now()
	if err := m.flushDigestIfDueLocked(now); err != nil {
		m.mu.Unlock()
		return err
	}
	m.mu.Unlock()

	if !cfg.Enabled || cfg.Host == "" || len(cfg.Recipients) == 0 || cfg.From == "" {
		return nil
	}
	if !severityAtLeast(f.Severity, cfg.MinSeverity) {
		return nil
	}

	key := findingKey(f)
	if f.Severity == SeverityCritical {
		return m.notifyImmediate(cfg, f, adminURL, key)
	}
	return m.queueDigest(f, adminURL, key)
}

func (m *AlertMailer) notifyImmediate(cfg MailConfig, f Finding, adminURL, key string) error {
	m.mu.Lock()
	now := m.now()
	if t, ok := m.lastAt[key]; ok && now.Sub(t) < m.window {
		m.mu.Unlock()
		return nil
	}
	m.lastAt[key] = now
	m.mu.Unlock()

	return m.doSend(cfg, BuildAlertMessage(cfg.From, cfg.Recipients, f, adminURL))
}

func (m *AlertMailer) queueDigest(f Finding, adminURL, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()

	if item, ok := m.pending[key]; ok {
		item.count++
		m.pending[key] = item
		return nil
	}
	if t, ok := m.lastAt[key]; ok && now.Sub(t) < m.window {
		return nil
	}
	m.pending[key] = digestItem{finding: f, count: 1, adminURL: adminURL}
	if m.digestStarted.IsZero() {
		m.digestStarted = now
		m.armDigestTimerLocked()
	}
	return nil
}

func (m *AlertMailer) armDigestTimerLocked() {
	if m.digestTimer != nil {
		m.digestTimer.Stop()
		m.digestTimer = nil
	}
	if m.testClock {
		return
	}
	delay := m.window
	m.digestTimer = time.AfterFunc(delay, func() {
		_ = m.FlushDigest()
	})
}

// FlushDigest sends any pending aggregated digest immediately (tests / shutdown).
func (m *AlertMailer) FlushDigest() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flushDigestLocked(m.now())
}

func (m *AlertMailer) flushDigestIfDueLocked(now time.Time) error {
	if len(m.pending) == 0 || m.digestStarted.IsZero() {
		return nil
	}
	if now.Sub(m.digestStarted) < m.window {
		return nil
	}
	return m.flushDigestLocked(now)
}

func (m *AlertMailer) flushDigestLocked(now time.Time) error {
	if len(m.pending) == 0 {
		m.digestStarted = time.Time{}
		if m.digestTimer != nil {
			m.digestTimer.Stop()
			m.digestTimer = nil
		}
		return nil
	}
	cfg := m.cfg
	items := make([]digestItem, 0, len(m.pending))
	adminURL := ""
	for key, item := range m.pending {
		items = append(items, item)
		m.lastAt[key] = now
		if adminURL == "" {
			adminURL = item.adminURL
		}
	}
	m.pending = map[string]digestItem{}
	m.digestStarted = time.Time{}
	if m.digestTimer != nil {
		m.digestTimer.Stop()
		m.digestTimer = nil
	}
	if !cfg.Enabled || cfg.Host == "" || len(cfg.Recipients) == 0 || cfg.From == "" {
		return nil
	}
	m.mu.Unlock()
	err := m.doSend(cfg, BuildDigestMessage(cfg.From, cfg.Recipients, items, adminURL))
	m.mu.Lock()
	return err
}

func (m *AlertMailer) doSend(cfg MailConfig, msg []byte) error {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}
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
