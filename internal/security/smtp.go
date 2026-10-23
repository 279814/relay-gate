package security

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"sort"
	"strings"
	"sync"
	"time"
)

// MailConfig is runtime SMTP settings for alerts (§14.6).
type MailConfig struct {
	Revision             int64
	Enabled              bool
	Host                 string
	Port                 int
	UseSTARTTLS          bool
	UseSMTPS             bool
	From                 string
	Recipients           []string
	Username             string
	Password             string
	MinSeverity          Severity
	AggregationWindowSec int
	RateLimitWindowSec   int
}

const DefaultSMTPWindowSec = 300
const MaxSMTPWindowSec = 86400

func (c MailConfig) withDefaults() MailConfig {
	if c.Port == 0 {
		c.Port = 587
		if c.UseSMTPS {
			c.Port = 465
		}
	}
	if c.AggregationWindowSec == 0 {
		c.AggregationWindowSec = DefaultSMTPWindowSec
	}
	if c.RateLimitWindowSec == 0 {
		c.RateLimitWindowSec = DefaultSMTPWindowSec
	}
	return c
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
	mu       sync.Mutex
	cfg      MailConfig
	dial     func(addr string) (net.Conn, error)
	send     func(addr string, a smtp.Auth, from string, to []string, msg []byte) error
	lastAt   map[string]time.Time // zero reserves an unsent identity
	inFlight map[string]bool
	flushing bool
	ignore   func(Finding, int64) (bool, error)
	status   MailStatus

	pending       map[string]digestItem
	digestStarted time.Time
	digestTimer   *time.Timer
	now           func() time.Time
	testClock     bool        // WithNowForTest: tests drive FlushDigest; no wall timer
	tlsConfig     *tls.Config // package-local test trust roots; nil uses system roots
	timeout       time.Duration
}

// NewAlertMailer constructs a mailer with bounded, certificate-verified TLS.
func NewAlertMailer() *AlertMailer {
	return &AlertMailer{
		cfg:      (MailConfig{}).withDefaults(),
		dial:     func(addr string) (net.Conn, error) { return net.DialTimeout("tcp", addr, 10*time.Second) },
		lastAt:   map[string]time.Time{},
		inFlight: map[string]bool{},
		pending:  map[string]digestItem{},
		now:      time.Now,
		timeout:  10 * time.Second,
	}
}

// SetConfig replaces SMTP settings (password held in memory only).
func (m *AlertMailer) SetConfig(c MailConfig) error {
	c = c.withDefaults()
	if err := c.Validate(); err != nil {
		return err
	}
	c.Recipients = append([]string(nil), c.Recipients...)
	m.mu.Lock()
	defer m.mu.Unlock()
	if c.Revision < m.cfg.Revision {
		return nil // a slower reload must not replace a newer committed snapshot
	}
	m.cfg = c
	if !m.digestStarted.IsZero() {
		m.armDigestTimerLocked()
	}
	return nil
}

// Config returns a copy without password.
func (m *AlertMailer) Config() MailConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.cfg
	c.Password = ""
	c.Recipients = append([]string(nil), c.Recipients...)
	return c
}

// WithSendForTest captures message delivery in content/rate-limit tests.
// Transport security is exercised separately against real TLS SMTP listeners.
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

// sanitizeSMTPField strips CR, LF, and NUL so free-text values cannot inject
// extra SMTP header lines when written into alert/digest messages.
func sanitizeSMTPField(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return -1
		}
		return r
	}, s)
}

// BuildAlertMessage builds a metadata-only MIME message (no response/conversation body).
func BuildAlertMessage(from string, to []string, f Finding, adminURL string) []byte {
	subj := fmt.Sprintf("[relay-gate] %s %s", sanitizeSMTPField(string(f.Severity)), sanitizeSMTPField(f.Category))
	body := strings.Builder{}
	body.WriteString("relay-gate security alert (metadata only; no conversation body)\r\n\r\n")
	body.WriteString(fmt.Sprintf("severity: %s\r\n", sanitizeSMTPField(string(f.Severity))))
	body.WriteString(fmt.Sprintf("category: %s\r\n", sanitizeSMTPField(f.Category)))
	body.WriteString(fmt.Sprintf("summary: %s\r\n", sanitizeSMTPField(clip(f.Summary, 200))))
	body.WriteString(fmt.Sprintf("upstream: %s\r\n", sanitizeSMTPField(f.Upstream)))
	body.WriteString(fmt.Sprintf("route_id: %d\r\n", f.RouteID))
	body.WriteString(fmt.Sprintf("req_id: %s\r\n", sanitizeSMTPField(f.ReqID)))
	body.WriteString(fmt.Sprintf("source: %s\r\n", sanitizeSMTPField(f.Source)))
	body.WriteString(fmt.Sprintf("finding_id: %s\r\n", sanitizeSMTPField(f.ID)))
	if u := sanitizeSMTPField(adminURL); u != "" {
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
		body.WriteString(fmt.Sprintf("severity: %s\r\n", sanitizeSMTPField(string(f.Severity))))
		body.WriteString(fmt.Sprintf("category: %s\r\n", sanitizeSMTPField(f.Category)))
		body.WriteString(fmt.Sprintf("summary: %s\r\n", sanitizeSMTPField(clip(f.Summary, 200))))
		body.WriteString(fmt.Sprintf("upstream: %s\r\n", sanitizeSMTPField(f.Upstream)))
		body.WriteString(fmt.Sprintf("route_id: %d\r\n", f.RouteID))
		body.WriteString(fmt.Sprintf("source: %s\r\n", sanitizeSMTPField(f.Source)))
		body.WriteString("\r\n")
	}
	if u := sanitizeSMTPField(adminURL); u != "" {
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

// MailStatus contains operational counters only, with no evidence or driver errors.
type MailStatus struct {
	PolicyFailures   uint64 `json:"policy_failures"`
	DeliveryFailures uint64 `json:"delivery_failures"`
	CapacityDrops    uint64 `json:"capacity_drops"`
	Suppressed       uint64 `json:"suppressed"`
	Pending          int    `json:"pending"`
}

var errAlertPolicy = errors.New("安全告警忽略策略暂不可读")
var errAlertCapacity = errors.New("安全告警身份容量已满")

const maxAlertIdentities = 1024

// SetIgnorePolicy runs a direct persistent reader in the background worker.
// Policy SQL and SMTP delivery never run under the mailer mutex.
func (m *AlertMailer) SetIgnorePolicy(fn func(Finding, int64) (bool, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ignore = fn
}
func (m *AlertMailer) Status() MailStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.status
	s.Pending = len(m.pending)
	return s
}
func (m *AlertMailer) ignored(f Finding, now time.Time) (bool, error) {
	m.mu.Lock()
	fn := m.ignore
	m.mu.Unlock()
	if fn == nil {
		return false, nil
	}
	ignored, err := fn(f, now.UnixMilli())
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.status.PolicyFailures++
		return false, errAlertPolicy
	}
	if ignored {
		m.status.Suppressed++
	}
	return ignored, nil
}
func findingKey(f Finding) string {
	if f.RuleID != "" && f.UpstreamID > 0 && f.RouteID > 0 {
		return fmt.Sprintf("captured:%q:%d:%d", f.RuleID, f.UpstreamID, f.RouteID)
	}
	return fmt.Sprintf("legacy:%q:%q:%q:%d:%d", f.RuleID, f.Category, f.Upstream, f.UpstreamID, f.RouteID)
}
func mailEnabled(c MailConfig) bool {
	return c.Enabled && c.Host != "" && len(c.Recipients) > 0 && c.From != ""
}
func (m *AlertMailer) admitLocked(key string, now time.Time) bool {
	for id, at := range m.lastAt {
		if !m.inFlight[id] && m.pending[id].count == 0 && (at.IsZero() || now.Sub(at) >= time.Duration(m.cfg.RateLimitWindowSec)*time.Second) {
			delete(m.lastAt, id)
		}
	}
	if _, ok := m.lastAt[key]; ok {
		return true
	}
	if len(m.lastAt) >= maxAlertIdentities {
		m.status.CapacityDrops++
		return false
	}
	m.lastAt[key] = time.Time{}
	return true
}
func (m *AlertMailer) MaybeNotify(f Finding, adminURL string) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	now := m.now()
	err := m.flushDigestIfDueLocked(now)
	cfg := m.cfg
	m.mu.Unlock()
	if err != nil {
		return err
	}
	if !mailEnabled(cfg) || !severityAtLeast(f.Severity, cfg.MinSeverity) {
		return nil
	}
	ignored, err := m.ignored(f, now)
	if err != nil || ignored {
		return err
	}
	key := findingKey(f)
	if f.Severity == SeverityCritical {
		return m.notifyImmediate(cfg, f, adminURL, key)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now = m.now()
	if !m.admitLocked(key, now) {
		return errAlertCapacity
	}
	if !m.lastAt[key].IsZero() && now.Sub(m.lastAt[key]) < time.Duration(m.cfg.RateLimitWindowSec)*time.Second {
		return nil
	}
	if item, ok := m.pending[key]; ok {
		item.count++
		m.pending[key] = item
		return nil
	}
	m.pending[key] = digestItem{finding: f, count: 1, adminURL: adminURL}
	if m.digestStarted.IsZero() {
		m.digestStarted = now
		m.armDigestTimerLocked()
	}
	return nil
}
func (m *AlertMailer) notifyImmediate(cfg MailConfig, f Finding, adminURL, key string) error {
	m.mu.Lock()
	now := m.now()
	if !m.admitLocked(key, now) {
		m.mu.Unlock()
		return errAlertCapacity
	}
	if m.inFlight[key] || !m.lastAt[key].IsZero() && now.Sub(m.lastAt[key]) < time.Duration(cfg.RateLimitWindowSec)*time.Second {
		m.mu.Unlock()
		return nil
	}
	m.inFlight[key] = true
	m.mu.Unlock()
	err := m.doSend(cfg, BuildAlertMessage(cfg.From, cfg.Recipients, f, adminURL))
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.inFlight, key)
	if err != nil {
		m.status.DeliveryFailures++
		if m.lastAt[key].IsZero() && m.pending[key].count == 0 {
			delete(m.lastAt, key)
		}
		return err
	}
	m.lastAt[key] = m.now()
	return nil
}
func (m *AlertMailer) armDigestTimerLocked() {
	if m.digestTimer != nil {
		m.digestTimer.Stop()
		m.digestTimer = nil
	}
	if m.testClock || m.digestStarted.IsZero() {
		return
	}
	delay := max(time.Duration(0), m.digestStarted.Add(time.Duration(m.cfg.AggregationWindowSec)*time.Second).Sub(m.now()))
	m.digestTimer = time.AfterFunc(delay, func() { m.mu.Lock(); defer m.mu.Unlock(); _ = m.flushDigestIfDueLocked(m.now()) })
}
func (m *AlertMailer) FlushDigest() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flushDigestLocked(m.now())
}
func (m *AlertMailer) flushDigestIfDueLocked(now time.Time) error {
	if len(m.pending) == 0 || m.digestStarted.IsZero() || now.Sub(m.digestStarted) < time.Duration(m.cfg.AggregationWindowSec)*time.Second {
		return nil
	}
	return m.flushDigestLocked(now)
}

// Snapshot counts, perform I/O outside the lock, subtract only that snapshot.
// Later arrivals stay pending; failed delivery leaves all captured items intact.
func (m *AlertMailer) flushDigestLocked(now time.Time) error {
	if m.flushing || len(m.pending) == 0 {
		return nil
	}
	m.flushing = true
	cfg := m.cfg
	captured := make(map[string]digestItem, len(m.pending))
	keys := make([]string, 0, len(m.pending))
	for k, v := range m.pending {
		captured[k] = v
		keys = append(keys, k)
	}
	sort.Strings(keys)
	m.mu.Unlock()
	items := make([]digestItem, 0, len(keys))
	ignoredKeys := map[string]bool{}
	var err error
	if mailEnabled(cfg) {
		for _, k := range keys {
			ignored, policyErr := m.ignored(captured[k].finding, now)
			if policyErr != nil {
				err = policyErr
				break
			}
			if ignored || !severityAtLeast(captured[k].finding.Severity, cfg.MinSeverity) {
				ignoredKeys[k] = true
			} else {
				items = append(items, captured[k])
			}
		}
	}
	if err == nil && len(items) > 0 {
		err = m.doSend(cfg, BuildDigestMessage(cfg.From, cfg.Recipients, items, items[0].adminURL))
	}
	m.mu.Lock()
	m.flushing = false
	if err == nil {
		for _, k := range keys {
			v := m.pending[k]
			v.count -= captured[k].count
			if v.count <= 0 {
				delete(m.pending, k)
			} else {
				m.pending[k] = v
			}
			if mailEnabled(cfg) && !ignoredKeys[k] {
				m.lastAt[k] = m.now()
			} else if m.lastAt[k].IsZero() && v.count <= 0 {
				delete(m.lastAt, k)
			}
		}
	} else if !errors.Is(err, errAlertPolicy) {
		m.status.DeliveryFailures++
	}
	if len(m.pending) > 0 {
		m.digestStarted = m.now()
	} else {
		m.digestStarted = time.Time{}
	}
	m.armDigestTimerLocked()
	return err
}

// SendTest sends a test alert with smtp_test source.
func (m *AlertMailer) SendTest(adminURL string) error {
	if m == nil {
		return fmt.Errorf("SMTP mailer is not configured")
	}
	m.mu.Lock()
	cfg := m.cfg
	m.mu.Unlock()
	// A deliberate test is independent of alert enablement, threshold and
	// dedupe. Success means this call actually completed one SMTP delivery.
	cfg.Enabled = true
	finding := Finding{
		ID:       "smtp-test",
		Severity: SeverityCritical,
		Category: "smtp_test",
		Summary:  "SMTP 测试邮件",
		Source:   "smtp_test",
	}
	return m.doSend(cfg, BuildAlertMessage(cfg.From, cfg.Recipients, finding, adminURL))
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
