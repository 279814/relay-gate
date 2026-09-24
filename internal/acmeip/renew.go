package acmeip

import (
	"fmt"
	"sync"
	"time"
)

// DefaultLowValidity is the remaining-lifetime threshold that raises an
// observability alert. LE IP certificates last ~160h; operators need headroom
// before expiry, not a last-minute surprise.
const DefaultLowValidity = 48 * time.Hour

// Renewer is the Certbot renew surface used after live HTTPS is up (§12.2).
// Tests inject fakes; this package is not the documented HTTP IP:port install path.
type Renewer interface {
	RenewIP(ip string) (certPEM, keyPEM string, notAfter time.Time, err error)
	Validate(certPEM, keyPEM, expectIP string) error
}

// Reloader applies a validated renewed certificate (e.g. nginx -s reload).
// A failed Reload must leave the previous working process in place.
type Reloader interface {
	Reload() error
}

// RenewWatch tracks daily renew attempts, remaining validity, and reload
// outcomes so §23 "IP 证书自动续期可观测" can be asserted offline with fakes.
//
// It never claims a public certificate was issued. The documented install is
// HTTP IP:port (README); this watcher is for the §12.2 certificate experiment.
type RenewWatch struct {
	mu sync.Mutex

	bot    Renewer
	reload Reloader
	ip     string
	low    time.Duration
	now    func() time.Time

	lastAttemptAt       time.Time
	lastSuccessAt       time.Time
	lastError           string
	notAfter            time.Time
	alertLowValidity    bool
	reloadFailedKeepOld bool
	renewCount          int
	successCount        int
}

// NewRenewWatch constructs an idle watch. low <= 0 selects DefaultLowValidity.
func NewRenewWatch(bot Renewer, reload Reloader, ip string, low time.Duration) *RenewWatch {
	if low <= 0 {
		low = DefaultLowValidity
	}
	return &RenewWatch{
		bot:    bot,
		reload: reload,
		ip:     ip,
		low:    low,
		now:    time.Now,
	}
}

// SetClock overrides the clock (tests only).
func (w *RenewWatch) SetClock(now func() time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if now != nil {
		w.now = now
	}
}

// ObserveCurrent records NotAfter for an already-live certificate and
// refreshes the low-validity alert without attempting renew.
func (w *RenewWatch) ObserveCurrent(notAfter time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.notAfter = notAfter
	w.refreshAlertLocked(w.now())
}

// TryRenew runs renew → validate → reload.
//
// On renew/validate failure the previous certificate stays in service and the
// error is recorded. On reload failure the previous working process is kept
// (reloadFailedKeepOld=true) and an alert is raised — never fall back to
// plaintext HTTP.
func (w *RenewWatch) TryRenew() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	now := w.now()
	w.lastAttemptAt = now
	w.renewCount++
	w.lastError = ""

	if w.bot == nil {
		return w.failAttemptLocked(fmt.Errorf("未配置 Certbot renewer"))
	}
	if w.ip == "" {
		return w.failAttemptLocked(fmt.Errorf("ip 不能为空"))
	}

	cert, key, notAfter, err := w.bot.RenewIP(w.ip)
	if err != nil {
		return w.failAttemptLocked(err)
	}
	if err := w.bot.Validate(cert, key, w.ip); err != nil {
		return w.failAttemptLocked(err)
	}
	if w.reload != nil {
		if err := w.reload.Reload(); err != nil {
			w.reloadFailedKeepOld = true
			w.lastError = err.Error()
			w.refreshAlertLocked(now)
			return fmt.Errorf("reload 失败，保留旧证书工作进程: %w", err)
		}
	}
	w.reloadFailedKeepOld = false
	w.notAfter = notAfter
	w.lastSuccessAt = now
	w.successCount++
	w.refreshAlertLocked(now)
	return nil
}

func (w *RenewWatch) failAttemptLocked(err error) error {
	w.lastError = err.Error()
	w.refreshAlertLocked(w.now())
	return err
}

func (w *RenewWatch) refreshAlertLocked(now time.Time) {
	if w.notAfter.IsZero() {
		w.alertLowValidity = false
		return
	}
	w.alertLowValidity = !now.Before(w.notAfter.Add(-w.low))
}

// Snapshot is a JSON-friendly renew observability view (§23).
func (w *RenewWatch) Snapshot() map[string]any {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	var remainingHours float64
	if !w.notAfter.IsZero() {
		remainingHours = w.notAfter.Sub(now).Hours()
	}
	return map[string]any{
		"ip":                       w.ip,
		"last_attempt_at":          formatTime(w.lastAttemptAt),
		"last_success_at":          formatTime(w.lastSuccessAt),
		"last_error":               w.lastError,
		"not_after":                formatTime(w.notAfter),
		"remaining_hours":          remainingHours,
		"alert_low_validity":       w.alertLowValidity,
		"reload_failed_keep_old":   w.reloadFailedKeepOld,
		"renew_attempts":           w.renewCount,
		"renew_successes":          w.successCount,
		"low_validity_threshold_h": w.low.Hours(),
	}
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
