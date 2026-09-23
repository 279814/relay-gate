package credential

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ErrReauthRequired means the caller must re-submit the admin password.
var ErrReauthRequired = errors.New("需要重新输入管理员密码")

// ErrNotFound is returned when a relay key id is unknown.
var ErrNotFound = errors.New("凭据不存在")

// Service holds admin-facing credential operations (§12.3–12.6).
//
// Master Key plaintext lives only in Keyring; Relay keys are held here for
// hot-path auth with optional grace overlap. Admin password verification is
// delegated to the caller (API compares against configured adminPW).
type Service struct {
	mu sync.Mutex

	revealUntil time.Time
	revealValue string

	relayActive string
	relayGrace  string
	// relayAlso holds extra bootstrap keys (comma-separated RELAY_KEYS) that
	// remain accepted alongside active/grace. Rotation moves only relayActive
	// into grace; also-keys are unchanged (§12.6 single active + docs/03 multi).
	relayAlso  map[string]struct{}
	graceUntil time.Time
	graceSec   int

	audit []AuditEvent
	max   int
	now   func() time.Time
}

// AuditEvent is a pure-text credential audit row (§12.6).
type AuditEvent struct {
	At     string `json:"at"`
	Action string `json:"action"`
	Detail string `json:"detail"`
}

// New constructs a Service with default 10-minute relay grace.
func New() *Service {
	return &Service{
		graceSec: 600,
		max:      200,
		now:      time.Now,
	}
}

// SetActiveRelayKey installs the primary relay key (bootstrap / env import).
func (s *Service) SetActiveRelayKey(key string) {
	s.SetActiveRelayKeys([]string{key})
}

// SetActiveRelayKeys installs the accepted relay key set from env / bootstrap.
// The first non-empty key becomes active; the rest are also-keys.
func (s *Service) SetActiveRelayKeys(keys []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.relayActive = ""
	s.relayAlso = nil
	s.relayGrace = ""
	s.graceUntil = time.Time{}
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if s.relayActive == "" {
			s.relayActive = key
			continue
		}
		if s.relayAlso == nil {
			s.relayAlso = make(map[string]struct{})
		}
		s.relayAlso[key] = struct{}{}
	}
}

// WithNow overrides the time source (tests: grace expiry without sleeping).
func (s *Service) WithNow(now func() time.Time) *Service {
	if now != nil {
		s.now = now
	}
	return s
}

// Status returns a non-secret snapshot for the credentials page.
func (s *Service) Status() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireGraceLocked()
	graceLeft := 0
	if !s.graceUntil.IsZero() && s.now().Before(s.graceUntil) {
		graceLeft = int(s.graceUntil.Sub(s.now()).Seconds())
	}
	return map[string]any{
		"relay_active_fingerprint": fingerprint(s.relayActive),
		"relay_grace_fingerprint":  fingerprint(s.relayGrace),
		"relay_grace_seconds_left": graceLeft,
		"master_reveal_active":     s.now().Before(s.revealUntil),
		"audit":                    append([]AuditEvent(nil), s.audit...),
	}
}

// ValidRelayKey reports whether key matches active, in-grace, or also-key.
func (s *Service) ValidRelayKey(key string) bool {
	if key == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireGraceLocked()
	if key == s.relayActive || (s.relayGrace != "" && key == s.relayGrace) {
		return true
	}
	_, ok := s.relayAlso[key]
	return ok
}

// ActiveRelayKeys returns keys currently accepted for proxy auth.
func (s *Service) ActiveRelayKeys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireGraceLocked()
	out := []string{}
	if s.relayActive != "" {
		out = append(out, s.relayActive)
	}
	if s.relayGrace != "" {
		out = append(out, s.relayGrace)
	}
	for k := range s.relayAlso {
		out = append(out, k)
	}
	return out
}

// RotateRelayKey generates a new active key; old remains in grace.
func (s *Service) RotateRelayKey() (newKey string, graceSeconds int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	newKey, err = randomKey(32)
	if err != nil {
		return "", 0, err
	}
	if s.relayActive != "" {
		s.relayGrace = s.relayActive
		s.graceUntil = s.now().Add(time.Duration(s.graceSec) * time.Second)
	}
	s.relayActive = newKey
	s.noteLocked("relay_rotate", "new active; old in grace")
	return newKey, s.graceSec, nil
}

// RevokeGrace drops the overlapping old relay key immediately.
func (s *Service) RevokeGrace() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.relayGrace = ""
	s.graceUntil = time.Time{}
	s.noteLocked("relay_revoke_grace", "old key revoked")
}

// BeginMasterReveal stores plaintext for a short window after re-auth (§12.4).
func (s *Service) BeginMasterReveal(plain string, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	s.revealValue = plain
	s.revealUntil = s.now().Add(ttl)
	s.noteLocked("master_reveal", "short-lived reveal started")
}

// TakeMasterReveal returns plaintext once if still within the reveal window.
func (s *Service) TakeMasterReveal() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revealValue == "" || !s.now().Before(s.revealUntil) {
		s.revealValue = ""
		s.revealUntil = time.Time{}
		return "", ErrReauthRequired
	}
	v := s.revealValue
	return v, nil
}

// ClearMasterReveal drops any cached plaintext.
func (s *Service) ClearMasterReveal() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revealValue = ""
	s.revealUntil = time.Time{}
}

func (s *Service) expireGraceLocked() {
	if !s.graceUntil.IsZero() && !s.now().Before(s.graceUntil) {
		s.relayGrace = ""
		s.graceUntil = time.Time{}
	}
}

func (s *Service) noteLocked(action, detail string) {
	ev := AuditEvent{
		At: s.now().UTC().Format(time.RFC3339Nano), Action: action, Detail: detail,
	}
	s.audit = append([]AuditEvent{ev}, s.audit...)
	if len(s.audit) > s.max {
		s.audit = s.audit[:s.max]
	}
}

func fingerprint(key string) string {
	if key == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}

func randomKey(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}
	return "rk_" + base64.RawURLEncoding.EncodeToString(buf), nil
}

// GenerateAdminPassword returns a high-entropy admin password (reset path).
func GenerateAdminPassword() (string, error) {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "ap_" + base64.RawURLEncoding.EncodeToString(buf), nil
}
