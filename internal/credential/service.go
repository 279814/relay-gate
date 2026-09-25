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

// ErrRevealUnavailable means no Master-Key envelope is available for the
// current active Relay Key (§12.6 view-after-reauth).
var ErrRevealUnavailable = errors.New("当前 Relay Key 不可查看（缺少加密副本）")

// EnvelopeCipher seals high-entropy Relay Key plaintext under the Master Key
// (§12.6). Implemented by store.Cipher (EncryptEnvelope / DecryptEnvelope).
type EnvelopeCipher interface {
	EncryptEnvelope(plain string) (string, error)
	DecryptEnvelope(encoded string) (string, error)
}

// Service holds admin-facing credential operations (§12.3–12.6).
//
// Master Key plaintext lives only in Keyring; Relay key digests are held here
// for hot-path auth with optional grace overlap (§6.1 / §12.6). An envelope
// ciphertext of the active Relay Key is kept beside the digest so operators
// can view the current key after re-auth without rotating. Admin password
// verification is delegated to the caller (API compares against configured adminPW).
type Service struct {
	mu sync.Mutex

	revealUntil time.Time
	revealValue string

	envelope EnvelopeCipher

	// relayActive / relayGrace / relayAlso store irreversible SHA-256 digests
	// (hex), never raw key material. ValidRelayKey digests the presented key
	// before comparing against this snapshot.
	relayActive string
	// relayActiveEnc is the Master-Key envelope of the current active raw key
	// (§12.6). Never returned by Status / list snapshots.
	relayActiveEnc string
	relayGrace     string
	// relayAlso holds digests of extra bootstrap keys (comma-separated
	// RELAY_KEYS) that remain accepted alongside active/grace. Rotation moves
	// only relayActive into grace; also-keys are unchanged (§12.6 single
	// active + optional comma-separated extras from env).
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

// WithEnvelope wires Master-Key envelope crypto for Relay Key view-after-reauth.
func (s *Service) WithEnvelope(e EnvelopeCipher) *Service {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.envelope = e
	return s
}

// SetActiveRelayKey installs the primary relay key (bootstrap / env import).
func (s *Service) SetActiveRelayKey(key string) error {
	return s.SetActiveRelayKeys([]string{key})
}

// SetActiveRelayKeys installs the accepted relay key set from env / bootstrap.
// Raw keys are digested on insert; the first non-empty becomes active and the
// rest are also-keys. When an EnvelopeCipher is wired, the active raw key is
// sealed beside its digest (§12.6). Empty input clears the snapshot (all
// requests rejected).
func (s *Service) SetActiveRelayKeys(keys []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.relayActive = ""
	s.relayActiveEnc = ""
	s.relayAlso = nil
	s.relayGrace = ""
	s.graceUntil = time.Time{}
	var primaryPlain string
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		d := digestRelayKey(key)
		if s.relayActive == "" {
			s.relayActive = d
			primaryPlain = key
			continue
		}
		if s.relayAlso == nil {
			s.relayAlso = make(map[string]struct{})
		}
		s.relayAlso[d] = struct{}{}
	}
	if primaryPlain == "" || s.envelope == nil {
		return nil
	}
	enc, err := s.envelope.EncryptEnvelope(primaryPlain)
	if err != nil {
		s.relayActive = ""
		s.relayAlso = nil
		return fmt.Errorf("加密 Relay Key: %w", err)
	}
	s.relayActiveEnc = enc
	return nil
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

// ValidRelayKey reports whether key matches active, in-grace, or also-key
// digests. Empty and unconfigured snapshots always reject.
func (s *Service) ValidRelayKey(key string) bool {
	if key == "" {
		return false
	}
	d := digestRelayKey(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireGraceLocked()
	if d == s.relayActive || (s.relayGrace != "" && d == s.relayGrace) {
		return true
	}
	_, ok := s.relayAlso[d]
	return ok
}

// ActiveRelayKeys returns digests currently accepted for proxy auth (not raw keys).
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

// RotateRelayKey generates a new active key; old digest remains in grace.
// The returned newKey is plaintext for one-time admin display; the hot-path
// snapshot keeps only the digest, and (when EnvelopeCipher is wired) an
// envelope of the new active key for later re-auth reveal (§12.6).
func (s *Service) RotateRelayKey() (newKey string, graceSeconds int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	newKey, err = randomKey(32)
	if err != nil {
		return "", 0, err
	}
	enc := ""
	if s.envelope != nil {
		enc, err = s.envelope.EncryptEnvelope(newKey)
		if err != nil {
			return "", 0, fmt.Errorf("加密 Relay Key: %w", err)
		}
	}
	if s.relayActive != "" {
		s.relayGrace = s.relayActive
		s.graceUntil = s.now().Add(time.Duration(s.graceSec) * time.Second)
	}
	s.relayActive = digestRelayKey(newKey)
	s.relayActiveEnc = enc
	s.noteLocked("relay_rotate", "new active; old in grace")
	return newKey, s.graceSec, nil
}

// RevealActiveRelayKey decrypts the sealed active Relay Key (§12.6).
// Callers must re-check the admin password and set Cache-Control: no-store.
// The digest snapshot remains the auth path; this does not rotate the key.
func (s *Service) RevealActiveRelayKey() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.envelope == nil || s.relayActiveEnc == "" {
		return "", ErrRevealUnavailable
	}
	plain, err := s.envelope.DecryptEnvelope(s.relayActiveEnc)
	if err != nil {
		return "", fmt.Errorf("解密 Relay Key: %w", err)
	}
	if digestRelayKey(plain) != s.relayActive {
		return "", errors.New("Relay Key 密文与摘要不一致")
	}
	s.noteLocked("relay_reveal", "active key revealed after reauth")
	return plain, nil
}

// ResealActiveRelayEnvelope re-encrypts the in-memory Relay Key under the
// current EnvelopeCipher active master (§12.7 after ActivateMaster). No-op
// when no envelope is wired or no sealed copy exists.
func (s *Service) ResealActiveRelayEnvelope() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.envelope == nil || s.relayActiveEnc == "" {
		return nil
	}
	plain, err := s.envelope.DecryptEnvelope(s.relayActiveEnc)
	if err != nil {
		return fmt.Errorf("解密 Relay Key: %w", err)
	}
	if digestRelayKey(plain) != s.relayActive {
		return errors.New("Relay Key 密文与摘要不一致")
	}
	enc, err := s.envelope.EncryptEnvelope(plain)
	if err != nil {
		return fmt.Errorf("加密 Relay Key: %w", err)
	}
	s.relayActiveEnc = enc
	s.noteLocked("relay_reseal", "envelope rewrapped under new master")
	return nil
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

// digestRelayKey returns the irreversible SHA-256 hex digest used in the
// hot-path auth snapshot (§6.1 / §12.6). No pepper: digest is hash(raw key).
func digestRelayKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// fingerprint returns the UI-facing short id from a stored digest (first 8 bytes).
func fingerprint(digest string) string {
	if digest == "" {
		return ""
	}
	if len(digest) >= 16 {
		return digest[:16]
	}
	return digest
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
