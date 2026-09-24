package acmeip

import (
	"errors"
	"fmt"
	"sync"
)

// Phase is the public-IP HTTPS startup state machine (§12.2).
type Phase string

const (
	PhaseIdle          Phase = "idle"
	PhaseConfirmIP     Phase = "confirm_ip"
	PhaseACMEChallenge Phase = "acme_challenge" // temp nginx: only ACME path
	PhaseIssueCert     Phase = "issue_cert"
	PhaseValidateCert  Phase = "validate_cert"
	PhaseLiveHTTPS     Phase = "live_https"
	PhaseFailed        Phase = "failed"
)

// ErrClosed means business must stay unreachable (no plaintext HTTP fallback).
var ErrClosed = errors.New("https bootstrap failed closed")

// Certbot is the Certbot 5.4+ capability surface; tests inject fakes.
type Certbot interface {
	SupportsIPCertificates() (bool, error)
	IssueIP(ip string) (certPEM, keyPEM string, err error)
	Validate(certPEM, keyPEM, expectIP string) error
}

// Machine is the fail-closed public IP HTTPS bootstrap (§12.2).
//
// It never claims a public certificate was issued unless Certbot.IssueIP
// succeeds and Validate passes. Documented install is HTTP IP:port (README);
// this machine is not required to install or log in.
type Machine struct {
	mu     sync.Mutex
	phase  Phase
	ip     string
	reason string
	bot    Certbot
}

// New constructs a machine in idle.
func New(bot Certbot) *Machine {
	return &Machine{phase: PhaseIdle, bot: bot}
}

// Phase returns the current phase.
func (m *Machine) Phase() Phase {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.phase
}

// Snapshot is a JSON-friendly status.
func (m *Machine) Snapshot() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	return map[string]any{
		"phase":  m.phase,
		"ip":     m.ip,
		"reason": m.reason,
	}
}

// ConfirmIP records the operator-confirmed public IP and advances.
func (m *Machine) ConfirmIP(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ip == "" {
		return fmt.Errorf("ip 不能为空")
	}
	if m.bot != nil {
		ok, err := m.bot.SupportsIPCertificates()
		if err != nil {
			return m.failLocked(err)
		}
		if !ok {
			return m.failLocked(fmt.Errorf("Certbot 不支持 IP 证书（需要 5.4+）"))
		}
	}
	m.ip = ip
	m.phase = PhaseConfirmIP
	m.reason = ""
	return nil
}

// StartChallenge enters ACME-only temp nginx phase (no admin/model exposure).
func (m *Machine) StartChallenge() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.phase != PhaseConfirmIP {
		return fmt.Errorf("需要先 ConfirmIP，当前 %s", m.phase)
	}
	m.phase = PhaseACMEChallenge
	return nil
}

// IssueAndValidate requests a certificate and validates SAN/chain/permissions.
// On any failure the machine stays failed-closed (no HTTP fallback).
func (m *Machine) IssueAndValidate() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.phase != PhaseACMEChallenge && m.phase != PhaseIssueCert {
		return fmt.Errorf("需要 ACME challenge 阶段，当前 %s", m.phase)
	}
	if m.bot == nil {
		return m.failLocked(fmt.Errorf("未配置 Certbot"))
	}
	m.phase = PhaseIssueCert
	cert, key, err := m.bot.IssueIP(m.ip)
	if err != nil {
		return m.failLocked(err)
	}
	m.phase = PhaseValidateCert
	if err := m.bot.Validate(cert, key, m.ip); err != nil {
		return m.failLocked(err)
	}
	m.phase = PhaseLiveHTTPS
	m.reason = ""
	return nil
}

// BusinessAllowed is true only after live HTTPS is up.
func (m *Machine) BusinessAllowed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.phase == PhaseLiveHTTPS
}

func (m *Machine) failLocked(err error) error {
	m.phase = PhaseFailed
	m.reason = err.Error()
	return fmt.Errorf("%w: %v", ErrClosed, err)
}
