package acmeip

import (
	"errors"
	"strings"
	"testing"
)

type fakeBot struct {
	support                           bool
	supportErr, issueErr, validateErr error
	issued                            bool
}

func (f *fakeBot) SupportsIPCertificates() (bool, error) {
	return f.support, f.supportErr
}

func (f *fakeBot) IssueIP(ip string) (string, string, error) {
	if f.issueErr != nil {
		return "", "", f.issueErr
	}
	f.issued = true
	return "CERT:" + ip, "KEY:" + ip, nil
}

func (f *fakeBot) Validate(certPEM, keyPEM, expectIP string) error {
	if f.validateErr != nil {
		return f.validateErr
	}
	if !strings.Contains(certPEM, expectIP) {
		return errors.New("SAN missing IP")
	}
	return nil
}

func TestMachine_FailClosedOnIssueError(t *testing.T) {
	bot := &fakeBot{support: true, issueErr: errors.New("acme refused")}
	m := New(bot)
	if err := m.ConfirmIP("203.0.113.10"); err != nil {
		t.Fatal(err)
	}
	if err := m.StartChallenge(); err != nil {
		t.Fatal(err)
	}
	err := m.IssueAndValidate()
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("err=%v want ErrClosed", err)
	}
	if m.BusinessAllowed() {
		t.Fatal("business must stay closed")
	}
	if m.Phase() != PhaseFailed {
		t.Fatalf("phase=%s", m.Phase())
	}
}

func TestMachine_LiveAfterValidate(t *testing.T) {
	bot := &fakeBot{support: true}
	m := New(bot)
	_ = m.ConfirmIP("198.51.100.7")
	_ = m.StartChallenge()
	if err := m.IssueAndValidate(); err != nil {
		t.Fatal(err)
	}
	if !m.BusinessAllowed() || m.Phase() != PhaseLiveHTTPS {
		t.Fatalf("phase=%s allowed=%v", m.Phase(), m.BusinessAllowed())
	}
	if !bot.issued {
		t.Fatal("expected IssueIP call")
	}
}

func TestMachine_RejectsUnsupportedCertbot(t *testing.T) {
	m := New(&fakeBot{support: false})
	err := m.ConfirmIP("203.0.113.1")
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("err=%v", err)
	}
}
