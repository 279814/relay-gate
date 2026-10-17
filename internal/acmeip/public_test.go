package acmeip

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type idleProcess struct{ done chan error }

func (p *idleProcess) Wait() error { return <-p.done }
func (p *idleProcess) Kill() error {
	select {
	case p.done <- nil:
	default:
	}
	return nil
}

func publicFixture(t *testing.T) (*PublicManager, *fakeCommands, *x509.CertPool) {
	t.Helper()
	root := t.TempDir()
	webroot := t.TempDir()
	cert, key, roots := testCertificate(t, "8.8.8.8", 160*time.Hour)
	runner := &fakeCommands{help: "--webroot --webroot-path --ip-address --required-profile"}
	runner.onIssue = func() error {
		folder := filepath.Join(root, "acme", "config", "live", "relay-gate-public-ip")
		if err := os.MkdirAll(folder, 0700); err != nil {
			return err
		}
		for source, name := range map[string]string{cert: "fullchain.pem", key: "privkey.pem"} {
			raw, err := os.ReadFile(source)
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(folder, name), raw, 0600); err != nil {
				return err
			}
		}
		return nil
	}
	m, err := NewPublicManager(PublicOptions{IP: "8.8.8.8", StateDir: root, Webroot: webroot, Upstream: "http://172.30.187.3:18787", Runner: runner, Roots: roots,
		StartNginx:     func(string) (ManagedProcess, error) { return &idleProcess{done: make(chan error, 1)}, nil },
		ChallengeProbe: func(context.Context, string, string) error { return nil },
		TLSProbe:       func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		defer cancel()
		_ = m.Close(stop)
	})
	return m, runner, roots
}

func TestPublicBootstrapFailureNeverPublishesBusiness(t *testing.T) {
	m, runner, _ := publicFixture(t)
	runner.onIssue = func() error { return os.ErrPermission }
	if err := m.Bootstrap(context.Background()); err == nil {
		t.Fatal("issuance failure accepted")
	}
	state := m.Snapshot()
	if state.BusinessAllowed || state.Phase != "failed" {
		t.Fatalf("business opened after failure: %+v", state)
	}
	config, err := os.ReadFile(m.configPath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(config), "proxy_pass") || strings.Contains(string(config), "listen 443") || !strings.Contains(string(config), "return 503") {
		t.Fatal("bootstrap exposed admin/models before valid TLS")
	}
	persisted, err := ReadPublicState(filepath.Join(m.options.StateDir, "status", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Phase != "failed" {
		t.Fatal("failure state not persisted")
	}
}

func TestPublicNginxCandidateFailureIsDurablyReported(t *testing.T) {
	m, runner, _ := publicFixture(t)
	runner.failCandidate = true
	if err := m.Bootstrap(context.Background()); err == nil {
		t.Fatal("invalid candidate configuration accepted")
	}
	persisted, err := ReadPublicState(m.statePath())
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Phase != "failed" || persisted.LastError == "" || persisted.BusinessAllowed {
		t.Fatalf("candidate failure left misleading operation state: %+v", persisted)
	}
}

func TestPublicBootstrapAndRenewalPublishOnlyValidatedCertificates(t *testing.T) {
	m, runner, _ := publicFixture(t)
	if err := m.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := m.Snapshot()
	if !before.BusinessAllowed || before.Phase != "live_https" || before.CertificateFingerprint == "" {
		t.Fatalf("TLS was not published: %+v", before)
	}
	config, err := os.ReadFile(m.configPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"listen 443 ssl", "return 308 https://", "proxy_buffering off", "proxy_request_buffering off", "proxy_read_timeout 35m", "proxy_send_timeout 35m", "proxy_set_header X-Forwarded-For $remote_addr", "proxy_set_header X-Forwarded-Proto https"} {
		if !strings.Contains(string(config), value) {
			t.Fatalf("missing edge invariant: %s", value)
		}
	}
	runner.failRenew = true
	if err := m.RenewOnce(context.Background()); err == nil {
		t.Fatal("renew error hidden")
	}
	after := m.Snapshot()
	if !after.BusinessAllowed || after.CertificateFingerprint != before.CertificateFingerprint || after.NotAfter != before.NotAfter || after.LastError == "" {
		t.Fatal("renew failure discarded live certificate or observability")
	}
	persisted, err := ReadPublicState(filepath.Join(m.options.StateDir, "status", "state.json"))
	if err != nil || persisted.RenewAttempts != 1 {
		t.Fatalf("renew state not durable: %v", err)
	}
}

func TestPublicRenewalReloadFailureRestoresPreviousConfig(t *testing.T) {
	m, runner, _ := publicFixture(t)
	if err := m.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := m.Snapshot()
	oldConfig, _ := os.ReadFile(m.configPath())
	cert, key, newRoots := testCertificate(t, "8.8.8.8", 160*time.Hour)
	// A different root is not trusted: validation fails before reload.
	runner.onIssue = func() error {
		paths := m.bot.paths()
		for source, target := range map[string]string{cert: paths.Certificate, key: paths.Key} {
			raw, _ := os.ReadFile(source)
			if err := os.WriteFile(target, raw, 0600); err != nil {
				return err
			}
		}
		return nil
	}
	if err := m.RenewOnce(context.Background()); err == nil {
		t.Fatal("untrusted replacement accepted")
	}
	if m.Snapshot().CertificateFingerprint != before.CertificateFingerprint {
		t.Fatal("untrusted replacement displaced old cert")
	}
	// Reload failure is covered using the same valid, newly reissued fixture.
	runner.failReload = true
	m.options.Roots = newRoots
	if err := m.RenewOnce(context.Background()); err == nil {
		t.Fatal("failed candidate accepted")
	}
	current, _ := os.ReadFile(m.configPath())
	if string(current) != string(oldConfig) {
		t.Fatal("failed renewal changed the working nginx config")
	}
	if !m.Snapshot().ReloadFailedKeepOld || !m.Snapshot().BusinessAllowed {
		t.Fatal("reload failure was not reported as keeping the old certificate")
	}
}

func TestPublicExpiredCertificateClosesBusinessButKeepsChallenge(t *testing.T) {
	m, _, _ := publicFixture(t)
	if err := m.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(200 * time.Hour)
	m.options.Now = func() time.Time { return future }
	if err := m.CheckCurrent(context.Background()); err == nil {
		t.Fatal("expiration not reported")
	}
	if m.Snapshot().BusinessAllowed || m.Snapshot().Phase != "expired" {
		t.Fatal("expired certificate continued business")
	}
	config, _ := os.ReadFile(m.configPath())
	if strings.Contains(string(config), "proxy_pass") || !strings.Contains(string(config), "return 503") {
		t.Fatal("expired TLS fell back to plaintext proxy")
	}
}

func TestPublicRunClosesAtExpiryBeforeHourlyCheck(t *testing.T) {
	m, _, _ := publicFixture(t)
	if err := m.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	expires, err := time.Parse(time.RFC3339, m.Snapshot().NotAfter)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	m.options.Now = func() time.Time { return expires.Add(-100 * time.Millisecond).Add(time.Since(started)) }
	m.options.CheckInterval = time.Hour
	m.options.RenewInterval = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	process := m.process
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	state := m.Snapshot()
	for state.Phase != "expired" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
		state = m.Snapshot()
	}
	// End the fake child before cancelling so the graceful-shutdown wait exits.
	_ = process.Kill()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("manager did not stop")
	}
	if state.Phase != "expired" || state.BusinessAllowed {
		t.Fatalf("expiry waited for hourly check: %+v", state)
	}
}
