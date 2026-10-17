package acmeip

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ManagedProcess interface {
	Wait() error
	Kill() error
}

type nginxProcess struct{ command *exec.Cmd }

func (p *nginxProcess) Wait() error { return p.command.Wait() }
func (p *nginxProcess) Kill() error { return killNginxProcess(p.command) }

type PublicOptions struct {
	IP, StateDir, Webroot, Upstream string
	CertbotBinary, NginxBinary      string
	ChallengeAddress, HTTPSAddress  string
	Runner                          CommandRunner
	Output                          io.Writer
	Roots                           *x509.CertPool // local-CA tests only; production CLI uses system roots
	Now                             func() time.Time
	RenewInterval, CheckInterval    time.Duration
	RenewTrigger                    <-chan struct{}
	StartNginx                      func(string) (ManagedProcess, error)
	ChallengeProbe                  func(context.Context, string, string) error
	TLSProbe                        func(context.Context, string) error
}

// PublicManager is the production edge lifecycle. Run serializes certificate
// operations; the short mutex protects snapshots only, never process/network I/O.
// It has no dependency on gateway admission/paused state or its credentials.
type PublicManager struct {
	options     PublicOptions
	bot         *ProcessCertbot
	mu          sync.Mutex
	state       PublicState
	process     ManagedProcess
	processDone chan error
}

func NewPublicManager(options PublicOptions) (*PublicManager, error) {
	ip, err := ParsePublicIP(options.IP)
	if err != nil {
		return nil, err
	}
	options.IP = ip.String()
	for _, path := range []string{options.StateDir, options.Webroot} {
		if !filepath.IsAbs(path) || strings.ContainsAny(path, "\r\n\x00") {
			return nil, errors.New("公网边缘目录必须是安全绝对路径")
		}
	}
	upstream, err := url.Parse(options.Upstream)
	if err != nil || upstream.Scheme != "http" || upstream.User != nil || upstream.RawQuery != "" || upstream.Fragment != "" || upstream.Path != "" {
		return nil, errors.New("公网边缘上游必须是内部 HTTP 地址")
	}
	upstreamIP, err := netip.ParseAddr(upstream.Hostname())
	port, portErr := strconv.Atoi(upstream.Port())
	if err != nil || (!upstreamIP.IsPrivate() && !upstreamIP.IsLoopback()) || portErr != nil || port < 1 || port > 65535 {
		return nil, errors.New("公网边缘上游必须使用受控内部 IP/端口")
	}
	if options.Runner == nil {
		options.Runner = OSCommands{}
	}
	if options.Output == nil {
		options.Output = io.Discard
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.NginxBinary == "" {
		options.NginxBinary = "nginx"
	}
	if options.CertbotBinary == "" {
		options.CertbotBinary = "certbot"
	}
	if options.HTTPSAddress == "" {
		options.HTTPSAddress = "127.0.0.1:443"
	}
	if options.ChallengeAddress == "" {
		options.ChallengeAddress = net.JoinHostPort(options.IP, "80")
	}
	if options.RenewInterval <= 0 {
		options.RenewInterval = 12 * time.Hour
	}
	if options.CheckInterval <= 0 {
		options.CheckInterval = time.Hour
	}
	for _, dir := range []string{options.StateDir, filepath.Join(options.StateDir, "nginx"), filepath.Join(options.StateDir, "tls")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
		if err := os.Chmod(dir, 0700); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(options.Webroot, 0755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(options.StateDir, "status"), 0755); err != nil {
		return nil, err
	}
	m := &PublicManager{options: options, state: PublicState{FormatVersion: 1, IP: options.IP, Phase: "acme_only"}}
	if saved, err := ReadPublicState(m.statePath()); err == nil {
		if saved.IP != options.IP {
			return nil, errors.New("持久 HTTPS 状态属于另一个 IP；请使用独立状态目录")
		}
		m.state = saved
		m.state.BusinessAllowed = false
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	m.bot = &ProcessCertbot{Binary: options.CertbotBinary, StateDir: options.StateDir, Webroot: options.Webroot, IP: options.IP, Runner: options.Runner}
	return m, nil
}

func (m *PublicManager) configPath() string {
	return filepath.Join(m.options.StateDir, "nginx", "nginx.conf")
}
func (m *PublicManager) statePath() string {
	return filepath.Join(m.options.StateDir, "status", "state.json")
}
func (m *PublicManager) now() time.Time { return m.options.Now().UTC() }

func (m *PublicManager) Snapshot() PublicState {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.state
	if expiry, err := time.Parse(time.RFC3339, state.NotAfter); err == nil {
		state.RemainingHours = expiry.Sub(m.now()).Hours()
		state.AlertLowValidity = state.RemainingHours <= DefaultLowValidity.Hours()
		if !m.now().Before(expiry) {
			state.BusinessAllowed = false
		}
	}
	return state
}

func (m *PublicManager) save(change func(*PublicState)) error {
	m.mu.Lock()
	change(&m.state)
	if len(m.state.LastError) > 512 {
		m.state.LastError = m.state.LastError[:512]
	}
	m.mu.Unlock()
	state := m.Snapshot()
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(m.statePath(), append(raw, '\n'), 0644)
}

func (m *PublicManager) fail(err error, reload bool) error {
	old := m.Snapshot()
	keep := old.BusinessAllowed && m.process != nil
	_ = m.save(func(s *PublicState) {
		s.LastError = err.Error()
		s.ReloadFailedKeepOld = reload && keep
		s.BusinessAllowed = keep
		if !keep {
			s.Phase = "failed"
			if expiry, e := time.Parse(time.RFC3339, s.NotAfter); e == nil && !m.now().Before(expiry) {
				s.Phase = "expired"
			}
		}
	})
	fmt.Fprintln(m.options.Output, "public_https_alert:", err.Error())
	return err
}

func (m *PublicManager) nginx(ctx context.Context, args ...string) error {
	args = append([]string{"-c", m.configPath()}, args...)
	_, err := m.options.Runner.Run(ctx, m.options.NginxBinary, args...)
	return err
}

func (m *PublicManager) start(config string) error {
	if m.process != nil {
		return nil
	}
	var process ManagedProcess
	var err error
	if m.options.StartNginx != nil {
		process, err = m.options.StartNginx(config)
	} else {
		cmd := exec.Command(m.options.NginxBinary, "-c", config, "-g", "daemon off;")
		configureNginxProcess(cmd)
		cmd.Stdout = m.options.Output
		cmd.Stderr = m.options.Output
		err = cmd.Start()
		if err == nil {
			process = &nginxProcess{command: cmd}
		}
	}
	if err != nil {
		return errors.New("临时 Nginx 无法启动；业务保持关闭")
	}
	m.process = process
	m.processDone = make(chan error, 1)
	done := m.processDone
	go func() { done <- process.Wait() }()
	return nil
}

func (m *PublicManager) ensureChallenge(ctx context.Context) error {
	if err := writeAtomic(m.configPath(), []byte(renderNginx(m.options, nil)), 0600); err != nil {
		return err
	}
	if err := m.nginx(ctx, "-t"); err != nil {
		return errors.New("ACME-only Nginx 配置测试失败")
	}
	if m.process == nil {
		if err := m.start(m.configPath()); err != nil {
			return err
		}
	} else if err := m.nginx(ctx, "-s", "reload"); err != nil {
		return errors.New("无法关闭现有 HTTPS 业务监听")
	}
	return m.save(func(s *PublicState) { s.Phase = "acme_only"; s.BusinessAllowed = false })
}

func (m *PublicManager) challenge(ctx context.Context) error {
	if m.options.ChallengeProbe != nil {
		return m.options.ChallengeProbe(ctx, m.options.IP, m.options.Webroot)
	}
	deadline := time.Now().Add(8 * time.Second)
	var last error
	for {
		last = probeChallenge(ctx, m.options.Webroot, m.options.IP, m.options.ChallengeAddress)
		if last == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return last
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (m *PublicManager) tlsProbe(ctx context.Context, fingerprint string) error {
	if m.options.TLSProbe != nil {
		return m.options.TLSProbe(ctx, fingerprint)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := probeHTTPS(ctx, m.options.HTTPSAddress, m.options.IP, fingerprint, m.options.Roots)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (m *PublicManager) generationPaths(generation string) CertificatePaths {
	root := filepath.Join(m.options.StateDir, "tls", generation)
	return CertificatePaths{Certificate: filepath.Join(root, "fullchain.pem"), Key: filepath.Join(root, "privkey.pem")}
}

func (m *PublicManager) candidatePaths(paths CertificatePaths) error {
	root, err := filepath.Abs(filepath.Join(m.options.StateDir, "acme", "config"))
	if err != nil {
		return err
	}
	for _, path := range []string{paths.Certificate, paths.Key} {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, resolved)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return errors.New("Certbot 输出不在受控持久目录中")
		}
	}
	return nil
}

func (m *PublicManager) rollback(ctx context.Context, config []byte, before PublicState) error {
	err := writeAtomic(m.configPath(), config, 0600)
	if err == nil {
		err = m.nginx(ctx, "-s", "reload")
	}
	if err == nil && before.BusinessAllowed {
		err = m.tlsProbe(ctx, before.CertificateFingerprint)
	}
	if err != nil && m.process != nil {
		_ = m.process.Kill()
		m.process = nil
	}
	return err
}

func (m *PublicManager) publish(ctx context.Context, paths CertificatePaths, info CertificateInfo) (result error) {
	reloadFailure := false
	defer func() {
		if result != nil {
			_ = m.fail(result, reloadFailure)
		}
	}()
	before := m.Snapshot()
	previousConfig, err := os.ReadFile(m.configPath())
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp(filepath.Join(m.options.StateDir, "tls"), info.Fingerprint[:16]+"-")
	if err != nil {
		return err
	}
	generation := filepath.Base(dir)
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(dir)
		}
	}()
	installed := m.generationPaths(generation)
	for source, target := range map[string]string{paths.Certificate: installed.Certificate, paths.Key: installed.Key} {
		raw, err := readCertificateFile(source, 1<<20)
		if err != nil {
			return err
		}
		if err := writeAtomic(target, raw, 0600); err != nil {
			return err
		}
	}
	config := []byte(renderNginx(m.options, &installed))
	candidate := filepath.Join(m.options.StateDir, "nginx", "candidate.conf")
	if err := writeAtomic(candidate, config, 0600); err != nil {
		return err
	}
	defer os.Remove(candidate)
	if _, err := m.options.Runner.Run(ctx, m.options.NginxBinary, "-c", candidate, "-t"); err != nil {
		return errors.New("已验证证书的 Nginx 配置测试失败")
	}
	if err := writeAtomic(m.configPath(), config, 0600); err != nil {
		return err
	}
	if err := m.nginx(ctx, "-s", "reload"); err != nil {
		reloadFailure = true
		restoreErr := writeAtomic(m.configPath(), previousConfig, 0600)
		// A failed signal command normally leaves old workers untouched. Prove
		// that before claiming keep-old; otherwise reload the old config or close.
		if restoreErr == nil && before.BusinessAllowed {
			restoreErr = m.tlsProbe(ctx, before.CertificateFingerprint)
		} else if restoreErr == nil {
			restoreErr = errors.New("initial TLS switch was not confirmed")
		}
		if restoreErr != nil {
			_ = m.rollback(ctx, previousConfig, before)
		}
		return errors.New("Nginx reload 失败，已保留旧证书或关闭业务")
	}
	if err := m.tlsProbe(ctx, info.Fingerprint); err != nil {
		reloadFailure = true
		_ = m.rollback(ctx, previousConfig, before)
		return errors.New("Nginx 未呈现已验证的新证书，已恢复旧配置或关闭业务")
	}
	if err := m.save(func(s *PublicState) {
		s.Phase = "live_https"
		s.BusinessAllowed = true
		s.CurrentGeneration = generation
		s.NotAfter = info.NotAfter.UTC().Format(time.RFC3339)
		s.CertificateFingerprint = info.Fingerprint
		s.LastError = ""
		s.ReloadFailedKeepOld = false
		s.LastSuccessAt = m.now().Format(time.RFC3339)
		s.LastReloadAt = s.LastSuccessAt
	}); err != nil {
		reloadFailure = true
		_ = m.rollback(ctx, previousConfig, before)
		m.mu.Lock()
		m.state = before
		m.mu.Unlock()
		return errors.New("HTTPS 持久状态写入失败；未确认发布成功")
	}
	published = true
	// Once both Nginx and durable state name this generation, superseded private
	// keys are no longer needed for rollback or restart.
	if before.CurrentGeneration != "" && before.CurrentGeneration != generation {
		old := filepath.Join(m.options.StateDir, "tls", before.CurrentGeneration)
		if filepath.Dir(old) == filepath.Join(m.options.StateDir, "tls") {
			_ = os.RemoveAll(old)
		}
	}
	return nil
}

func (m *PublicManager) Bootstrap(ctx context.Context) error {
	state := m.Snapshot()
	if state.CurrentGeneration != "" {
		paths := m.generationPaths(state.CurrentGeneration)
		if info, err := ValidateCertificateFiles(paths.Certificate, paths.Key, m.options.IP, m.options.Roots, m.now(), 0); err == nil {
			if err := writeAtomic(m.configPath(), []byte(renderNginx(m.options, &paths)), 0600); err != nil {
				return m.fail(err, false)
			}
			if err := m.nginx(ctx, "-t"); err != nil {
				return m.fail(errors.New("恢复正式 Nginx 配置失败"), false)
			}
			if err := m.start(m.configPath()); err != nil {
				return m.fail(err, false)
			}
			if err := m.tlsProbe(ctx, info.Fingerprint); err != nil {
				if m.ensureChallenge(ctx) != nil && m.process != nil {
					_ = m.process.Kill()
					m.process = nil
				}
				return m.fail(err, false)
			}
			return m.save(func(s *PublicState) {
				s.Phase = "live_https"
				s.BusinessAllowed = true
				s.NotAfter = info.NotAfter.UTC().Format(time.RFC3339)
				s.CertificateFingerprint = info.Fingerprint
				s.LastReloadAt = m.now().Format(time.RFC3339)
				s.LastError = ""
			})
		}
	}
	if err := m.ensureChallenge(ctx); err != nil {
		return m.fail(err, false)
	}
	if err := m.challenge(ctx); err != nil {
		return m.fail(err, false)
	}
	if err := m.save(func(s *PublicState) {
		s.Phase = "issuing"
		s.LastAttemptAt = m.now().Format(time.RFC3339)
		s.LastError = ""
	}); err != nil {
		return m.fail(err, false)
	}
	operation, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	paths, err := m.bot.Issue(operation)
	if err != nil {
		return m.fail(err, false)
	}
	if err := m.candidatePaths(paths); err != nil {
		return m.fail(errors.New("Certbot 证书路径验证失败"), false)
	}
	if err := m.save(func(s *PublicState) { s.Phase = "validating" }); err != nil {
		return m.fail(err, false)
	}
	info, err := ValidateCertificateFiles(paths.Certificate, paths.Key, m.options.IP, m.options.Roots, m.now(), 24*time.Hour)
	if err != nil {
		return m.fail(err, false)
	}
	if err := m.publish(ctx, paths, info); err != nil {
		return err
	}
	return nil
}

func (m *PublicManager) RenewOnce(ctx context.Context) error {
	if !m.Snapshot().BusinessAllowed {
		return m.Bootstrap(ctx)
	}
	if err := m.save(func(s *PublicState) {
		s.RenewAttempts++
		s.LastAttemptAt = m.now().Format(time.RFC3339)
		s.ReloadFailedKeepOld = false
	}); err != nil {
		return err
	}
	deadline := m.now().Add(5 * time.Minute)
	if expiry, err := time.Parse(time.RFC3339, m.Snapshot().NotAfter); err == nil && expiry.Before(deadline) {
		deadline = expiry
	}
	// Never let a stalled ACME process postpone closing an expired listener.
	operation, cancel := context.WithTimeout(ctx, deadline.Sub(m.now()))
	defer cancel()
	paths, err := m.bot.Renew(operation)
	if err != nil {
		return m.fail(err, false)
	}
	if err := m.candidatePaths(paths); err != nil {
		return m.fail(errors.New("续期证书路径验证失败"), false)
	}
	info, err := ValidateCertificateFiles(paths.Certificate, paths.Key, m.options.IP, m.options.Roots, m.now(), 24*time.Hour)
	if err != nil {
		return m.fail(err, false)
	}
	if info.Fingerprint == m.Snapshot().CertificateFingerprint {
		return m.save(func(s *PublicState) { s.LastError = "" })
	}
	if err := m.publish(operation, paths, info); err != nil {
		return err
	}
	return m.save(func(s *PublicState) { s.RenewSuccesses++ })
}

func (m *PublicManager) CheckCurrent(ctx context.Context) error {
	state := m.Snapshot()
	if state.NotAfter == "" {
		return nil
	}
	expires, err := time.Parse(time.RFC3339, state.NotAfter)
	if err != nil {
		return m.fail(errors.New("持久证书效期无效"), false)
	}
	if !m.now().Before(expires) {
		if err := m.ensureChallenge(ctx); err != nil {
			if m.process != nil {
				_ = m.process.Kill()
				m.process = nil
			}
		}
		_ = m.save(func(s *PublicState) {
			s.Phase = "expired"
			s.BusinessAllowed = false
			s.LastError = "当前证书已过期，业务关闭；ACME 路径保留"
		})
		return errors.New("当前 IP 证书已过期")
	}
	if err := m.save(func(*PublicState) {}); err != nil {
		return err
	}
	if state.AlertLowValidity {
		fmt.Fprintln(m.options.Output, "public_https_alert: IP 证书剩余效期低于 48 小时")
	}
	return nil
}

func (m *PublicManager) Close(ctx context.Context) error {
	if m.process == nil {
		return nil
	}
	_ = m.nginx(ctx, "-s", "quit")
	select {
	case <-m.processDone:
		m.process = nil
		return nil
	case <-ctx.Done():
		_ = m.process.Kill()
		m.process = nil
		return ctx.Err()
	}
}

func (m *PublicManager) Run(ctx context.Context) error {
	initialErr := m.Bootstrap(ctx)
	if m.process == nil {
		return initialErr
	}
	defer func() {
		stop, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		_ = m.Close(stop)
	}()
	renew := time.NewTicker(m.options.RenewInterval)
	defer renew.Stop()
	check := time.NewTicker(m.options.CheckInterval)
	defer check.Stop()
	for {
		var expires <-chan time.Time
		var expiryTimer *time.Timer
		state := m.Snapshot()
		if state.Phase == "live_https" {
			if expiry, err := time.Parse(time.RFC3339, state.NotAfter); err == nil {
				expiryTimer = time.NewTimer(max(0, expiry.Sub(m.now())))
				expires = expiryTimer.C
			}
		}
		select {
		case <-ctx.Done():
			if expiryTimer != nil {
				expiryTimer.Stop()
			}
			return nil
		case <-m.processDone:
			if expiryTimer != nil {
				expiryTimer.Stop()
			}
			m.process = nil
			return m.fail(errors.New("Nginx 工作进程已退出；业务关闭"), false)
		case <-expires:
			_ = m.CheckCurrent(ctx)
		case <-renew.C:
			_ = m.RenewOnce(ctx)
		case <-check.C:
			_ = m.CheckCurrent(ctx)
		case <-m.options.RenewTrigger:
			_ = m.RenewOnce(ctx)
		}
		if expiryTimer != nil {
			expiryTimer.Stop()
		}
	}
}
