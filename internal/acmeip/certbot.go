package acmeip

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const letsEncryptDirectory = "https://acme-v02.api.letsencrypt.org/directory"

type CommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type OSCommands struct{}

// Certbot output is private diagnostic material. Only help/plugin discovery
// consumes it; persistent status records action categories rather than output.
func (OSCommands) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var output boundedOutput
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s command failed", filepath.Base(name))
	}
	return output.data, nil
}

type boundedOutput struct{ data []byte }

func (w *boundedOutput) Write(value []byte) (int, error) {
	n := len(value)
	remaining := (256 << 10) - len(w.data)
	if remaining > 0 {
		w.data = append(w.data, value[:min(remaining, n)]...)
	}
	return n, nil
}

type CertificatePaths struct{ Certificate, Key string }

// ProcessCertbot uses webroot HTTP-01 and persists Certbot's account, lineage
// and renewal configuration. No shell interpolation or webserver installer.
type ProcessCertbot struct {
	Binary      string
	StateDir    string
	Webroot     string
	IP          string
	Runner      CommandRunner
	profileFlag string
}

func (c *ProcessCertbot) baseArgs() []string {
	return []string{"--config-dir", filepath.Join(c.StateDir, "acme", "config"), "--work-dir", filepath.Join(c.StateDir, "acme", "work"), "--logs-dir", filepath.Join(c.StateDir, "acme", "logs")}
}

func (c *ProcessCertbot) paths() CertificatePaths {
	root := filepath.Join(c.StateDir, "acme", "config", "live", "relay-gate-public-ip")
	return CertificatePaths{Certificate: filepath.Join(root, "fullchain.pem"), Key: filepath.Join(root, "privkey.pem")}
}

func exactHelpFlag(help, flag string) bool {
	for _, word := range strings.Fields(help) {
		if strings.TrimRight(word, ",") == flag {
			return true
		}
	}
	return false
}

func (c *ProcessCertbot) Probe(ctx context.Context) error {
	if c.Runner == nil {
		c.Runner = OSCommands{}
	}
	if c.Binary == "" {
		c.Binary = "certbot"
	}
	for _, dir := range []string{filepath.Join(c.StateDir, "acme", "config"), filepath.Join(c.StateDir, "acme", "work"), filepath.Join(c.StateDir, "acme", "logs")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	help, err := c.Runner.Run(ctx, c.Binary, "--help", "all")
	if err != nil {
		return errors.New("Certbot 能力探测失败；需要支持 IP/webroot/profile 的版本")
	}
	for _, flag := range []string{"--ip-address", "--webroot", "--webroot-path"} {
		if !exactHelpFlag(string(help), flag) {
			return fmt.Errorf("Certbot 未声明 %s 支持", flag)
		}
	}
	switch {
	case exactHelpFlag(string(help), "--required-profile"):
		c.profileFlag = "--required-profile"
	case exactHelpFlag(string(help), "--preferred-profile"):
		c.profileFlag = "--preferred-profile"
	default:
		return errors.New("Certbot 不支持 shortlived profile 选择")
	}
	args := append([]string{"plugins", "--authenticators", "--text"}, c.baseArgs()...)
	plugins, err := c.Runner.Run(ctx, c.Binary, args...)
	if err != nil || !strings.Contains(string(plugins), "webroot") {
		return errors.New("Certbot webroot authenticator 不可用")
	}
	return nil
}

func (c *ProcessCertbot) Issue(ctx context.Context) (CertificatePaths, error) {
	if c.profileFlag == "" {
		if err := c.Probe(ctx); err != nil {
			return CertificatePaths{}, err
		}
	}
	args := []string{"certonly", "--non-interactive", "--agree-tos", "--register-unsafely-without-email", "--webroot", "--webroot-path", c.Webroot, "--ip-address", c.IP, "--cert-name", "relay-gate-public-ip", c.profileFlag, "shortlived", "--preferred-challenges", "http", "--no-directory-hooks", "--server", letsEncryptDirectory}
	args = append(args, c.baseArgs()...)
	if _, err := c.Runner.Run(ctx, c.Binary, args...); err != nil {
		return CertificatePaths{}, errors.New("IP 证书签发失败；检查公网 80/443、确认目标 IP 与 Certbot 私有日志")
	}
	return c.paths(), nil
}

func (c *ProcessCertbot) Renew(ctx context.Context) (CertificatePaths, error) {
	if err := c.Probe(ctx); err != nil {
		return CertificatePaths{}, err
	}
	args := append([]string{"renew", "--non-interactive", "--cert-name", "relay-gate-public-ip", "--no-directory-hooks"}, c.baseArgs()...)
	if _, err := c.Runner.Run(ctx, c.Binary, args...); err != nil {
		return CertificatePaths{}, errors.New("IP 证书续期失败；当前有效证书保持服务")
	}
	return c.paths(), nil
}
