package acmeip

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The test executable doubles as a tiny external Certbot/Nginx process. This
// exercises exec.CommandContext and real PEM files on Windows as well as Linux;
// it never executes a shell or contacts a public IP/CA.
func TestMain(m *testing.M) {
	if root := os.Getenv("RELAY_ACME_PROCESS_FIXTURE"); root != "" {
		args := os.Args[1:]
		if len(args) > 0 {
			switch args[0] {
			case "--help":
				fmt.Println("--webroot --webroot-path --ip-address --required-profile")
				os.Exit(0)
			case "plugins":
				fmt.Println("webroot")
				os.Exit(0)
			case "certonly", "renew":
				config := ""
				for i, arg := range args {
					if arg == "--config-dir" && i+1 < len(args) {
						config = args[i+1]
					}
				}
				if config == "" {
					os.Exit(8)
				}
				live := filepath.Join(config, "live", "relay-gate-public-ip")
				if os.MkdirAll(live, 0700) != nil {
					os.Exit(9)
				}
				for _, name := range []string{"fullchain.pem", "privkey.pem"} {
					raw, err := os.ReadFile(filepath.Join(root, name))
					if err != nil {
						os.Exit(10)
					}
					if os.WriteFile(filepath.Join(live, name), raw, 0600) != nil {
						os.Exit(11)
					}
				}
				os.Exit(0)
			case "-c":
				if os.Getenv("RELAY_ACME_PROCESS_FAIL_RELOAD") == "1" && strings.Contains(" "+strings.Join(args, " ")+" ", " -s reload ") {
					fmt.Fprintln(os.Stderr, "private raw fixture output must not enter status")
					os.Exit(12)
				}
				os.Exit(0)
			}
		}
		os.Exit(99)
	}
	os.Exit(m.Run())
}

func TestPublicManagerExecutesExternalCertbotAndNginxCommands(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	fixture := t.TempDir()
	cert, key, roots := testCertificate(t, "8.8.8.8", 160*time.Hour)
	for source, name := range map[string]string{cert: "fullchain.pem", key: "privkey.pem"} {
		raw, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fixture, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("RELAY_ACME_PROCESS_FIXTURE", fixture)
	m, err := NewPublicManager(PublicOptions{IP: "8.8.8.8", StateDir: t.TempDir(), Webroot: t.TempDir(), Upstream: "http://127.0.0.1:18787", CertbotBinary: executable, NginxBinary: executable, Roots: roots,
		StartNginx:     func(string) (ManagedProcess, error) { return &idleProcess{done: make(chan error, 1)}, nil },
		ChallengeProbe: func(context.Context, string, string) error { return nil }, TLSProbe: func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.process.Kill() }()
	if err := m.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !m.Snapshot().BusinessAllowed {
		t.Fatal("external command path did not publish validated certificate")
	}
	// Change the externally emitted leaf to a second trusted local CA, then
	// inject a real child exit status at reload, after validation succeeded.
	cert, key, newRoots := testCertificate(t, "8.8.8.8", 160*time.Hour)
	for source, name := range map[string]string{cert: "fullchain.pem", key: "privkey.pem"} {
		raw, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fixture, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	m.options.Roots = newRoots
	t.Setenv("RELAY_ACME_PROCESS_FAIL_RELOAD", "1")
	before := m.Snapshot()
	if err := m.RenewOnce(context.Background()); err == nil {
		t.Fatal("external reload failure accepted")
	}
	after := m.Snapshot()
	if !after.ReloadFailedKeepOld || after.CertificateFingerprint != before.CertificateFingerprint || strings.Contains(after.LastError, "private raw fixture") {
		t.Fatal("external reload fault leaked output or displaced old certificate")
	}
}
