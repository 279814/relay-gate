package acmeip

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeCommands struct {
	help          string
	calls         [][]string
	failRenew     bool
	failReload    bool
	failCandidate bool
	onIssue       func() error
}

func (f *fakeCommands) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	joined := strings.Join(args, " ")
	if f.failCandidate && strings.Contains(joined, "candidate.conf") {
		return nil, errors.New("candidate configuration failed")
	}
	if strings.Contains(joined, "--help") {
		return []byte(f.help), nil
	}
	if len(args) > 0 && args[0] == "plugins" {
		return []byte("* webroot\nDescription: HTTP-01 webroot authenticator"), nil
	}
	if len(args) > 0 && args[0] == "renew" && f.failRenew {
		return nil, errors.New("renew failed")
	}
	if strings.Contains(joined, "-s reload") && f.failReload {
		return nil, errors.New("reload failed")
	}
	if len(args) > 0 && (args[0] == "certonly" || args[0] == "renew") && f.onIssue != nil {
		return nil, f.onIssue()
	}
	return nil, nil
}

func TestCertbotRuntimeCapabilityProbeAndArguments(t *testing.T) {
	for _, tc := range []struct {
		help   string
		want   string
		reject bool
	}{
		{"--webroot --webroot-path --ip-address --required-profile --preferred-profile", "--required-profile", false},
		{"--webroot --webroot-path --ip-address --preferred-profile", "--preferred-profile", false},
		{"--webroot --preferred-profile", "", true},
		{"--webroot --webroot-path --ip-address", "", true},
	} {
		t.Run(tc.help, func(t *testing.T) {
			runner := &fakeCommands{help: tc.help}
			bot := &ProcessCertbot{Binary: "certbot", StateDir: t.TempDir(), Webroot: t.TempDir(), IP: "8.8.8.8", Runner: runner}
			err := bot.Probe(context.Background())
			if tc.reject {
				if err == nil {
					t.Fatal("unsupported certbot accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := bot.Issue(context.Background()); err != nil {
				t.Fatal(err)
			}
			last := strings.Join(runner.calls[len(runner.calls)-1], " ")
			for _, value := range []string{"certonly", "--ip-address 8.8.8.8", tc.want + " shortlived", "--webroot-path", "--register-unsafely-without-email", "--agree-tos"} {
				if !strings.Contains(last, value) {
					t.Fatalf("missing %s: %s", value, last)
				}
			}
			if strings.Contains(last, " -d ") || strings.Contains(last, "--nginx") {
				t.Fatal("IP issuance used a domain/installer path")
			}
		})
	}
}
