package acmeip

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// CI's public Docker target sets RELAY_PUBLIC_NGINX_TEST=1. A missing real
// Certbot/Nginx then fails rather than silently passing through a mock/skip.
func requireEdgeContainer(t *testing.T) {
	t.Helper()
	if os.Getenv("RELAY_PUBLIC_NGINX_TEST") != "1" {
		t.Skip("requires isolated public-edge test container (ports 80/443)")
	}
	for _, binary := range []string{"nginx", "certbot"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Fatalf("required real %s unavailable: %v", binary, err)
		}
	}
}

func TestInstalledCertbotIPWebrootCapabilities(t *testing.T) {
	requireEdgeContainer(t)
	bot := ProcessCertbot{StateDir: t.TempDir(), Webroot: t.TempDir(), IP: "8.8.8.8"}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := bot.Probe(ctx); err != nil {
		t.Fatal(err)
	}
}

type realNginxCommands struct {
	certbot    *fakeCommands
	failReload bool
}

func (r *realNginxCommands) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if filepath.Base(name) == "certbot" {
		return r.certbot.Run(ctx, name, args...)
	}
	if r.failReload && strings.Contains(" "+strings.Join(args, " ")+" ", " -s reload ") {
		return nil, errors.New("injected reload failure")
	}
	return (OSCommands{}).Run(ctx, name, args...)
}

func TestPublicRealNginxLocalCAIntegration(t *testing.T) {
	requireEdgeContainer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Forwarded") != "" || r.Header.Get("X-Forwarded-Proto") != "https" || r.Header.Get("X-Forwarded-For") != "127.0.0.1" {
			http.Error(w, "spoofed edge identity", 400)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		time.Sleep(250 * time.Millisecond)
		_, _ = io.WriteString(w, "data: second\n\n")
		w.(http.Flusher).Flush()
	}))
	defer upstream.Close()
	cert, key, roots := testCertificate(t, "8.8.8.8", 160*time.Hour)
	fixture := &fakeCommands{help: "--webroot --webroot-path --ip-address --required-profile", onIssue: func() error { return errors.New("injected issuance failure") }}
	runner := &realNginxCommands{certbot: fixture}
	root := t.TempDir()
	// t.TempDir's 0700 ancestors would hide webroot from Nginx's worker user.
	webroot, err := os.MkdirTemp("/tmp", "relay-public-webroot-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(webroot)
	if err := os.Chmod(webroot, 0755); err != nil {
		t.Fatal(err)
	}
	m, err := NewPublicManager(PublicOptions{IP: "8.8.8.8", StateDir: root, Webroot: webroot, Upstream: upstream.URL, Runner: runner, Roots: roots, Output: os.Stderr, ChallengeAddress: "127.0.0.1:80", HTTPSAddress: "127.0.0.1:443"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		stop, done := context.WithTimeout(context.Background(), 3*time.Second)
		defer done()
		_ = m.Close(stop)
	}()
	if err := m.Bootstrap(ctx); err == nil {
		t.Fatal("injected issuance failure accepted")
	}
	// A new configuration is observed on fresh connections. A shared default
	// transport may retain an HTTP connection to a retiring ACME-only worker.
	plainTransport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer plainTransport.CloseIdleConnections()
	plain := http.Client{Transport: plainTransport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 2 * time.Second}
	for _, path := range []string{"/admin/", "/v1/models", "/healthz"} {
		response, err := plain.Get("http://127.0.0.1" + path)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 503 {
			t.Fatalf("ACME-only exposed %s: %d", path, response.StatusCode)
		}
	}
	fixture.onIssue = func() error {
		paths := m.bot.paths()
		if err := os.MkdirAll(filepath.Dir(paths.Key), 0700); err != nil {
			return err
		}
		for source, target := range map[string]string{cert: paths.Certificate, key: paths.Key} {
			raw, err := os.ReadFile(source)
			if err != nil {
				return err
			}
			if err := os.WriteFile(target, raw, 0600); err != nil {
				return err
			}
		}
		return nil
	}
	if err := m.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "8.8.8.8", MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:443")
	}}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: 4 * time.Second}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://8.8.8.8/sse", nil)
	request.Header.Set("Forwarded", "for=6.6.6.6;proto=http")
	request.Header.Set("X-Forwarded-For", "6.6.6.6")
	request.Header.Set("X-Forwarded-Proto", "http")
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 {
		response.Body.Close()
		t.Fatalf("HTTPS proxy status %d", response.StatusCode)
	}
	reader := bufio.NewReader(response.Body)
	line, err := reader.ReadString('\n')
	if err != nil || line != "data: first\n" || time.Since(started) >= 200*time.Millisecond {
		t.Fatalf("SSE first event buffered: %q, %v", line, err)
	}
	rest, err := io.ReadAll(reader)
	response.Body.Close()
	if err != nil || !strings.Contains(string(rest), "data: second") {
		t.Fatalf("SSE stream truncated: %q, %v", rest, err)
	}
	redirect, err := plain.Get("http://127.0.0.1/admin/")
	if err != nil {
		t.Fatal(err)
	}
	redirect.Body.Close()
	if redirect.StatusCode != 308 || redirect.Header.Get("Location") != "https://8.8.8.8/admin/" {
		t.Fatalf("HTTP did not redirect to the confirmed IP: status=%d location=%q", redirect.StatusCode, redirect.Header.Get("Location"))
	}
	before := m.Snapshot()
	fixture.failRenew = true
	if err := m.RenewOnce(ctx); err == nil {
		t.Fatal("renewal failure ignored")
	}
	if err := probeHTTPS(ctx, "127.0.0.1:443", "8.8.8.8", before.CertificateFingerprint, roots); err != nil {
		t.Fatalf("failed renewal displaced live TLS: %v", err)
	}
	// Reload-failure persistence is covered independently by an actually changed
	// trusted candidate in TestPublicRenewalReloadFailureRestoresPreviousConfig.
	// Expiry must close new TLS connections, while retaining HTTP-01 on port 80.
	m.options.Now = func() time.Time { return time.Now().Add(200 * time.Hour) }
	if err := m.CheckCurrent(ctx); err == nil {
		t.Fatal("expiration accepted")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:443", 100*time.Millisecond)
		if err != nil {
			break
		}
		conn.Close()
		if time.Now().After(deadline) {
			t.Fatal("expired TLS listener remained open")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := probeChallenge(ctx, webroot, "8.8.8.8", "127.0.0.1:80"); err != nil {
		t.Fatalf("expiry disabled renewal challenge: %v", err)
	}
	if err := m.process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-m.processDone:
	case <-ctx.Done():
		t.Fatal("killed Nginx did not exit")
	}
	m.process = nil
	deadline = time.Now().Add(2 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:80", 100*time.Millisecond)
		if err != nil {
			break
		}
		conn.Close()
		if time.Now().After(deadline) {
			t.Fatal("orphan worker retained ACME/business listener after forced shutdown")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRealChallengeAndTLSProbesUseLocalSockets(t *testing.T) {
	webroot := t.TempDir()
	server := httptest.NewServer(http.FileServer(http.Dir(webroot)))
	defer server.Close()
	if err := probeChallenge(context.Background(), webroot, "8.8.8.8", server.Listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	cert, key, roots := testCertificate(t, "8.8.8.8", 160*time.Hour)
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	tlsServer.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	tlsServer.StartTLS()
	defer tlsServer.Close()
	info, err := ValidateCertificateFiles(cert, key, "8.8.8.8", roots, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := probeHTTPS(context.Background(), tlsServer.Listener.Addr().String(), "8.8.8.8", info.Fingerprint, roots); err != nil {
		t.Fatal(err)
	}
	if err := probeHTTPS(context.Background(), tlsServer.Listener.Addr().String(), "8.8.8.8", strings.Repeat("0", 64), roots); err == nil {
		t.Fatal("wrong served fingerprint accepted")
	}
}
