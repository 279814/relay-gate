package api

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/probe"
	"github.com/279814/relay-gate/internal/security"
)

type diagnosticPublishBarrier struct {
	source  *livecfg.Source
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	secret  string
}

func (p *diagnosticPublishBarrier) Invalidate() {
	p.once.Do(func() { close(p.entered); <-p.release })
	p.source.Invalidate()
}

func (p *diagnosticPublishBarrier) Refresh() error {
	if err := p.source.Refresh(); err != nil {
		return fmt.Errorf("publish diagnostic %s: %w", p.secret, err)
	}
	return nil
}

func TestDiagnosticNewCommittedKeyIsRedactedBeforeInvalidateAndAfterRefreshFailure(t *testing.T) {
	s, _ := newTestServer(t)
	const oldKey = "opaque-published-old-fixture-credential"
	const newKey = "opaque-committed-new-fixture-credential"
	up := metadataUpstream(t, s, "publish-barrier-upstream", oldKey)
	var logs bytes.Buffer
	s.log = slog.New(slog.NewTextHandler(&logs, nil))
	source := livecfg.New(s.st, s.log)
	if err := source.Refresh(); err != nil {
		t.Fatal(err)
	}
	if err := s.st.InsertSecurityFinding(security.Finding{ID: "publish-window", AtMS: 1, Severity: security.SeverityHigh, Category: "xss_pattern", Summary: "legacy", Detail: "opaque detail " + newKey}); err != nil {
		t.Fatal(err)
	}
	barrier := &diagnosticPublishBarrier{source: source, entered: make(chan struct{}), release: make(chan struct{}), secret: newKey}
	server := httptest.NewServer(s.WithConfigPublisher(barrier).Routes(testAdminPW))
	server.Client().Timeout = 5 * time.Second
	var unblock sync.Once
	defer func() { unblock.Do(func() { close(barrier.release) }); server.Close() }()
	updateDone := make(chan int, 1)
	go func() {
		request, _ := http.NewRequest("PUT", server.URL+"/admin/api/upstreams/"+itoa(up.ID), strings.NewReader(fmt.Sprintf(`{"expected_revision":1,"api_key":%q}`, newKey)))
		request.Header.Set("Authorization", "Bearer "+testAdminPW)
		response, err := server.Client().Do(request)
		if err != nil {
			updateDone <- 0
			return
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		updateDone <- response.StatusCode
	}()
	select {
	case <-barrier.entered: // Real DB commit has returned; Source.Invalidate has not run.
	case <-time.After(5 * time.Second):
		t.Fatal("update did not reach the post-commit publication barrier")
	}
	if _, err := s.st.DB().Exec(`UPDATE upstream SET probe_headers='bad-json' WHERE id=?`, up.ID); err != nil {
		t.Fatal(err)
	}
	assertSafeRead := func() {
		t.Helper()
		request, _ := http.NewRequest("GET", server.URL+"/admin/api/security/findings", nil)
		request.Header.Set("Authorization", "Bearer "+testAdminPW)
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		wire, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 200 || strings.Contains(string(wire), newKey) {
			t.Fatalf("new committed key escaped current DB redaction: status=%d", response.StatusCode)
		}
	}
	assertSafeRead()
	unblock.Do(func() { close(barrier.release) })
	if status := <-updateDone; status != 503 {
		t.Fatalf("failed publish response=%d", status)
	}
	oldBundle, err := source.Bundle()
	if err != nil || oldBundle.Routing.Upstreams[up.ID].APIKey != oldKey {
		t.Fatal("test did not retain the old routing snapshot after refresh failed")
	}
	assertSafeRead()
	s.writeErr(httptest.NewRecorder(), fmt.Errorf("write diagnostic %s", newKey))
	if strings.Contains(logs.String(), newKey) {
		t.Fatal("new key reached diagnostic logs across the commit/publish failure window")
	}
}

func TestDiagnosticReadbackUsesAllCurrentKeysAndFailsClosed(t *testing.T) {
	s, _ := newTestServer(t)
	const secret = "opaque-disabled-site-205-credential"
	for i := 1; i <= 205; i++ {
		key := fmt.Sprintf("opaque-diagnostic-fixture-%03d", i)
		if i == 205 {
			key = secret
		}
		metadataUpstream(t, s, fmt.Sprintf("diagnostic-%03d", i), key)
	}
	// Disabled/no-route credentials are still secrets, and irrelevant legacy
	// JSON cannot make the readback lose every known key.
	if _, err := s.st.DB().Exec(`UPDATE upstream SET enabled=0 WHERE id=205; UPDATE upstream SET probe_headers='invalid-json' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := s.st.InsertSecurityFinding(security.Finding{ID: "diagnostic-legacy", AtMS: 1, Severity: security.SeverityHigh, Category: "xss_pattern", Summary: "legacy", Detail: "opaque detail " + secret}); err != nil {
		t.Fatal(err)
	}
	admin := &legacyDetailAdmin{Service: probe.NewService(s.st, nil, nil, nil, nil, nil), detail: "opaque detail " + secret}
	var logs bytes.Buffer
	s.log = slog.New(slog.NewTextHandler(&logs, nil))
	server := httptest.NewServer(s.WithProbeAdmin(admin).Routes(testAdminPW))
	defer server.Close()
	read := func(path string) (int, string) {
		t.Helper()
		request, _ := http.NewRequest("GET", server.URL+"/admin/api/"+path, nil)
		request.Header.Set("Authorization", "Bearer "+testAdminPW)
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, string(body)
	}
	paths := []string{"security/findings", "probe-executions", "probe-executions/exec-legacy", "capabilities", "reachability"}
	for _, path := range paths {
		status, wire := read(path)
		if status != 200 || strings.Contains(wire, secret) {
			t.Fatalf("complete key coverage failed: %s status=%d secret_present=%t", path, status, strings.Contains(wire, secret))
		}
	}
	if _, err := s.st.DB().Exec(`UPDATE upstream SET api_key_enc='invalid-envelope' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		status, wire := read(path)
		if status != 503 || strings.Contains(wire, secret) {
			t.Fatalf("unreadable key did not fail closed: %s status=%d secret_present=%t", path, status, strings.Contains(wire, secret))
		}
	}
	s.writeErr(httptest.NewRecorder(), fmt.Errorf("driver diagnostic %s", secret))
	s.WithConfigPublisher(refreshErrPublisher{err: fmt.Errorf("refresh diagnostic %s", secret)})
	_ = s.publishAfterSuccessfulWrite()
	if strings.Contains(logs.String(), secret) {
		t.Fatal("unreadable redaction key caused raw diagnostic log disclosure")
	}
}
