package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPublicHTTPSStatus_UnconfiguredIsUnavailable(t *testing.T) {
	_, handler := newTestServer(t)
	response := do(t, handler, http.MethodGet, "/admin/api/public-https", "", true)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured HTTPS status=%d want 503", response.Code)
	}
}

func publicStatusFixture() map[string]any {
	return map[string]any{"format_version": 1, "ip": "203.0.113.50", "phase": "live_https", "not_after": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		"remaining_hours": 999, "last_attempt_at": "2026-10-18T00:00:00Z", "last_success_at": "2026-10-18T00:00:00Z", "last_reload_at": "2026-10-18T00:00:00Z",
		"last_error": "renew_command_failed", "renew_attempts": 2, "renew_successes": 1, "reload_failed_keep_old": true, "alert_low_validity": false, "business_allowed": true,
		"certificate_fingerprint": strings.Repeat("a", 64), "current_generation": "PRIVATE_INTERNAL_PATH", "private_key": "PRIVATE_KEY_NEVER_EXPOSE", "certificate_pem": "PRIVATE_CERTIFICATE_BYTES"}
}

func TestPublicHTTPSStatus_AuthenticatedWhitelistNeverReturnsPrivateFields(t *testing.T) {
	s, handler := newTestServer(t)
	path := filepath.Join(t.TempDir(), "state.json")
	encoded, err := json.Marshal(publicStatusFixture())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	s.WithPublicHTTPSStatusFile(path)
	if unauthorized := do(t, handler, http.MethodGet, "/admin/api/public-https", "", false); unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("metadata was unauthenticated: %d", unauthorized.Code)
	}
	response := do(t, handler, http.MethodGet, "/admin/api/public-https?file=/private/key.pem", "", true)
	if response.Code != http.StatusOK {
		t.Fatalf("metadata status=%d", response.Code)
	}
	if strings.Contains(response.Body.String(), "PRIVATE_") || strings.Contains(response.Body.String(), "current_generation") {
		t.Fatal("status API exposed private/internal state fields")
	}
	var status publicHTTPSStatus
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.IP != "203.0.113.50" || status.Phase != "live_https" || status.RenewAttempts != 2 || !status.ReloadFailedKeepOld || status.RemainingHours < 23.9 || status.RemainingHours > 24.1 {
		t.Fatal("approved metadata or live expiry calculation was lost")
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("certificate status can be cached past expiry")
	}
}

func TestPublicHTTPSStatus_ExpiredCertificateNeverClaimsBusinessAllowed(t *testing.T) {
	s, handler := newTestServer(t)
	metadata := publicStatusFixture()
	metadata["not_after"] = time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	s.WithPublicHTTPSStatusFile(path)
	response := do(t, handler, http.MethodGet, "/admin/api/public-https", "", true)
	var status publicHTTPSStatus
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &status) != nil || status.BusinessAllowed || status.Phase != "expired" || !status.AlertLowValidity {
		t.Fatal("stale metadata still advertised an expired certificate as live")
	}
}

func TestPublicHTTPSStatus_InvalidOrOversizedMetadataFailsClosed(t *testing.T) {
	for _, data := range []string{"PRIVATE_INVALID_JSON", strings.Repeat("x", publicHTTPSStatusLimit+1), `{"format_version":2,"ip":"203.0.113.50","phase":"live_https"}`, `{"format_version":1,"ip":"203.0.113.50","phase":"unknown"}`} {
		t.Run(data[:min(len(data), 24)], func(t *testing.T) {
			s, handler := newTestServer(t)
			path := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			s.WithPublicHTTPSStatusFile(path)
			response := do(t, handler, http.MethodGet, "/admin/api/public-https", "", true)
			if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "PRIVATE_") {
				t.Fatal("invalid status file was exposed")
			}
		})
	}
}

func TestPublicHTTPSStatus_RefusesSymlinkMetadata(t *testing.T) {
	s, handler := newTestServer(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	link := filepath.Join(dir, "state.json")
	encoded, err := json.Marshal(publicStatusFixture())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlink creation unavailable")
	}
	s.WithPublicHTTPSStatusFile(link)
	if response := do(t, handler, http.MethodGet, "/admin/api/public-https", "", true); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("symlink status=%d", response.Code)
	}
}
