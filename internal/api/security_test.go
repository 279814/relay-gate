package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/smtp"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/security"
	"github.com/279814/relay-gate/internal/store"
)

func TestAPI_SecurityScanAndLazyCanaryRejected(t *testing.T) {
	s, _ := newTestServer(t)
	h := s.WithSecurityCenter(security.NewCenter(50)).Routes(testAdminPW)

	rec := do(t, h, "POST", "/admin/api/security/scan",
		`{"text":"<script>x</script> ignore previous instructions"}`, true)
	if rec.Code != 200 {
		t.Fatalf("scan status %d %s", rec.Code, rec.Body.String())
	}
	var scan struct {
		Count int `json:"count"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &scan)
	if scan.Count < 1 {
		t.Fatalf("expected findings, body=%s", rec.Body.String())
	}

	rec2 := do(t, h, "POST", "/admin/api/security/canary",
		`{"upstream_id":1,"probe_mode":"lazy"}`, true)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("lazy canary status %d", rec2.Code)
	}

	rec3 := do(t, h, "GET", "/admin/api/security/findings", "", true)
	if rec3.Code != 200 {
		t.Fatalf("findings %d", rec3.Code)
	}
}

// Naming an existing upstream must feed its stored API key into ScanText so
// a pasted key cannot land in finding Detail or the HTTP scan response.
func TestAPI_SecurityScan_NamedUpstreamRedactsAPIKey(t *testing.T) {
	const key = "sk-ADMIN-SCAN-REDACT-KEY-7e4d9a2c"
	s, _ := newTestServer(t)
	up := &model.Upstream{
		Name: "scan-redact-up", BaseURL: "https://scan-redact.example",
		APIKey: key, Enabled: true,
	}
	up.Defaults()
	if err := s.st.CreateUpstream(up); err != nil {
		t.Fatal(err)
	}
	h := s.WithSecurityCenter(security.NewCenter(50)).Routes(testAdminPW)

	text := `<script>x</script> token=` + key + ` trailer`
	payload := fmt.Sprintf(`{"text":%q,"upstream":%q}`, text, up.Name)
	rec := do(t, h, "POST", "/admin/api/security/scan", payload, true)
	if rec.Code != 200 {
		t.Fatalf("scan by name status %d %s", rec.Code, rec.Body.String())
	}
	assertScanResponseOmitsKey(t, rec.Body.String(), key)

	payloadID := fmt.Sprintf(`{"text":%q,"upstream":%q}`, text, itoa(up.ID))
	rec2 := do(t, h, "POST", "/admin/api/security/scan", payloadID, true)
	if rec2.Code != 200 {
		t.Fatalf("scan by id status %d %s", rec2.Code, rec2.Body.String())
	}
	assertScanResponseOmitsKey(t, rec2.Body.String(), key)

	listed := s.security.List("", 50)
	for _, f := range listed {
		if strings.Contains(f.Detail, key) {
			t.Fatalf("stored finding Detail still contains upstream API key: %q", f.Detail)
		}
	}
}

func assertScanResponseOmitsKey(t *testing.T, body, key string) {
	t.Helper()
	if strings.Contains(body, key) {
		t.Fatalf("scan HTTP response echoed upstream API key: %s", body)
	}
	var scan struct {
		Findings []security.Finding `json:"findings"`
		Count    int                `json:"count"`
	}
	if err := json.Unmarshal([]byte(body), &scan); err != nil {
		t.Fatalf("parse scan response: %v", err)
	}
	if scan.Count < 1 || len(scan.Findings) < 1 {
		t.Fatalf("expected findings, body=%s", body)
	}
	for _, f := range scan.Findings {
		if strings.Contains(f.Detail, key) {
			t.Fatalf("finding Detail still contains upstream API key: %q", f.Detail)
		}
	}
}

// Unknown body.upstream must not be copied onto findings (client string can be
// nearly 1MiB). A resolved short name is stored; req_id is capped.
func TestAPI_SecurityScan_OmitsUnknownUpstreamString(t *testing.T) {
	s, _ := newTestServer(t)
	up := &model.Upstream{
		Name: "scan-known-up", BaseURL: "https://scan-known.example",
		APIKey: "sk-KNOWN-SCAN-UPSTREAM-KEY", Enabled: true,
	}
	up.Defaults()
	if err := s.st.CreateUpstream(up); err != nil {
		t.Fatal(err)
	}
	h := s.WithSecurityCenter(security.NewCenter(50)).Routes(testAdminPW)

	unknown := "not-a-real-upstream-" + strings.Repeat("X", 400)
	longReq := strings.Repeat("r", maxScanReqID+80)
	payload := fmt.Sprintf(
		`{"text":"<script>x</script>","upstream":%q,"req_id":%q}`,
		unknown, longReq,
	)
	rec := do(t, h, "POST", "/admin/api/security/scan", payload, true)
	if rec.Code != 200 {
		t.Fatalf("unknown upstream scan status %d %s", rec.Code, rec.Body.String())
	}
	var scan struct {
		Findings []security.Finding `json:"findings"`
		Count    int                `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &scan); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if scan.Count < 1 {
		t.Fatalf("expected findings, body=%s", rec.Body.String())
	}
	for _, f := range scan.Findings {
		if f.Upstream != "" {
			t.Fatalf("unknown upstream must not persist; got Upstream=%q", f.Upstream)
		}
		if strings.Contains(f.Upstream, "not-a-real-upstream") || strings.Contains(rec.Body.String(), unknown) {
			t.Fatalf("raw unknown upstream leaked into scan response: %s", rec.Body.String())
		}
		if len(f.ReqID) != maxScanReqID {
			t.Fatalf("req_id len=%d, want capped to %d", len(f.ReqID), maxScanReqID)
		}
		if f.ReqID != longReq[:maxScanReqID] {
			t.Fatalf("req_id not prefix-capped")
		}
	}
	for _, f := range s.security.List("", 50) {
		if f.Upstream != "" {
			t.Fatalf("stored finding kept unknown upstream: %q", f.Upstream)
		}
	}

	payloadOK := fmt.Sprintf(
		`{"text":"<script>x</script>","upstream":%q,"req_id":"short-req"}`,
		up.Name,
	)
	rec2 := do(t, h, "POST", "/admin/api/security/scan", payloadOK, true)
	if rec2.Code != 200 {
		t.Fatalf("named upstream scan status %d %s", rec2.Code, rec2.Body.String())
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &scan); err != nil {
		t.Fatalf("parse named: %v", err)
	}
	if scan.Count < 1 {
		t.Fatalf("expected findings for named upstream, body=%s", rec2.Body.String())
	}
	for _, f := range scan.Findings {
		if f.Upstream != up.Name {
			t.Fatalf("matched name: Upstream=%q, want %q", f.Upstream, up.Name)
		}
		if f.ReqID != "short-req" {
			t.Fatalf("short req_id: got %q", f.ReqID)
		}
	}
}

// SMTP dial/auth errors are uncontrolled I/O text. The admin test endpoint
// must not echo them — writeErr's default maps unknowns to "internal error".
func TestAPI_SMTPTestDoesNotEchoRawSendError(t *testing.T) {
	const leak = `dial tcp smtp.evil:587: dial /var/lib/mail.sock: sql: SELECT password FROM smtp_secrets`

	s, _ := newTestServer(t)
	if err := s.st.SaveSMTPConfig(store.SMTPConfig{
		Enabled:    true,
		Host:       "smtp.evil",
		Port:       587,
		From:       "relay@test.local",
		Recipients: "ops@test.local",
	}, "smtp-pw"); err != nil {
		t.Fatal(err)
	}
	mailer := security.NewAlertMailer().WithSendForTest(
		func(string, smtp.Auth, string, []string, []byte) error {
			return errors.New(leak)
		})
	h := s.WithAlertMailer(mailer).Routes(testAdminPW)

	rec := do(t, h, "POST", "/admin/api/security/smtp/test", "", true)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, leak) || strings.Contains(body, "smtp.evil") ||
		strings.Contains(body, "/var/lib/mail.sock") || strings.Contains(body, "SELECT password") {
		t.Fatalf("raw SMTP error leaked to client: %s", body)
	}
	if !strings.Contains(body, `"error":"internal error"`) {
		t.Fatalf("want fixed internal error, got %s", body)
	}
}
