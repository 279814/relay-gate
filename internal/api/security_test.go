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
	longReq := strings.Repeat("r", maxFindingClientField+80)
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
		if len(f.ReqID) != maxFindingClientField {
			t.Fatalf("req_id len=%d, want capped to %d", len(f.ReqID), maxFindingClientField)
		}
		if f.ReqID != longReq[:maxFindingClientField] {
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

// Canary note is persisted into finding Detail; an unbounded body.note must not
// bloat the row (same 256-byte cap as scan req_id).
func TestAPI_SecurityCanary_CapsNoteInDetail(t *testing.T) {
	s, _ := newTestServer(t)
	up := &model.Upstream{
		Name: "canary-note-up", BaseURL: "https://canary-note.example",
		APIKey: "sk-CANARY-NOTE-KEY", Enabled: true,
	}
	up.Defaults()
	if err := s.st.CreateUpstream(up); err != nil {
		t.Fatal(err)
	}
	mn := &model.ModelName{Name: "canary-note-model", Protocol: model.ProtoAnthropic, Enabled: true}
	mn.Defaults()
	if err := s.st.CreateModelName(mn); err != nil {
		t.Fatal(err)
	}
	rt := &model.Route{ModelNameID: mn.ID, UpstreamID: up.ID, Enabled: true}
	rt.Defaults()
	if err := s.st.CreateRoute(rt); err != nil {
		t.Fatal(err)
	}
	h := s.WithSecurityCenter(security.NewCenter(50)).Routes(testAdminPW)

	longNote := strings.Repeat("n", maxFindingClientField+120)
	payload := fmt.Sprintf(`{"route_id":%d,"note":%q}`, rt.ID, longNote)
	rec := do(t, h, "POST", "/admin/api/security/canary", payload, true)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("canary status %d %s", rec.Code, rec.Body.String())
	}
	var found *security.Finding
	for _, f := range s.security.List("", 50) {
		if f.Category == "canary_manual" && f.RouteID == rt.ID {
			cp := f
			found = &cp
			break
		}
	}
	if found == nil {
		t.Fatal("expected canary_manual finding")
	}
	if len(found.Detail) != maxFindingClientField {
		t.Fatalf("Detail len=%d, want capped to %d", len(found.Detail), maxFindingClientField)
	}
	if found.Detail != longNote[:maxFindingClientField] {
		t.Fatalf("Detail not prefix-capped")
	}

	short := "brief-note"
	payloadShort := fmt.Sprintf(`{"route_id":%d,"note":%q}`, rt.ID, short)
	rec2 := do(t, h, "POST", "/admin/api/security/canary", payloadShort, true)
	if rec2.Code != http.StatusAccepted {
		t.Fatalf("short canary status %d %s", rec2.Code, rec2.Body.String())
	}
	var shortFound *security.Finding
	for _, f := range s.security.List("", 50) {
		if f.Category == "canary_manual" && f.RouteID == rt.ID && f.Detail == short {
			cp := f
			shortFound = &cp
			break
		}
	}
	if shortFound == nil {
		t.Fatalf("short note Detail not preserved; listed=%v", s.security.List("", 50))
	}
}

// Legacy security_finding rows may still hold a raw upstream key in Detail
// (Insert stores as-is; only ScanText redacts on write). GET list must not
// echo that secret in JSON (§2.4).
func TestAPI_ListSecurityFindings_RedactsLegacyDetailSecret(t *testing.T) {
	const key = "sk-LEGACY-FINDING-DETAIL-KEY99"
	s, _ := newTestServer(t)
	up := &model.Upstream{
		Name: "legacy-finding-up", BaseURL: "https://legacy-finding.example",
		APIKey: key, Enabled: true,
	}
	up.Defaults()
	if err := s.st.CreateUpstream(up); err != nil {
		t.Fatal(err)
	}
	f := security.Finding{
		ID:       "legacy-detail-secret-1",
		AtMS:     1,
		Severity: security.SeverityHigh,
		Category: "xss_pattern",
		Summary:  "legacy row",
		Detail:   "matched body fragment token=" + key + " trailer",
		Source:   "passive",
	}
	if err := s.st.InsertSecurityFinding(f); err != nil {
		t.Fatal(err)
	}
	h := s.Routes(testAdminPW)
	rec := do(t, h, "GET", "/admin/api/security/findings", "", true)
	if rec.Code != 200 {
		t.Fatalf("findings status %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, key) {
		t.Fatal("findings JSON still contains fixture secret from legacy Detail")
	}
	var resp struct {
		Findings []security.Finding `json:"findings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse findings: %v", err)
	}
	if len(resp.Findings) < 1 {
		t.Fatal("expected at least one finding")
	}
	found := false
	for _, got := range resp.Findings {
		if got.ID != f.ID {
			continue
		}
		found = true
		if strings.Contains(got.Detail, key) {
			t.Fatal("finding Detail still contains fixture secret")
		}
		if !strings.Contains(got.Detail, "…") {
			t.Fatalf("Detail missing masked secret form: %q", got.Detail)
		}
	}
	if !found {
		t.Fatal("legacy finding id missing from list response")
	}
}

// Shared admin-list page contract for findings: omitted limit → default 50;
// over MaximumPageLimit is rejected so a huge limit cannot load unbounded rows
// on either the SQL or in-memory list path.
func TestAPI_ListSecurityFindings_PageLimitDefaultAndCap(t *testing.T) {
	const n = 60
	s, _ := newTestServer(t)
	for i := 0; i < n; i++ {
		f := security.Finding{
			ID:       fmt.Sprintf("api-page-limit-%d", i),
			AtMS:     int64(n - i),
			Severity: security.SeverityLow,
			Category: "xss_pattern",
			Summary:  "api page limit fixture",
			Source:   "passive",
		}
		if err := s.st.InsertSecurityFinding(f); err != nil {
			t.Fatal(err)
		}
	}
	h := s.Routes(testAdminPW)

	rec := do(t, h, "GET", "/admin/api/security/findings", "", true)
	if rec.Code != 200 {
		t.Fatalf("omitted limit status %d %s", rec.Code, rec.Body.String())
	}
	var def struct {
		Findings []security.Finding `json:"findings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &def); err != nil {
		t.Fatal(err)
	}
	if len(def.Findings) != 50 {
		t.Fatalf("omitted limit: got %d findings, want default 50", len(def.Findings))
	}

	recHuge := do(t, h, "GET", "/admin/api/security/findings?limit=100000000", "", true)
	if recHuge.Code != http.StatusBadRequest {
		t.Fatalf("huge limit status %d, want 400; body=%s", recHuge.Code, recHuge.Body.String())
	}

	// In-memory path: API must still apply NormalizePageLimit before Center.List
	// (ring can hold > MaximumPageLimit; see NewPersistentCenter(500)).
	center := security.NewCenter(500)
	for i := 0; i < 250; i++ {
		center.Record(security.Finding{
			ID:       fmt.Sprintf("mem-page-limit-%d", i),
			AtMS:     int64(250 - i),
			Severity: security.SeverityLow,
			Category: "xss_pattern",
			Summary:  "mem page limit fixture",
			Source:   "passive",
		})
	}
	s.st = nil
	hMem := s.WithSecurityCenter(center).Routes(testAdminPW)

	recMem := do(t, hMem, "GET", "/admin/api/security/findings", "", true)
	if recMem.Code != 200 {
		t.Fatalf("in-memory omitted limit status %d %s", recMem.Code, recMem.Body.String())
	}
	var memDef struct {
		Findings []security.Finding `json:"findings"`
	}
	if err := json.Unmarshal(recMem.Body.Bytes(), &memDef); err != nil {
		t.Fatal(err)
	}
	if len(memDef.Findings) != 50 {
		t.Fatalf("in-memory omitted limit: got %d, want default 50", len(memDef.Findings))
	}

	recMemHuge := do(t, hMem, "GET", "/admin/api/security/findings?limit=100000000", "", true)
	if recMemHuge.Code != http.StatusBadRequest {
		t.Fatalf("in-memory huge limit status %d, want 400; body=%s", recMemHuge.Code, recMemHuge.Body.String())
	}

	recMemMax := do(t, hMem, "GET", "/admin/api/security/findings?limit="+itoa(int64(store.MaximumPageLimit)), "", true)
	if recMemMax.Code != 200 {
		t.Fatalf("in-memory max limit status %d %s", recMemMax.Code, recMemMax.Body.String())
	}
	var memMax struct {
		Findings []security.Finding `json:"findings"`
	}
	if err := json.Unmarshal(recMemMax.Body.Bytes(), &memMax); err != nil {
		t.Fatal(err)
	}
	if len(memMax.Findings) != store.MaximumPageLimit {
		t.Fatalf("in-memory limit=MaximumPageLimit: got %d, want %d", len(memMax.Findings), store.MaximumPageLimit)
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
