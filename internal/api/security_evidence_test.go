package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/security"
)

func securityRawFixture(t *testing.T, s *Server, reqID string) {
	t.Helper()
	sample := &model.Sample{ReqID: reqID, InMethod: "POST", Endpoint: "/v1/messages", InHeaders: http.Header{}, Attempts: []*model.SampleAttempt{{RouteID: 7, UpstreamID: 42, RespStatus: 202, RespHeaders: http.Header{"Content-Type": {"text/plain"}}, RespBody: []byte("private-original-upstream"), ResponseCaptureView: "upstream_response", Metadata: model.AttemptMetadata{Version: 1}}}}
	if err := s.st.InsertSample(sample); err != nil {
		t.Fatal(err)
	}
}
func TestSecurityRawEvidenceRequiresTrustedUniqueCompleteRelationAndCookieReauth(t *testing.T) {
	s, h := newTestServer(t)
	securityRawFixture(t, s, "exact-req")
	f := security.Finding{ID: "raw-fixture", Source: "passive", ReqID: "exact-req", RouteID: 7, UpstreamID: 42, ScannerVersion: security.ScannerVersion, RuleVersion: security.RuleVersion, BytesScanned: 25, RuleID: "builtin:prompt_injection"}
	if err := s.st.InsertSecurityFinding(f); err != nil {
		t.Fatal(err)
	}
	session := loginSession(t, h)
	call := func(method, path, body string, cookie bool, bearer bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "http://example.com")
		if cookie {
			req.AddCookie(session)
		}
		if bearer {
			req.Header.Set("Authorization", "Bearer "+testAdminPW)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	path := "/admin/api/security/findings/raw-fixture/evidence"
	for _, test := range []struct {
		cookie bool
		body   string
	}{{false, `{"password":"` + testAdminPW + `"}`}, {true, `{"password":"wrong"}`}} {
		rec := call("POST", path, test.body, test.cookie, true)
		if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "private-original") {
			t.Fatalf("raw auth bypass: %d %s", rec.Code, rec.Body.String())
		}
	}
	meta := call("GET", path+"-metadata", "", true, false)
	if meta.Code != http.StatusOK || strings.Contains(meta.Body.String(), "private-original") || !strings.Contains(meta.Body.String(), `"available":true`) {
		t.Fatalf("metadata=%d %s", meta.Code, meta.Body.String())
	}
	rec := call("POST", path, `{"password":"`+testAdminPW+`"}`, true, false)
	var raw struct {
		Available bool   `json:"available"`
		Body      []byte `json:"body"`
		Status    int    `json:"status"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &raw) != nil || !raw.Available || string(raw.Body) != "private-original-upstream" || raw.Status != 202 || !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("authorized raw=%d %s", rec.Code, rec.Body.String())
	}
	// A caller-controlled admin-scan ReqID never becomes authority.
	f.ID = "forged"
	f.Source = "admin_scan"
	s.st.InsertSecurityFinding(f)
	rec = call("POST", "/admin/api/security/findings/forged/evidence", `{"password":"`+testAdminPW+`"}`, true, false)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "body") || !strings.Contains(rec.Body.String(), `"available":false`) {
		t.Fatalf("forged relation=%d %s", rec.Code, rec.Body.String())
	}
	// Duplicated retries or groups cannot select a guessed last attempt.
	securityRawFixture(t, s, "exact-req")
	rec = call("POST", path, `{"password":"`+testAdminPW+`"}`, true, false)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), `"body"`) || !strings.Contains(rec.Body.String(), `"available":false`) {
		t.Fatalf("ambiguous relation=%d %s", rec.Code, rec.Body.String())
	}
	// Completion failure must block the first plaintext byte.
	s.st.DB().Exec(`DELETE FROM sample_request WHERE id=(SELECT MAX(id) FROM sample_request)`)
	s.st.DB().Exec(`CREATE TRIGGER block_raw_audit BEFORE UPDATE ON audit_event WHEN OLD.action='security_evidence_view' BEGIN SELECT RAISE(ABORT,'audit failed'); END`)
	rec = call("POST", path, `{"password":"`+testAdminPW+`"}`, true, false)
	if rec.Code != 503 || strings.Contains(rec.Body.String(), "body") || rec.Header().Get("X-Audit-Status") != "pending" {
		t.Fatalf("audit failure released raw=%d %s", rec.Code, rec.Body.String())
	}
}

func TestSecurityEvidenceEncodedIDCannotBypassFirstByteAudit(t *testing.T) {
	s, h := newTestServer(t)
	securityRawFixture(t, s, "escaped-exact")
	f := security.Finding{ID: "legacy/encoded-finding", Source: "passive", ReqID: "escaped-exact", RouteID: 7, UpstreamID: 42, ScannerVersion: security.ScannerVersion, RuleVersion: security.RuleVersion, BytesScanned: 25}
	if err := s.st.InsertSecurityFinding(f); err != nil {
		t.Fatal(err)
	}
	session := loginSession(t, h)
	if _, err := s.st.DB().Exec(`CREATE TRIGGER block_encoded_raw_audit BEFORE UPDATE ON audit_event WHEN OLD.action='security_evidence_view' BEGIN SELECT RAISE(ABORT,'audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", "/admin/api/security/findings/legacy%2Fencoded-finding/evidence", strings.NewReader(`{"password":"`+testAdminPW+`"}`))
	request.AddCookie(session)
	request.Header.Set("Origin", "http://example.com")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != 503 || strings.Contains(response.Body.String(), `"body"`) {
		t.Fatalf("encoded finding ID bypassed durable first-byte gate: %d %s", response.Code, response.Body.String())
	}
}
