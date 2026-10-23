package api

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/279814/relay-gate/internal/store"
	"net/http"
	"net/smtp"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/security"
)

func TestSecurityFindingReviewCASIsSeparateFromEvidenceAndAuditsFailures(t *testing.T) {
	s, h := newTestServer(t)
	if err := s.st.InsertSecurityFinding(security.Finding{ID: "review-fixture", AtMS: 1, Severity: security.SeverityHigh, Category: "prompt_injection", RuleID: "builtin:prompt_injection", Detail: "finite redacted evidence"}); err != nil {
		t.Fatal(err)
	}
	var original string
	if err := s.st.DB().QueryRow(`SELECT detail FROM security_finding WHERE id='review-fixture'`).Scan(&original); err != nil {
		t.Fatal(err)
	}
	rec := do(t, h, http.MethodPut, "/admin/api/security/findings/review-fixture/review", `{"expected_revision":1,"status":"false_positive"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("review status=%d body=%s", rec.Code, rec.Body.String())
	}
	var reviewed struct {
		Status   string `json:"status"`
		Revision int64  `json:"revision"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reviewed); err != nil || reviewed.Status != "false_positive" || reviewed.Revision != 2 {
		t.Fatalf("review=%+v err=%v", reviewed, err)
	}
	stale := do(t, h, http.MethodPut, "/admin/api/security/findings/review-fixture/review", `{"expected_revision":1,"status":"open"}`, true)
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale review status=%d body=%s", stale.Code, stale.Body.String())
	}
	var detail string
	var revision int64
	var status string
	if err := s.st.DB().QueryRow(`SELECT f.detail,r.status,r.revision FROM security_finding f JOIN security_finding_review r ON r.finding_id=f.id WHERE f.id='review-fixture'`).Scan(&detail, &status, &revision); err != nil || detail != original || status != "false_positive" || revision != 2 {
		t.Fatalf("CAS changed evidence or accepted an old decision: %q %d %v", status, revision, err)
	}
	var succeeded, failed int
	if err := s.st.DB().QueryRow(`SELECT COUNT(*) FILTER (WHERE outcome='succeeded'),COUNT(*) FILTER (WHERE outcome='failed' AND reason_code='conflict') FROM audit_event WHERE action='security_finding_review'`).Scan(&succeeded, &failed); err != nil || succeeded != 1 || failed != 1 {
		t.Fatalf("review audit success=%d conflict=%d err=%v", succeeded, failed, err)
	}
	for _, body := range []string{`{"expected_revision":2,"status":"ignored"}`, `{"expected_revision":0,"status":"open"}`, `{"expected_revision":2,"status":"open","reason":"do not persist arbitrary reason"}`} {
		bad := do(t, h, http.MethodPut, "/admin/api/security/findings/review-fixture/review", body, true)
		if bad.Code != http.StatusBadRequest {
			t.Fatalf("invalid review accepted: %d %s", bad.Code, bad.Body.String())
		}
	}
}

func TestSecurityReviewRefusedWriteCannotClaimSuccess(t *testing.T) {
	s, h := newTestServer(t)
	if err := s.st.InsertSecurityFinding(security.Finding{ID: "blocked-review"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.DB().Exec(`CREATE TRIGGER decline_review BEFORE INSERT ON security_finding_review BEGIN SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatal(err)
	}
	rec := do(t, h, http.MethodPut, "/admin/api/security/findings/blocked-review/review", `{"expected_revision":1,"status":"false_positive"}`, true)
	if rec.Code != http.StatusConflict {
		t.Fatalf("refused mutation claimed success: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSecurityIgnoreCapacityIsBoundedAndDriverFailureIsNotEvidence(t *testing.T) {
	s, h := newTestServer(t)
	if err := s.st.InsertSecurityFinding(security.Finding{ID: "ignore-bound", RuleID: "builtin:prompt_injection"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.DB().Exec(`WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<1024)
		INSERT INTO security_ignore_rule(scope,rule_id,created_at_ms,updated_at_ms) SELECT 'rule','builtin:prompt_injection',1,1 FROM n`); err != nil {
		t.Fatal(err)
	}
	rec := do(t, h, http.MethodPost, "/admin/api/security/ignore-rules", `{"scope":"rule","rule_id":"builtin:prompt_injection","expires_at_ms":0}`, true)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "1024") {
		t.Fatalf("capacity limit missing: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := s.st.DB().Exec(`CREATE TRIGGER fail_ignore BEFORE UPDATE ON security_ignore_rule BEGIN SELECT RAISE(ABORT,'driver-detail-private-marker'); END`); err != nil {
		t.Fatal(err)
	}
	rec = do(t, h, http.MethodPut, "/admin/api/security/ignore-rules/1", `{"expected_revision":1,"scope":"rule","rule_id":"builtin:prompt_injection","expires_at_ms":0,"enabled":false}`, true)
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "driver-detail-private-marker") {
		t.Fatalf("driver failure leaked or claimed success: %d %s", rec.Code, rec.Body.String())
	}
	var revision, enabled int
	if err := s.st.DB().QueryRow(`SELECT revision,enabled FROM security_ignore_rule WHERE id=1`).Scan(&revision, &enabled); err != nil || revision != 1 || enabled != 1 {
		t.Fatalf("failed policy write changed state: %d %d %v", revision, enabled, err)
	}
	var failed int
	if err := s.st.DB().QueryRow(`SELECT COUNT(*) FROM audit_event WHERE action='security_ignore_update' AND outcome='failed' AND reason_code='operation_failed'`).Scan(&failed); err != nil || failed != 1 {
		t.Fatalf("driver failure audit not factual: %d %v", failed, err)
	}
}

func TestSecurityIgnoreRuleHTTPHasCASPermanentExpiryAndNonreusedIDs(t *testing.T) {
	s, h := newTestServer(t)
	if err := s.st.InsertSecurityFinding(security.Finding{ID: "ignore-fixture", AtMS: 1, Category: "prompt_injection", RuleID: "builtin:prompt_injection"}); err != nil {
		t.Fatal(err)
	}
	const create = `{"scope":"rule","rule_id":"builtin:prompt_injection","route_id":0,"expires_at_ms":0,"enabled":true}`
	rec := do(t, h, http.MethodPost, "/admin/api/security/ignore-rules", create, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body.String())
	}
	var rule struct {
		ID          int64 `json:"id"`
		Revision    int64 `json:"revision"`
		ExpiresAtMS int64 `json:"expires_at_ms"`
		Enabled     bool  `json:"enabled"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &rule); err != nil || rule.ID <= 0 || rule.Revision != 1 || rule.ExpiresAtMS != 0 || !rule.Enabled {
		t.Fatalf("created=%+v err=%v", rule, err)
	}
	path := fmt.Sprintf("/admin/api/security/ignore-rules/%d", rule.ID)
	update := `{"expected_revision":1,"scope":"rule","rule_id":"builtin:prompt_injection","route_id":0,"expires_at_ms":0,"enabled":false}`
	rec = do(t, h, http.MethodPut, path, update, true)
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &rule) != nil || rule.Revision != 2 || rule.Enabled {
		t.Fatalf("update status=%d body=%s", rec.Code, rec.Body.String())
	}
	if stale := do(t, h, http.MethodPut, path, update, true); stale.Code != http.StatusConflict {
		t.Fatalf("stale update status=%d body=%s", stale.Code, stale.Body.String())
	}
	if stale := do(t, h, http.MethodDelete, path, `{"expected_revision":1}`, true); stale.Code != http.StatusConflict {
		t.Fatalf("stale delete status=%d body=%s", stale.Code, stale.Body.String())
	}
	if deleted := do(t, h, http.MethodDelete, path, `{"expected_revision":2}`, true); deleted.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", deleted.Code, deleted.Body.String())
	}
	oldID := rule.ID
	rec = do(t, h, http.MethodPost, "/admin/api/security/ignore-rules", create, true)
	if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &rule) != nil || rule.ID <= oldID {
		t.Fatalf("rebuilt rule reused old CAS identity: %+v status=%d", rule, rec.Code)
	}
	if stale := do(t, h, http.MethodDelete, path, `{"expected_revision":1}`, true); stale.Code != http.StatusNotFound {
		t.Fatalf("old delete found a rebuilt rule: %d", stale.Code)
	}
	var retained int
	if err := s.st.DB().QueryRow(`SELECT COUNT(*) FROM security_ignore_rule WHERE id=?`, rule.ID).Scan(&retained); err != nil || retained != 1 {
		t.Fatalf("old delete removed new rule: %d %v", retained, err)
	}
	for _, body := range []string{
		`{"scope":"rule","rule_id":"builtin:prompt_injection","route_id":7,"expires_at_ms":0,"enabled":true}`,
		`{"scope":"rule","rule_id":"builtin:prompt_injection","expires_at_ms":1,"enabled":true}`,
		`{"scope":"rule","rule_id":"builtin:prompt_injection","expires_at_ms":0,"enabled":true,"body":"do not persist"}`,
	} {
		bad := do(t, h, http.MethodPost, "/admin/api/security/ignore-rules", body, true)
		if bad.Code != http.StatusBadRequest {
			t.Fatalf("invalid ignore rule accepted: %d %s", bad.Code, bad.Body.String())
		}
	}
}

func TestSecurityManagementFiltersUseCapturedIdentityAndCurrentModeration(t *testing.T) {
	s, h := newTestServer(t)
	for _, f := range []security.Finding{
		{ID: "target", AtMS: 100, UpstreamID: 42, RouteID: 7, RuleID: "builtin:prompt_injection", Category: "prompt_injection"},
		{ID: "other-rule", AtMS: 100, UpstreamID: 42, RouteID: 7, RuleID: "custom:other", Category: "prompt_injection"},
		{ID: "historical-unknown", AtMS: 100, Upstream: "renamed-label", RouteID: 7, Category: "prompt_injection"},
	} {
		if err := s.st.InsertSecurityFinding(f); err != nil {
			t.Fatal(err)
		}
	}
	if rec := do(t, h, http.MethodPut, "/admin/api/security/findings/target/review", `{"expected_revision":1,"status":"false_positive"}`, true); rec.Code != 200 {
		t.Fatalf("review: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(t, h, http.MethodPost, "/admin/api/security/ignore-rules", `{"scope":"rule","rule_id":"builtin:prompt_injection","expires_at_ms":0}`, true); rec.Code != 201 {
		t.Fatalf("ignore: %d %s", rec.Code, rec.Body.String())
	}
	rec := do(t, h, http.MethodGet, "/admin/api/security/findings?upstream_id=42&rule_id=builtin%3Aprompt_injection&review_status=false_positive&ignored=true&limit=1", "", true)
	var page struct {
		Findings []struct {
			ID           string `json:"id"`
			Ignored      bool   `json:"ignored"`
			IgnoreRuleID int64  `json:"ignore_rule_id"`
			Review       struct {
				Status   string `json:"status"`
				Revision int64  `json:"revision"`
			} `json:"review"`
		} `json:"findings"`
		Total int `json:"total"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &page) != nil || len(page.Findings) != 1 || page.Total != 1 || page.Findings[0].ID != "target" || !page.Findings[0].Ignored || page.Findings[0].IgnoreRuleID <= 0 || page.Findings[0].Review.Revision != 2 || page.Findings[0].Review.Status != "false_positive" {
		t.Fatalf("captured/moderation filters not applied: status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, http.MethodGet, "/admin/api/security/ignore-rules?scope=rule&active=true&limit=1", "", true)
	var rules struct {
		Rules []struct {
			Revision int64 `json:"revision"`
		} `json:"rules"`
		Total int `json:"total"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &rules) != nil || rules.Total != 1 || len(rules.Rules) != 1 || rules.Rules[0].Revision != 1 {
		t.Fatalf("durable ignore page missing: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSecurityIgnorePolicyIsReadByInstalledMailerAfterRestart(t *testing.T) {
	s, _ := newTestServer(t)
	if err := s.st.InsertSecurityFinding(security.Finding{ID: "smtp-policy-source", RuleID: "builtin:prompt_injection"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.CreateSecurityIgnoreRule(context.Background(), security.IgnoreRule{Scope: "rule", RuleID: "builtin:prompt_injection", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.st.SaveSMTPConfig(store.SMTPConfig{Revision: 1, Enabled: true, Host: "smtp.example.test", Port: 587, UseSTARTTLS: true, From: "from@example.test", Recipients: "to@example.test", MinSeverity: "info", AggregationWindowSec: 7, RateLimitWindowSec: 13}, ""); err != nil {
		t.Fatal(err)
	}
	deliveries := 0
	m := security.NewAlertMailer().WithSendForTest(func(string, smtp.Auth, string, []string, []byte) error { deliveries++; return nil })
	s.WithAlertMailer(m)
	if err := m.MaybeNotify(security.Finding{RuleID: "builtin:prompt_injection", Severity: security.SeverityCritical}, ""); err != nil {
		t.Fatal(err)
	}
	if deliveries != 0 || m.Status().Suppressed != 1 {
		t.Fatalf("restart did not read existing SQL policy: deliveries=%d", deliveries)
	}
	s.st.DB().Exec(`DROP TABLE security_ignore_rule`)
	if err := m.MaybeNotify(security.Finding{RuleID: "custom:b", Severity: security.SeverityCritical}, ""); err == nil {
		t.Fatal("SQL failure treated as no ignore")
	}
	if deliveries != 0 || m.Status().PolicyFailures != 1 {
		t.Fatal("policy failure sent a message")
	}
	if err := m.SendTest(""); err != nil {
		t.Fatal(err)
	}
	if deliveries != 1 {
		t.Fatal("explicit SMTP test was blocked by policy failure")
	}
}

func TestSecurityAlertStatusExposesFiniteOperationalCounters(t *testing.T) {
	s, _ := newTestServer(t)
	m := security.NewAlertMailer()
	h := s.WithAlertMailer(m).Routes(testAdminPW)
	response := do(t, h, "GET", "/admin/api/security/alert-status", "", true)
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"policy_failures":0`) || !strings.Contains(response.Body.String(), `"pending":0`) {
		t.Fatalf("missing alert status: %d %s", response.Code, response.Body.String())
	}
}

func TestSecurityDiagnosticsResourceIsDurableReadOnlyAndStrict(t *testing.T) {
	_, h := newTestServer(t)
	rec := do(t, h, "GET", "/admin/api/security/diagnostics?limit=1&source=manual&verdict=passed", "", true)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"total":0`) || !strings.Contains(rec.Body.String(), `"items":[]`) {
		t.Fatalf("diagnostics missing: %d %s", rec.Code, rec.Body.String())
	}
	for _, q := range []string{"?unknown=1", "?source=scheduled", "?verdict=success", "?limit=-1", "?source=manual&source=periodic", "?route_id=-1"} {
		if got := do(t, h, "GET", "/admin/api/security/diagnostics"+q, "", true); got.Code != 400 {
			t.Fatalf("invalid diagnostic filter %s=%d", q, got.Code)
		}
	}
}
