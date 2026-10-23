package api

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

type canaryAdminFixture struct {
	ProbeAdmin
	manualCalls, canaryCalls int
}

func (a *canaryAdminFixture) RunManual(context.Context, int64) (model.ProbeExecution, error) {
	a.manualCalls++
	return model.ProbeExecution{ID: "ordinary-recipe", Success: true}, nil
}
func (a *canaryAdminFixture) RunCanary(_ context.Context, id int64) (model.ProbeExecution, error) {
	a.canaryCalls++
	return model.ProbeExecution{ID: "actual-canary", RouteID: id, Success: true, Canary: &model.CanaryExecution{ExecutionID: "actual-canary", Source: model.CanaryManual, Verdict: "passed"}}, nil
}

func canaryAPIRoute(t *testing.T, s *Server) *model.Route {
	t.Helper()
	up := &model.Upstream{Name: "canary-api", BaseURL: "https://canary.example.test", APIKey: "synthetic-canary-api-credential", Enabled: true, ProbeMode: model.ProbeModeLazy}
	up.Defaults()
	if err := s.st.CreateUpstream(up); err != nil {
		t.Fatal(err)
	}
	name := &model.ModelName{Name: "canary-api-model", Protocol: model.ProtoAnthropic, Enabled: true}
	name.Defaults()
	if err := s.st.CreateModelName(name); err != nil {
		t.Fatal(err)
	}
	route := &model.Route{UpstreamID: up.ID, ModelNameID: name.ID, Enabled: true}
	route.Defaults()
	if err := s.st.CreateRoute(route); err != nil {
		t.Fatal(err)
	}
	return route
}

func TestSecurityCanaryHTTPManualLazyUsesActualRunner(t *testing.T) {
	s, _ := newTestServer(t)
	route := canaryAPIRoute(t, s)
	admin := &canaryAdminFixture{}
	h := s.WithProbeAdmin(admin).Routes(testAdminPW)
	response := do(t, h, "POST", "/admin/api/security/canary", fmt.Sprintf(`{"route_id":%d}`, route.ID), true)
	if response.Code != http.StatusAccepted {
		t.Fatalf("explicit manual Lazy Canary status=%d body=%s", response.Code, response.Body.String())
	}
	result := decodeBody[struct {
		ExecutionID string                 `json:"execution_id"`
		Canary      *model.CanaryExecution `json:"canary"`
	}](t, response)
	if result.ExecutionID != "actual-canary" || result.Canary == nil || result.Canary.Source != model.CanaryManual || admin.canaryCalls != 1 || admin.manualCalls != 0 {
		t.Fatalf("ordinary manual was mislabeled Canary: %+v calls=%d/%d", result, admin.canaryCalls, admin.manualCalls)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("Canary result is cacheable")
	}
}

func TestSecurityCanaryUnconfiguredCannotRecordFakeSuccess(t *testing.T) {
	s, _ := newTestServer(t)
	route := canaryAPIRoute(t, s)
	upstream, err := s.st.GetUpstream(route.UpstreamID)
	if err != nil {
		t.Fatal(err)
	}
	upstream.ProbeMode = model.ProbeModeActive
	if err := s.st.UpdateUpstreamWithRevision(context.Background(), upstream, upstream.Revision); err != nil {
		t.Fatal(err)
	}
	h := s.Routes(testAdminPW)
	response := do(t, h, "POST", "/admin/api/security/canary", fmt.Sprintf(`{"route_id":%d}`, route.ID), true)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured Canary accepted fake success: %d %s", response.Code, response.Body.String())
	}
}

func TestSecurityCanaryPolicyHTTPHasCASActiveGuardAndDurableAudit(t *testing.T) {
	s, _ := newTestServer(t)
	route := canaryAPIRoute(t, s)
	h := s.Routes(testAdminPW)
	path := fmt.Sprintf("/admin/api/security/canary-policy/%d", route.UpstreamID)
	response := do(t, h, "GET", path, "", true)
	if response.Code != http.StatusOK {
		t.Fatalf("Canary policy route status=%d want 200", response.Code)
	}
	initial := decodeBody[model.CanaryPolicy](t, response)
	if initial.Enabled || initial.Revision != 0 || initial.IntervalSec != 3600 || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("default Canary policy=%+v", initial)
	}
	body := fmt.Sprintf(`{"route_id":%d,"enabled":true,"interval_sec":900,"revision":0}`, route.ID)
	if response := do(t, h, "PUT", path, body, true); response.Code != http.StatusBadRequest {
		t.Fatalf("Lazy periodic policy accepted: %d", response.Code)
	}
	body = fmt.Sprintf(`{"route_id":%d,"enabled":false,"interval_sec":900,"revision":0}`, route.ID)
	response = do(t, h, "PUT", path, body, true)
	if response.Code != http.StatusOK || decodeBody[model.CanaryPolicy](t, response).Revision != 1 {
		t.Fatalf("disabled policy write=%d %s", response.Code, response.Body.String())
	}
	if response := do(t, h, "PUT", path, body, true); response.Code != http.StatusConflict {
		t.Fatalf("stale policy overwritten: %d", response.Code)
	}
	var auditOutcome, auditReason string
	if err := s.st.DB().QueryRow(`SELECT outcome,reason_code FROM audit_event WHERE action='security_canary_policy_update' AND resource_id=? ORDER BY id DESC LIMIT 1`, fmt.Sprint(route.UpstreamID)).Scan(&auditOutcome, &auditReason); err != nil || auditOutcome != "failed" || auditReason != "conflict" {
		t.Fatalf("policy CAS has no durable rejection audit: %q/%q %v", auditOutcome, auditReason, err)
	}
	if _, err := s.st.DB().Exec(`CREATE TRIGGER synthetic_canary_audit_fail BEFORE INSERT ON audit_event BEGIN SELECT RAISE(FAIL,'synthetic'); END`); err != nil {
		t.Fatal(err)
	}
	body = fmt.Sprintf(`{"route_id":%d,"enabled":false,"interval_sec":1200,"revision":1}`, route.ID)
	if response := do(t, h, "PUT", path, body, true); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing audit did not fail closed: %d", response.Code)
	}
	current, err := s.st.GetCanaryPolicy(context.Background(), route.UpstreamID)
	if err != nil || current.Revision != 1 || current.IntervalSec != 900 {
		t.Fatalf("policy changed without durable audit: %+v %v", current, err)
	}
}
