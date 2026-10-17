package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/observationseq"
	"github.com/279814/relay-gate/internal/probe"
	"github.com/279814/relay-gate/internal/revisioncodec"
	"github.com/279814/relay-gate/internal/store"
)

// The API receives already committed evidence. This fixture stamps the same
// policy identity as the store/recorder, without a legacy mutable Gate map.
func applyAPIReachability(t *testing.T, tracker *health.ReachabilityTracker, settings model.Settings, id, revision int64, state model.ReachabilityState, order int64) {
	t.Helper()
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	policy, err := revisioncodec.BuildReachabilityEvidencePolicy(settings, selector)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := revisioncodec.ReachabilitySettingsFingerprint(policy)
	row := &model.UpstreamReachability{UpstreamID: id, State: state, PolicySelector: selector, ObservedNetworkRevision: revision, SettingsFingerprint: fingerprint, ObservationToken: revisioncodec.NewReachabilityToken(model.ReachabilityRevision{NetworkRevision: revision, SettingsFingerprint: fingerprint}), LastObservationOrder: order}
	if state == model.ReachabilityUnreachable {
		row.LastError = "fixture dial failed"
		row.LastErrorAt = 1000
	} else if state == model.ReachabilityReachable {
		row.LastOKAt = 2000
	}
	tracker.ApplyCommitted(row)
}

func TestGetHealthUsesCurrentReachabilityAndKeepsStaleDiagnosticSeparate(t *testing.T) {
	s, _ := newTestServer(t)
	seedConfig(t, s, 1, 1)
	upstreams, err := s.st.ListUpstreams()
	if err != nil {
		t.Fatal(err)
	}
	up := upstreams[0]
	routes, err := s.st.ListRoutes(0)
	if err != nil {
		t.Fatal(err)
	}
	route := routes[0]
	reach := health.NewReachabilityTracker(nil)
	h := s.WithHealth(stubHealth{}, reach).Routes(testAdminPW)
	row := healthRowsByRoute(t, h)[route.ID]
	if row["selectable"] != true {
		t.Fatalf("missing reachability must be optimistic unknown: %+v", row)
	}
	applyAPIReachability(t, reach, model.DefaultSettings(), up.ID, up.NetworkRevision, model.ReachabilityUnreachable, 1)
	row = healthRowsByRoute(t, h)[route.ID]
	if row["selectable"] != false || row["l1"].(map[string]any)["ok"] != false || row["l1"].(map[string]any)["probed"] != true {
		t.Fatalf("unreachable did not block selection: %+v", row)
	}
	if _, err := s.st.DB().Exec(`UPDATE upstream SET network_revision=network_revision+1 WHERE id=?`, up.ID); err != nil {
		t.Fatal(err)
	}
	row = healthRowsByRoute(t, h)[route.ID]
	status := row["l1"].(map[string]any)
	if row["selectable"] != true || status["ok"] != true || status["probed"] != false || status["last_error"] != "" {
		t.Fatalf("API trusted stored row's own stale revision: %+v", row)
	}
	if evidence := reach.Snapshot(up.ID); evidence == nil || evidence.State != model.ReachabilityUnreachable {
		t.Fatal("diagnostic read destroyed stale committed evidence")
	}
}

func TestGetHealthCommittedHTTP503IsReachableButTransportFailureBlocks(t *testing.T) {
	s, _ := newTestServer(t)
	seedConfig(t, s, 1, 1)
	upstreams, err := s.st.ListUpstreams()
	if err != nil {
		t.Fatal(err)
	}
	up := upstreams[0]
	routes, err := s.st.ListRoutes(0)
	if err != nil {
		t.Fatal(err)
	}
	route := routes[0]
	reach := health.NewReachabilityTracker(nil)
	h := s.WithHealth(stubHealth{}, reach).Routes(testAdminPW)
	reducer := health.NewObservationReducer(nil)
	policy := model.ReachabilityReductionPolicy{ReachableThreshold: 1, UnreachableThreshold: 1}
	for index, execution := range []model.ProbeExecution{
		{Reachable: true, StatusCode: 503, ErrorClass: model.ErrorTransient, SentAtMS: 100, GotConnAtMS: 110, ResponseHeaderAtMS: 120, DoneAtMS: 130},
		{Reachable: false, ErrorClass: model.ErrorUnreachable, SentAtMS: 200, DoneAtMS: 300, RedactedDetail: "dial failed"},
	} {
		committed, err := reducer.ReduceReachability(nil, execution, policy)
		if err != nil {
			t.Fatal(err)
		}
		applyAPIReachability(t, reach, model.DefaultSettings(), up.ID, up.NetworkRevision, committed.State, int64(index+1))
		row := healthRowsByRoute(t, h)[route.ID]
		if got := row["selectable"]; got != execution.Reachable {
			t.Fatalf("status=%d reachable=%v selectable=%v", execution.StatusCode, execution.Reachable, got)
		}
	}
}

type manualRunnerFunc func(context.Context, int64) (model.ProbeExecution, error)

func (f manualRunnerFunc) RunManual(ctx context.Context, id int64) (model.ProbeExecution, error) {
	return f(ctx, id)
}

type manualContextKey struct{}

func TestManualProbeRunnerReceivesOneCallWithOriginalContextAndNoLegacyOutcome(t *testing.T) {
	s, _ := newTestServer(t)
	calls := 0
	deadline := time.Now().Add(6 * time.Minute)
	runner := manualRunnerFunc(func(ctx context.Context, id int64) (model.ProbeExecution, error) {
		calls++
		if id != 42 || ctx.Value(manualContextKey{}) != "fixture" {
			t.Fatal("manual target/context changed")
		}
		if actual, ok := ctx.Deadline(); !ok || !actual.Equal(deadline) {
			t.Fatal("HTTP adapter imposed an old hardcoded timeout instead of passing request context")
		}
		return model.ProbeExecution{ID: "manual-one", RouteID: id, Success: true, Final: true}, nil
	})
	h := s.WithManualProbeRunner(runner).Routes(testAdminPW)
	ctx, cancel := context.WithDeadline(context.WithValue(context.Background(), manualContextKey{}, "fixture"), deadline)
	defer cancel()
	request := httptest.NewRequest(http.MethodPost, "/admin/api/routes/42/probe", nil).WithContext(ctx)
	request.Header.Set("Authorization", "Bearer "+testAdminPW)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != 200 || calls != 1 {
		t.Fatalf("manual calls/status=%d/%d %s", calls, response.Code, response.Body.String())
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if string(body["execution_id"]) != `"manual-one"` || string(body["ok"]) != "true" || body["execution"] == nil {
		t.Fatal("manual execution identity was lost")
	}
	if body["l1"] != nil || body["l2"] != nil {
		t.Fatal("manual API fabricated legacy L1/L2 outcomes")
	}
}

func TestManualProbeRunnerDomainErrorsKeepHTTPMeaning(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		status int
	}{{"missing target", store.ErrNotFound, 404}, {"paused admission", probe.ErrSyntheticClosed, 503}, {"unpublished snapshot", livecfg.ErrProbeSnapshotUnavailable, 503}, {"order unavailable", observationseq.ErrUnavailable, 503}} {
		t.Run(test.name, func(t *testing.T) {
			s, _ := newTestServer(t)
			calls := 0
			h := s.WithManualProbeRunner(manualRunnerFunc(func(context.Context, int64) (model.ProbeExecution, error) {
				calls++
				return model.ProbeExecution{}, test.err
			})).Routes(testAdminPW)
			response := do(t, h, "POST", "/admin/api/routes/42/probe", "", true)
			if calls != 1 || response.Code != test.status {
				t.Fatalf("calls=%d status=%d want %d: %s", calls, response.Code, test.status, response.Body.String())
			}
		})
	}
}
