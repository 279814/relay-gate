package probe

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/observationseq"
	"github.com/279814/relay-gate/internal/revisioncodec"
	"github.com/279814/relay-gate/internal/store"
)

type countTrafficHarness struct {
	store   *store.Store
	up      *model.Upstream
	route   *model.Route
	caps    *CapabilityRegistry
	manager *TrafficObserverManager
	seq     *observationseq.Sequencer
	now     time.Time
}

func newCountTrafficHarness(t *testing.T) *countTrafficHarness {
	t.Helper()
	st := calibrationTestStore(t)
	up, _, rt := seedCalibrationRoute(t, st)
	cfg, _ := restoreTestDeps(st)
	if _, err := cfg.Bundle(); err != nil {
		t.Fatal(err)
	}
	seq, err := observationseq.Open(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(seq.Close)
	caps := persistingRegistry(st)
	h := &countTrafficHarness{store: st, up: up, route: rt, caps: caps, seq: seq, now: time.Now()}
	caps.now = func() time.Time { return h.now }
	recorder := NewResultRecorder(st, health.NewObservationReducer(func() time.Time { return h.now }), nil, caps)
	manager := NewTrafficObserverManager(cfg, seq, recorder, discardLogger())
	h.manager = manager
	return h
}

func (h *countTrafficHarness) seed(t *testing.T, state model.CapabilityState) *model.EndpointCapability {
	return h.seedEndpoint(t, model.EndpointCountTokens, state)
}

func (h *countTrafficHarness) seedEndpoint(t *testing.T, endpoint model.EndpointKind, state model.CapabilityState) *model.EndpointCapability {
	t.Helper()
	ctx := context.Background()
	cfg, recipes := restoreTestDeps(h.store)
	if _, err := cfg.Bundle(); err != nil {
		t.Fatal(err)
	}
	snap, err := cfg.ProbeSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	recipe, err := recipes.Resolve(ctx, RecipeQuery{UpstreamID: h.up.ID, RouteID: h.route.ID, Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	selector := model.EvidencePolicySelector{Kind: model.EvidenceCountTokens, Endpoint: endpoint}
	if endpoint != model.EndpointCountTokens {
		selector = model.EvidencePolicySelector{Kind: model.EvidenceL2, Endpoint: endpoint, TimeoutProfile: model.TimeoutL2Standard}
	}
	expectation, err := snap.SemanticExpectation(model.SemanticTarget{
		Scope: model.RecipeScopeRoute, UpstreamID: h.up.ID, RouteID: h.route.ID, Endpoint: endpoint,
	}, recipe.Identity, recipe.Facts, selector)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := revisioncodec.BuildCapabilityEvidencePolicy(snap.Settings, selector)
	if err != nil {
		t.Fatal(err)
	}
	order, err := h.seq.Next(ctx, model.TriggerManual)
	if err != nil {
		t.Fatal(err)
	}
	executor := &Executor{}
	req := ExecutionRequest{
		ExecutionID: "manual-count-" + time.Now().Format("150405.000000000"), Trigger: model.TriggerManual,
		Upstream: h.up, Route: h.route, Endpoint: endpoint, ObservationOrder: order,
		CapabilityExpectation: &expectation, CapabilityPolicy: &policy.State,
	}
	exec := executor.buildExecution(req, recipe, Decision{Final: true, Capability: state, Scope: model.ScopeRouteEndpoint}, sendTiming{doneAtMS: time.Now().UnixMilli()}, 0, 0, 0, false, "", "")
	executor.recorder = NewResultRecorder(h.store, health.NewObservationReducer(func() time.Time { return h.now }), nil, h.caps)
	if _, err := executor.recordExecution(ctx, req, &exec); err != nil {
		t.Fatal(err)
	}
	return h.caps.Snapshot(model.RecipeScopeRoute, h.route.ID, endpoint)
}

func (h *countTrafficHarness) begin() health.AttemptObserver {
	return h.beginEndpoint(model.EndpointCountTokens)
}

func (h *countTrafficHarness) beginEndpoint(endpoint model.EndpointKind) health.AttemptObserver {
	return h.manager.PrepareAttempt(context.Background(), health.AttemptTarget{
		UpstreamID: h.up.ID, RouteID: h.route.ID, Endpoint: endpoint, Protocol: model.ProtoAnthropic,
	}, health.AttemptRequestView{}).Observer
}

func (h *countTrafficHarness) finish(t *testing.T, observer health.AttemptObserver, status int, body string) {
	t.Helper()
	observer.TryHeaders(status, http.Header{"Content-Type": {"application/json"}}, time.Now())
	if body != "" {
		observer.TryChunk([]byte(body), time.Now())
	}
	observer.Finish(health.AttemptFinish{})
	h.commitQueued(t)
}

func (h *countTrafficHarness) commitQueued(t *testing.T) {
	t.Helper()
	select {
	case observation := <-h.manager.queue:
		if _, err := h.manager.record.Record(context.Background(), observation); err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("observation not queued")
	}
}

func TestCountTokensTraffic_ReplacesCommittedCapability(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		expired bool
		want    model.CapabilityState
	}{
		{"auth rejection", 401, `{"error":{"type":"authentication_error"}}`, false, model.CapabilityConfigError},
		{"unsupported", 404, `{"error":{"message":"no endpoint"}}`, false, model.CapabilityUnsupported},
		{"success refreshes expired evidence", 200, `{"input_tokens":12}`, true, model.CapabilitySupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newCountTrafficHarness(t)
			row := h.seed(t, model.CapabilitySupported)
			if row.ObservationToken == "" {
				t.Fatal("fixture must have committed token")
			}
			if tc.expired {
				h.now = time.UnixMilli(row.ExpiresAt)
				if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointCountTokens, ""); got != model.CapabilityUnknown {
					t.Fatalf("expired state=%s", got)
				}
			}
			h.finish(t, h.begin(), tc.status, tc.body)
			got := h.caps.Snapshot(model.RecipeScopeRoute, h.route.ID, model.EndpointCountTokens)
			if got.State != tc.want || got.LastObservationOrder <= row.LastObservationOrder {
				t.Fatalf("after real observation state=%s order=%d, want %s newer than %d", got.State, got.LastObservationOrder, tc.want, row.LastObservationOrder)
			}
			if state := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointCountTokens, ""); state != tc.want {
				t.Fatalf("effective state=%s want %s", state, tc.want)
			}
			if tc.want == model.CapabilityConfigError {
				restored := restartedRegistry(t, h.store)
				if got := restored.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointCountTokens, ""); got != tc.want {
					t.Fatalf("after restart=%s want %s", got, tc.want)
				}
			}
		})
	}
}

func TestCountTokensTraffic_LateObservationCannotUndoManualRetest(t *testing.T) {
	h := newCountTrafficHarness(t)
	h.seed(t, model.CapabilitySupported)
	late := h.begin()
	newer := h.seed(t, model.CapabilitySupported)
	h.finish(t, late, 401, `{"error":{"type":"authentication_error"}}`)
	got := h.caps.Snapshot(model.RecipeScopeRoute, h.route.ID, model.EndpointCountTokens)
	if got.State != model.CapabilitySupported || got.LastObservationOrder != newer.LastObservationOrder {
		t.Fatalf("late result replaced retest: %+v", got)
	}
}

func TestCountTokensTraffic_ConfigErrorNeedsManualRetest(t *testing.T) {
	h := newCountTrafficHarness(t)
	h.seed(t, model.CapabilitySupported)
	h.finish(t, h.begin(), 401, `{"error":{"type":"authentication_error"}}`)
	if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointCountTokens, ""); got != model.CapabilityConfigError {
		t.Fatalf("after 401=%s want config_error", got)
	}
	h.finish(t, h.begin(), 200, `{"input_tokens":12}`)
	if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointCountTokens, ""); got != model.CapabilityConfigError {
		t.Fatalf("real success cleared config_error: %s", got)
	}
	h.seed(t, model.CapabilitySupported)
	if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointCountTokens, ""); got != model.CapabilitySupported {
		t.Fatalf("manual retest did not clear error: %s", got)
	}
}

func TestCountTokensTraffic_CapacityStillRecordsStatusEvidence(t *testing.T) {
	for _, status := range []int{401, 403, 404, 405} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			h := newCountTrafficHarness(t)
			h.seed(t, model.CapabilitySupported)
			for i := 0; i < fullObserverLeases; i++ {
				<-h.manager.leases
			}
			h.finish(t, h.begin(), status, "")
			want := model.CapabilityUnsupported
			if status == 401 || status == 403 {
				want = model.CapabilityConfigError
			}
			if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointCountTokens, ""); got != want {
				t.Fatalf("capacity fallback status=%d state=%s want %s", status, got, want)
			}
		})
	}
}

func TestCountTokensTraffic_Encoded401StillRecordsStatusEvidence(t *testing.T) {
	h := newCountTrafficHarness(t)
	h.seed(t, model.CapabilitySupported)
	observer := h.begin()
	observer.TryHeaders(401, http.Header{"Content-Encoding": {"gzip"}}, time.Now())
	observer.TryChunk([]byte("encoded bytes"), time.Now())
	observer.Finish(health.AttemptFinish{})
	h.commitQueued(t)
	if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointCountTokens, ""); got != model.CapabilityConfigError {
		t.Fatalf("encoded 401 capability=%s", got)
	}
}

func TestCapabilityTraffic_PrepareRejectsDifferentAttemptConfiguration(t *testing.T) {
	h := newCountTrafficHarness(t)
	snap, err := h.manager.cfg.ProbeSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	ep := snap.Endpoints[h.up.ID][model.EndpointCountTokens]
	up := snap.Upstreams[h.up.ID]
	route := snap.Routes[h.route.ID]
	mn := snap.ModelNames[route.ModelNameID]
	facts := health.AttemptConfigFacts{
		EndpointID: ep.ID, EndpointRevision: ep.Revision, AuthProfileRevision: ep.AuthProfile.Revision,
		UpstreamNetworkRevision: up.NetworkRevision, UpstreamCredentialRevision: up.CredentialRevision,
		RouteCapabilityRevision: route.CapabilityRevision, ModelCapabilityRevision: mn.CapabilityRevision,
		UpstreamCreatedAt: up.CreatedAt, RouteCreatedAt: route.CreatedAt,
	}
	for _, tc := range []struct {
		name   string
		change func(*health.AttemptConfigFacts)
	}{
		{"endpoint", func(f *health.AttemptConfigFacts) { f.EndpointRevision++ }},
		{"auth", func(f *health.AttemptConfigFacts) { f.AuthProfileRevision++ }},
		{"network", func(f *health.AttemptConfigFacts) { f.UpstreamNetworkRevision++ }},
		{"credential", func(f *health.AttemptConfigFacts) { f.UpstreamCredentialRevision++ }},
		{"route", func(f *health.AttemptConfigFacts) { f.RouteCapabilityRevision++ }},
		{"model", func(f *health.AttemptConfigFacts) { f.ModelCapabilityRevision++ }},
		{"reused upstream id", func(f *health.AttemptConfigFacts) { f.UpstreamCreatedAt++ }},
		{"reused route id", func(f *health.AttemptConfigFacts) { f.RouteCreatedAt++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stale := facts
			tc.change(&stale)
			if got := prepareCapabilityTraffic(context.Background(), snap, health.AttemptTarget{
				Endpoint: model.EndpointCountTokens, UpstreamID: h.up.ID, RouteID: h.route.ID, Config: stale,
			}, 1); got != nil {
				t.Fatal("stale attempt was assigned the current configuration token")
			}
		})
	}
}

func TestCapabilityTraffic_FinishRejectsDifferentResolvedEndpoint(t *testing.T) {
	h := newCountTrafficHarness(t)
	snap, err := h.manager.cfg.ProbeSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	observation := prepareCapabilityTraffic(context.Background(), snap, health.AttemptTarget{
		Endpoint: model.EndpointMessages, UpstreamID: h.up.ID, RouteID: h.route.ID,
	}, 1)
	if observation == nil {
		t.Fatal("current configuration was not observable")
	}
	changed := health.AttemptConfigFacts{EndpointRevision: observation.req.CapabilityExpectation.Revision.EndpointRevision + 1}
	if got := observation.observation(health.AttemptFinish{ConfigError: true, ConfigFacts: &changed}, sendTiming{}, false, 0, nil, ""); got != nil {
		t.Fatal("local failure used the token of a different endpoint configuration")
	}
}
