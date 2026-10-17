package probe

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/observationseq"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

func disconnectBeforeHeaders(w http.ResponseWriter) {
	if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
		_ = conn.Close()
	}
}

// Scheduler fixtures exercise the production Executor and reducer. They supply
// configuration and persistence substitutes, never a second send/parser path.
func newSchedulerFixture(t *testing.T, cfg ConfigSource, transports TransportManager, track Tracker,
	reach *health.ReachabilityTracker, log *slog.Logger) *Scheduler {
	t.Helper()
	if reach == nil {
		reach = health.NewReachabilityTracker(cfg)
	}
	if transports == nil {
		transports = newFakeTransport()
	}
	seq, err := observationseq.Open(context.Background(), &fixtureOrders{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(seq.Close)
	recipes := builtinOnlyResolver()
	recorder := &schedulerFixtureRecorder{reach: reach, reducer: health.NewObservationReducer(nil), rows: map[int64]*model.UpstreamReachability{}}
	executor := NewExecutor(testTargets(), nil, recipes, transports, recorder, AlwaysOpenAdmission(), WallClock(), log)
	return NewScheduler(cfg, track, reach, log).WithRecipes(recipes).WithExecutor(executor).WithSequencer(seq)
}

func schedFixtureRoutes(cfg *fakeCfg, modelID int64) []*model.Route {
	snap, _ := cfg.Snapshot()
	return snap.RoutesByModelName[modelID]
}

func seedFixtureReach(reach *health.ReachabilityTracker, upstreamID int64, state model.ReachabilityState, settings ...model.Settings) {
	cfg := model.DefaultSettings()
	if len(settings) > 0 {
		cfg = settings[0]
	}
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	policy, _ := revisioncodec.BuildReachabilityEvidencePolicy(cfg, selector)
	fp := revisioncodec.ReachabilitySettingsFingerprint(policy)
	reach.ApplyCommitted(&model.UpstreamReachability{UpstreamID: upstreamID, State: state, PolicySelector: selector,
		SettingsFingerprint: fp, ObservationToken: revisioncodec.NewReachabilityToken(model.ReachabilityRevision{SettingsFingerprint: fp}), LastObservationOrder: 1})
}

type fixtureOrders struct {
	mu sync.Mutex
	hi int64
}

func (r *fixtureOrders) ReserveObservationOrders(_ context.Context, count int64) (int64, int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	first := r.hi + 1
	r.hi += count
	return first, r.hi, nil
}

func (f *fakeCfg) ProbeSnapshot() (*livecfg.ProbeSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.snapErr != nil {
		return nil, f.snapErr
	}
	if f.snap == nil {
		return nil, livecfg.ErrProbeSnapshotUnavailable
	}
	snap := &livecfg.ProbeSnapshot{Generation: 1, Settings: f.settings,
		Upstreams: map[int64]*model.ProbeUpstreamConfig{}, ModelNames: map[int64]*model.ModelName{},
		Routes: map[int64]*model.Route{}, Endpoints: map[int64]map[model.EndpointKind]*model.UpstreamEndpoint{}}
	for id, up := range f.snap.Upstreams {
		value := up.ProbeConfig()
		snap.Upstreams[id] = value
		snap.Endpoints[id] = map[model.EndpointKind]*model.UpstreamEndpoint{}
		for _, kind := range []model.EndpointKind{model.EndpointModels, model.EndpointMessages, model.EndpointResponses, model.EndpointChatCompletions, model.EndpointCountTokens} {
			ep, err := (testEndpoints{}).Endpoint(context.Background(), id, kind)
			if err != nil {
				return nil, err
			}
			snap.Endpoints[id][kind] = ep
		}
	}
	for _, mn := range f.snap.ModelNames {
		snap.ModelNames[mn.ID] = mn
	}
	for _, routes := range f.snap.RoutesByModelName {
		for _, rt := range routes {
			snap.Routes[rt.ID] = rt
		}
	}
	return snap, nil
}

func (f *gatingCfg) ProbeSnapshot() (*livecfg.ProbeSnapshot, error) {
	return f.inner.ProbeSnapshot()
}

func (f *fakeCfg) CachedProbeSnapshot() (*livecfg.ProbeSnapshot, error) {
	return f.ProbeSnapshot()
}

func (f *gatingCfg) CachedProbeSnapshot() (*livecfg.ProbeSnapshot, error) {
	return f.inner.CachedProbeSnapshot()
}

type schedulerFixtureRecorder struct {
	mu      sync.Mutex
	reach   *health.ReachabilityTracker
	reducer *health.ObservationReducer
	rows    map[int64]*model.UpstreamReachability
}

func (r *schedulerFixtureRecorder) Record(_ context.Context, v *model.ProbeObservation) (model.ProbeApplyResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := model.ProbeApplyResult{ExecutionStored: true, Reachability: model.ApplyNotApplicable, Capability: model.ApplyNotApplicable}
	if v.Execution.ErrorClass == model.ErrorIgnored {
		return result, nil
	}
	if exp, policy := v.ReachabilityExpectation, v.ReachabilityPolicy; exp != nil && policy != nil {
		row, err := r.reducer.ReduceReachability(r.rows[exp.UpstreamID], v.Execution, *policy)
		if err != nil {
			return result, err
		}
		row.UpstreamID, row.PolicySelector = exp.UpstreamID, exp.PolicySelector
		row.ObservedCreatedAt, row.ObservedNetworkRevision = exp.Revision.CreatedAt, exp.Revision.NetworkRevision
		row.SettingsFingerprint, row.ObservationToken = exp.Revision.SettingsFingerprint, exp.ObservationToken
		row.LastObservationOrder = v.Execution.ObservationOrder
		r.rows[exp.UpstreamID] = row
		r.reach.ApplyCommitted(row)
		result.Reachability, result.CommittedReachability = model.ApplyCurrent, row
	}
	if v.CapabilityExpectation != nil && v.CapabilityPolicy != nil {
		row, err := r.reducer.ReduceCapability(nil, v.Execution, *v.CapabilityPolicy)
		if err != nil {
			return result, err
		}
		result.Capability, result.CommittedCapability = model.ApplyCurrent, row
	}
	return result, nil
}
