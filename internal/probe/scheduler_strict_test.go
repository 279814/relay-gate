package probe

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
)

func TestSchedulerMissingExecutorNeverUsesLegacyNetworkFallback(t *testing.T) {
	var calls atomic.Int64
	h := newSchedHarness(t, 1, func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); _, _ = w.Write([]byte(`{"data":[]}`)) })
	h.sched.executor = nil
	up := h.cfg.snap.Upstreams[10]
	h.sched.runL1(context.Background(), up, h.cfg.settings)
	if calls.Load() != 0 {
		t.Fatalf("missing Executor fell back to legacy networking: %d", calls.Load())
	}
}

type unavailableProbeConfig struct{ *fakeCfg }

func (c unavailableProbeConfig) ProbeSnapshot() (*livecfg.ProbeSnapshot, error) {
	return nil, livecfg.ErrProbeSnapshotUnavailable
}

func TestSchedulerCannotSendWithoutOrderOrCurrentExpectations(t *testing.T) {
	for _, name := range []string{"order", "snapshot", "recipes", "upstream_revision", "upstream_incarnation", "route_revision", "route_incarnation", "model_revision"} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int64
			h := newSchedHarness(t, 1, func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); _, _ = w.Write([]byte(`{"data":[]}`)) })
			up := *h.cfg.snap.Upstreams[10]
			route := *h.cfg.snap.RoutesByModelName[1][0]
			mn := *h.cfg.snap.ModelNames[0]
			switch name {
			case "order":
				h.sched.sequencer = nil
			case "snapshot":
				h.sched.cfg = unavailableProbeConfig{h.cfg}
			case "recipes":
				h.sched.recipes = nil
			case "upstream_revision":
				up.NetworkRevision--
			case "upstream_incarnation":
				up.CreatedAt--
			case "route_revision":
				route.CapabilityRevision--
			case "route_incarnation":
				route.CreatedAt--
			case "model_revision":
				mn.CapabilityRevision--
			}
			h.sched.execL2(context.Background(), &up, &mn, &route, h.cfg.settings)
			if calls.Load() != 0 {
				t.Fatalf("unsafe %s probe reached upstream: %d", name, calls.Load())
			}
			req := ExecutionRequest{Upstream: &up, ModelName: &mn, Route: &route, Endpoint: model.EndpointMessages}
			if err := h.sched.PrepareManual(context.Background(), &req); err == nil {
				t.Fatalf("manual %s did not fail closed", name)
			}
		})
	}
}

type emptyManualPreparer struct{}

func (emptyManualPreparer) PrepareManual(context.Context, *ExecutionRequest) error { return nil }

func TestRunManualRequiresBoundPreparationBeforeSending(t *testing.T) {
	for _, name := range []string{"missing", "empty"} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int64
			h := newSchedHarness(t, 1, func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				_, _ = w.Write([]byte(anthropicSemanticBody()))
			})
			svc := manualFixtureService(h.cfg, h.sched)
			if name == "missing" {
				svc.manual = nil
			} else {
				svc.manual = emptyManualPreparer{}
			}
			_, err := svc.RunManual(context.Background(), 100)
			if err == nil || calls.Load() != 0 {
				t.Fatalf("unbound manual request: err=%v sends=%d", err, calls.Load())
			}
		})
	}
}
