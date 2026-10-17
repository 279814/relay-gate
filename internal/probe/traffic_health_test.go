package probe

import (
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

func TestTrafficHealth_StaleCapabilityCannotFailCurrentRoute(t *testing.T) {
	h := newCountTrafficHarness(t)
	cfg, _ := restoreTestDeps(h.store)
	tracker := health.NewTracker(cfg)
	generation := tracker.EnsureGeneration(h.route.ID)
	h.manager.WithHealthTracker(tracker)
	h.manager.applyHealth(trafficWrite{
		target: health.AttemptTarget{HealthGeneration: generation},
		observation: &model.ProbeObservation{Execution: model.ProbeExecution{
			RouteID: h.route.ID, Endpoint: model.EndpointMessages, StatusCode: 200,
			ErrorClass: model.ErrorPartial, Partial: true, Capability: model.CapabilityTransientError,
		}},
	}, model.ProbeApplyResult{Reachability: model.ApplyCurrent, Capability: model.ApplyConfigStale})
	if status := tracker.Status(h.route.ID); status.ConsecutiveFail != 0 {
		t.Fatalf("old capability failure was applied via current network evidence: %+v", status)
	}
}
