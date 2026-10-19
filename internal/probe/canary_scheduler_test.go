package probe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/runstate"
)

func TestCanaryPeriodicUsesExistingSchedulerGatesAndCompletionInterval(t *testing.T) {
	var calls atomic.Int64
	h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		nonce := canaryRequestNonce(t, body, model.EndpointMessages)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"content":[{"type":"tool_use","id":"one","name":"relay_canary_noop","input":{"nonce":%q}}],"stop_reason":"tool_use","usage":{"output_tokens":1}}`, nonce)
	})
	endpoint, err := h.store.Endpoint(context.Background(), h.up.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	endpoint.LegacyCompatRealOnly = false
	endpoint.AuthProfile = model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: "upstream_api_key"}
	if err := h.store.UpdateEndpoint(endpoint, endpoint.Revision); err != nil {
		t.Fatal(err)
	}
	service := manualAuthProbeService(t, h, h.store)
	scheduler := service.manual.(*Scheduler)
	scheduler.WithRunState(fixedSchedulerRunState{runstate.Snapshot{State: model.RunStateRunning, Revision: 1}})
	scheduler.WithCanary(service, h.store)
	clock := NewManualClock(time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC))
	service.executor.clock = clock
	tick := func() {
		t.Helper()
		snapshot, err := scheduler.cfg.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		scheduler.tickCanaries(context.Background(), snapshot)
		scheduler.wg.Wait()
	}
	tick()
	if calls.Load() != 0 {
		t.Fatal("periodic Canary enabled by default")
	}
	policy, err := h.store.SaveCanaryPolicy(context.Background(), model.CanaryPolicy{UpstreamID: h.up.ID, RouteID: h.route.ID, IntervalSec: 300, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	tick()
	if calls.Load() != 1 {
		t.Fatalf("enabled Active periodic calls=%d", calls.Load())
	}
	tick()
	clock.Advance(299 * time.Second)
	tick()
	if calls.Load() != 1 {
		t.Fatal("Canary ignored completion interval")
	}
	clock.Advance(time.Second)
	tick()
	if calls.Load() != 2 {
		t.Fatalf("due periodic calls=%d", calls.Load())
	}
	var source string
	var revision int64
	if err := h.store.DB().QueryRow(`SELECT source,policy_revision FROM canary_execution ORDER BY execution_id LIMIT 1`).Scan(&source, &revision); err != nil || source != "periodic" || revision != policy.Revision {
		t.Fatalf("scheduled Canary source=%q revision=%d %v", source, revision, err)
	}
	h.up.ProbeMode = model.ProbeModeLazy
	if err := h.store.UpdateUpstreamWithRevision(context.Background(), h.up, h.up.Revision); err != nil {
		t.Fatal(err)
	}
	cfg := service.snapshots.(*livecfg.Source)
	cfg.Invalidate()
	if err := cfg.Refresh(); err != nil {
		t.Fatal(err)
	}
	clock.Advance(300 * time.Second)
	tick()
	if calls.Load() != 2 {
		t.Fatal("Lazy emitted periodic Canary")
	}
	execution, err := service.RunCanary(context.Background(), h.route.ID)
	if err != nil || execution.Canary == nil || execution.Canary.Verdict != "passed" || execution.Canary.Source != model.CanaryManual || calls.Load() != 3 {
		t.Fatalf("Lazy manual exemption failed: %+v %v", execution, err)
	}
	h.up.ProbeMode = model.ProbeModeActive
	if err := h.store.UpdateUpstreamWithRevision(context.Background(), h.up, h.up.Revision); err != nil {
		t.Fatal(err)
	}
	cfg.Invalidate()
	if err := cfg.Refresh(); err != nil {
		t.Fatal(err)
	}
	scheduler.WithRunState(fixedSchedulerRunState{runstate.Snapshot{State: model.RunStatePaused, Revision: 2}})
	clock.Advance(300 * time.Second)
	tick()
	if calls.Load() != 3 {
		t.Fatal("paused gateway emitted periodic Canary")
	}
}
