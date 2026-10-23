package probe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/runstate"
)

type canaryTransportFunc func(outbound.NetworkConfig) (http.RoundTripper, error)

func (f canaryTransportFunc) RoundTripper(network outbound.NetworkConfig) (http.RoundTripper, error) {
	return f(network)
}

func approveCanaryEndpoint(t *testing.T, h *trafficHTTPHarness) {
	t.Helper()
	endpoint, err := h.store.Endpoint(context.Background(), h.up.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	endpoint.LegacyCompatRealOnly = false
	endpoint.AuthProfile = model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: "upstream_api_key"}
	if err := h.store.UpdateEndpoint(endpoint, endpoint.Revision); err != nil {
		t.Fatal(err)
	}
}

func TestCanaryPeriodicPolicyRecheckedImmediatelyBeforeSend(t *testing.T) {
	var requests atomic.Int64
	h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		body, _ := io.ReadAll(r.Body)
		nonce := canaryRequestNonce(t, body, model.EndpointMessages)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"content":[{"type":"tool_use","id":"one","name":"relay_canary_noop","input":{"nonce":%q}}],"stop_reason":"tool_use"}`, nonce)
	})
	approveCanaryEndpoint(t, h)
	service := manualAuthProbeService(t, h, h.store)
	scheduler := service.manual.(*Scheduler)
	scheduler.WithRunState(fixedSchedulerRunState{runstate.Snapshot{State: model.RunStateRunning, Revision: 1}}).WithCanary(service, h.store)
	policy, err := h.store.SaveCanaryPolicy(context.Background(), model.CanaryPolicy{UpstreamID: h.up.ID, RouteID: h.route.ID, Enabled: true, IntervalSec: 300})
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	original := service.executor.transports
	service.executor.transports = canaryTransportFunc(func(network outbound.NetworkConfig) (http.RoundTripper, error) {
		close(entered)
		<-release
		return original.RoundTripper(network)
	})
	snapshot, _ := scheduler.cfg.Snapshot()
	scheduler.tickCanaries(context.Background(), snapshot)
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("periodic execution did not reach the original transport preparation")
	}
	policy.Enabled = false
	if _, err := h.store.SaveCanaryPolicy(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	close(release)
	scheduler.wg.Wait()
	if requests.Load() != 0 {
		t.Fatalf("disabled armed Canary still sent: %d", requests.Load())
	}
	var verdict string
	if err := h.store.DB().QueryRow(`SELECT verdict FROM canary_execution`).Scan(&verdict); err != nil || verdict != "not_sent" {
		t.Fatalf("missing honest preflight result: %q %v", verdict, err)
	}
	var cost int
	if err := h.store.DB().QueryRow(`SELECT COUNT(*) FROM probe_cost_event`).Scan(&cost); err != nil || cost != 0 {
		t.Fatalf("unsent armed Canary charged: %d %v", cost, err)
	}
}

func TestCanaryRealClientCancellationClosesStreamAndPersistsCost(t *testing.T) {
	entered, closed := make(chan struct{}), make(chan struct{})
	h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"one\",\"name\":\"relay_canary_noop\",\"input\":{}}}\n\n")
		w.(http.Flusher).Flush()
		close(entered)
		<-r.Context().Done()
		close(closed)
	})
	approveCanaryEndpoint(t, h)
	service := manualAuthProbeService(t, h, h.store)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct {
		execution model.ProbeExecution
		err       error
	}
	done := make(chan result, 1)
	go func() { execution, err := service.RunCanary(ctx, h.route.ID); done <- result{execution, err} }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("Canary did not open physical SSE stream")
	}
	cancel()
	var actual result
	select {
	case actual = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Canary did not finish after caller cancel")
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream stream remained open after cancel")
	}
	if actual.err != nil || actual.execution.Canary == nil || actual.execution.Canary.Verdict != "canceled" {
		t.Fatalf("canceled Canary not durably returned: %+v %v", actual.execution.Canary, actual.err)
	}
	var requests, canceled, unknown int
	if err := h.store.DB().QueryRow(`SELECT requests,canceled,unknown_output_rows FROM canary_cost_daily`).Scan(&requests, &canceled, &unknown); err != nil || requests != 1 || canceled != 1 || unknown != 1 {
		t.Fatalf("canceled sent cost lost: %d/%d/%d %v", requests, canceled, unknown, err)
	}
	stored, err := h.store.GetProbeExecution(context.Background(), actual.execution.ID)
	if err != nil || stored.Canary == nil || stored.Canary.Verdict != "canceled" {
		t.Fatalf("canceled immutable facts missing: %+v %v", stored, err)
	}
}
