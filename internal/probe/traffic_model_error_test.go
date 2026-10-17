package probe

import (
	"context"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

const liveMissingModel = `{"error":{"type":"invalid_request_error","code":"model_not_found","message":"missing model"}}`

func TestModelErrorTraffic_ReplacesCommittedSupported(t *testing.T) {
	h := newCountTrafficHarness(t)
	prior := h.seedEndpoint(t, model.EndpointMessages, model.CapabilitySupported)
	h.finish(t, h.beginEndpoint(model.EndpointMessages), 404, liveMissingModel)
	got := h.caps.Snapshot(model.RecipeScopeRoute, h.route.ID, model.EndpointMessages)
	if got.State != model.CapabilityConfigError || got.LastObservationOrder <= prior.LastObservationOrder {
		t.Fatalf("live model_not_found did not replace supported: %+v", got)
	}
	if got := restartedRegistry(t, h.store).Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointMessages, ""); got != model.CapabilityConfigError {
		t.Fatalf("restart state=%s", got)
	}
}

func TestModelErrorTraffic_LateFailureCannotUndoManualRetest(t *testing.T) {
	h := newCountTrafficHarness(t)
	h.seedEndpoint(t, model.EndpointMessages, model.CapabilitySupported)
	late := h.beginEndpoint(model.EndpointMessages)
	newer := h.seedEndpoint(t, model.EndpointMessages, model.CapabilitySupported)
	h.finish(t, late, 404, liveMissingModel)
	got := h.caps.Snapshot(model.RecipeScopeRoute, h.route.ID, model.EndpointMessages)
	if got.State != model.CapabilitySupported || got.LastObservationOrder != newer.LastObservationOrder {
		t.Fatalf("late failure replaced manual retest: %+v", got)
	}
}

func TestModelErrorTraffic_ConfigChangeRejectsLateFailure(t *testing.T) {
	h := newCountTrafficHarness(t)
	h.seedEndpoint(t, model.EndpointMessages, model.CapabilitySupported)
	late := h.beginEndpoint(model.EndpointMessages)
	updated := *h.route
	updated.UpstreamModel = "different-model"
	if err := h.store.UpdateRouteWithRevision(context.Background(), &updated, h.route.Revision); err != nil {
		t.Fatal(err)
	}
	h.caps.InvalidateScope(model.RecipeScopeRoute, h.route.ID)
	h.finish(t, late, 404, liveMissingModel)
	if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointMessages, ""); got != model.CapabilityUnknown {
		t.Fatalf("late failure poisoned new configuration: %s", got)
	}
}

func TestModelErrorTraffic_FinishDoesNotWaitForDatabase(t *testing.T) {
	h := newCountTrafficHarness(t)
	h.seedEndpoint(t, model.EndpointMessages, model.CapabilitySupported)
	conn, err := h.store.DB().Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan struct{})
	go func() {
		observer := h.beginEndpoint(model.EndpointMessages)
		observer.TryHeaders(400, nil, time.Now())
		observer.TryChunk([]byte(liveMissingModel), time.Now())
		observer.Finish(health.AttemptFinish{})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		conn.Close()
		<-done
		t.Fatal("model-error observation waited for SQLite")
	}
	if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointMessages, ""); got != model.CapabilitySupported {
		t.Fatalf("result was applied outside shared persistence: %s", got)
	}
	conn.Close()
	h.commitQueued(t)
	if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointMessages, ""); got != model.CapabilityConfigError {
		t.Fatalf("queued result was not committed: %s", got)
	}
}

func TestCapabilityTraffic_PrepareAndFinishDoNotWaitForDatabase(t *testing.T) {
	h := newCountTrafficHarness(t)
	h.seed(t, model.CapabilitySupported)
	conn, err := h.store.DB().Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan struct{})
	go func() {
		observer := h.begin()
		observer.TryHeaders(401, nil, time.Now())
		observer.Finish(health.AttemptFinish{})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		conn.Close()
		<-done
		t.Fatal("observation preparation or finish waited for SQLite")
	}
	conn.Close()
	select {
	case observation := <-h.manager.queue:
		if _, err := h.manager.record.Record(context.Background(), observation.observation); err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("background observation was not queued")
	}
	if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointCountTokens, ""); got != model.CapabilityConfigError {
		t.Fatalf("async capability=%s", got)
	}
}

func TestCapabilityTraffic_LocalConfigErrorUsesCapturedObservation(t *testing.T) {
	h := newCountTrafficHarness(t)
	h.seedEndpoint(t, model.EndpointMessages, model.CapabilitySupported)
	for i := 0; i < fullObserverLeases+1; i++ {
		observer := h.beginEndpoint(model.EndpointMessages)
		observer.Finish(health.AttemptFinish{ConfigError: true})
		h.commitQueued(t)
	}
	if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointMessages, ""); got != model.CapabilityConfigError {
		t.Fatalf("local config failure=%s want config_error", got)
	}
	if got := h.manager.Stats().FullObserversInFlight; got != 0 {
		t.Fatalf("local failure leaked %d observer leases", got)
	}
}
