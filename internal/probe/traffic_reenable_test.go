package probe

import (
	"context"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/observation"
	"github.com/279814/relay-gate/internal/store"
)

// Deliberately commit straight through ResultRecorder, without a runtime
// generation check: the database CAS must also reject a reset lifecycle.
func TestCapabilityTraffic_ReEnableRejectsInFlightFailure(t *testing.T) {
	for _, scope := range []string{"route", "upstream"} {
		for _, endpoint := range []model.EndpointKind{model.EndpointCountTokens, model.EndpointMessages} {
			t.Run(scope+"/"+string(endpoint), func(t *testing.T) {
				h := newCountTrafficHarness(t)
				h.seedEndpoint(t, endpoint, model.CapabilitySupported)
				late := h.beginEndpoint(endpoint)
				if scope == "route" {
					value := *h.route
					value.Enabled = false
					if err := h.store.UpdateRouteWithRevision(context.Background(), &value, value.Revision); err != nil {
						t.Fatal(err)
					}
					value.Enabled = true
					if err := h.store.UpdateRouteWithRevision(context.Background(), &value, value.Revision); err != nil {
						t.Fatal(err)
					}
				} else {
					value := *h.up
					value.Enabled = false
					if err := h.store.UpdateUpstreamWithRevision(context.Background(), &value, value.Revision); err != nil {
						t.Fatal(err)
					}
					value.Enabled = true
					if err := h.store.UpdateUpstreamWithRevision(context.Background(), &value, value.Revision); err != nil {
						t.Fatal(err)
					}
				}
				h.caps.InvalidateScope(model.RecipeScopeRoute, h.route.ID)
				status, body := 401, `{"error":{"type":"authentication_error"}}`
				if endpoint == model.EndpointMessages {
					status, body = 404, liveMissingModel
				}
				h.finish(t, late, status, body)
				if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, endpoint, ""); got != model.CapabilityUnknown {
					t.Fatalf("late failure poisoned re-enabled %s: %s", scope, got)
				}
				if got := restartedRegistry(t, h.store).Effective(model.RecipeScopeRoute, h.route.ID, endpoint, ""); got != model.CapabilityUnknown {
					t.Fatalf("restart revived pre-enable failure: %s", got)
				}
			})
		}
	}
}

type delayedCommittedObservation struct {
	store     *store.Store
	committed chan struct{}
	release   chan struct{}
}

func (d delayedCommittedObservation) CommitProbeObservation(ctx context.Context, value *model.ProbeObservation, reducer observation.StateReducer) (model.ProbeApplyResult, error) {
	result, err := d.store.CommitProbeObservation(ctx, value, reducer)
	close(d.committed)
	<-d.release
	return result, err
}

func TestCapabilityTraffic_ReEnableBeforeCommittedResultReturns(t *testing.T) {
	for _, scope := range []string{"route", "upstream"} {
		t.Run(scope, func(t *testing.T) {
			h := newCountTrafficHarness(t)
			tracker := health.NewTracker(nil)
			tracker.EnsureGeneration(h.route.ID)
			h.caps.WithRouteGeneration(tracker)
			h.seedEndpoint(t, model.EndpointMessages, model.CapabilitySupported)
			observer := h.beginEndpoint(model.EndpointMessages)
			observer.TryHeaders(404, nil, time.Now())
			observer.TryChunk([]byte(liveMissingModel), time.Now())
			observer.Finish(health.AttemptFinish{})
			var value *model.ProbeObservation
			select {
			case item := <-h.manager.queue:
				value = item.observation
			case <-time.After(time.Second):
				t.Fatal("observation not queued")
			}
			delayed := delayedCommittedObservation{store: h.store, committed: make(chan struct{}), release: make(chan struct{})}
			defer func() {
				select {
				case <-delayed.release:
				default:
					close(delayed.release)
				}
			}()
			recorder := NewResultRecorder(delayed, health.NewObservationReducer(nil), nil, h.caps)
			done := make(chan error, 1)
			go func() { _, err := recorder.Record(context.Background(), value); done <- err }()
			select {
			case <-delayed.committed:
			case <-time.After(2 * time.Second):
				t.Fatal("observation did not commit")
			}
			stored, err := h.store.ListEndpointCapabilitiesByState(context.Background(), model.CapabilityConfigError)
			if err != nil {
				t.Fatal(err)
			}
			if len(stored) != 1 {
				t.Fatalf("fixture must commit config_error before reset, rows=%d", len(stored))
			}
			if scope == "route" {
				value := *h.route
				value.Enabled = false
				if err := h.store.UpdateRouteWithRevision(context.Background(), &value, value.Revision); err != nil {
					t.Fatal(err)
				}
				value.Enabled = true
				if err := h.store.UpdateRouteWithRevision(context.Background(), &value, value.Revision); err != nil {
					t.Fatal(err)
				}
			} else {
				value := *h.up
				value.Enabled = false
				if err := h.store.UpdateUpstreamWithRevision(context.Background(), &value, value.Revision); err != nil {
					t.Fatal(err)
				}
				value.Enabled = true
				if err := h.store.UpdateUpstreamWithRevision(context.Background(), &value, value.Revision); err != nil {
					t.Fatal(err)
				}
			}
			health.NewSemanticInvalidator(tracker, nil, h.caps, nil, nil).ForgetRouteHealth(h.route.ID)
			close(delayed.release)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointMessages, ""); got != model.CapabilityUnknown {
				t.Fatalf("delayed committed result revived old lifecycle: %s", got)
			}
			if got := restartedRegistry(t, h.store).Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointMessages, ""); got != model.CapabilityUnknown {
				t.Fatalf("restart revived old lifecycle: %s", got)
			}
		})
	}
}
