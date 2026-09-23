package proxy

import (
	"context"
	"net/http"
	"testing"

	"github.com/279814/relay-gate/internal/health"
)

// panicAfterAcquireFactory panics from PrepareAttempt, which runs after
// max_concurrency / RecoveryGate acquire and before the upstream RoundTrip.
type panicAfterAcquireFactory struct{}

func (panicAfterAcquireFactory) PrepareAttempt(
	context.Context, health.AttemptTarget, health.AttemptRequestView,
) health.AttemptInstrumentation {
	panic("injected after concurrency/RecoveryGate acquire")
}

// §9.4: a handler panic after acquire must still Release the concurrency slot
// (net/http recovers; without defer the slot sticks for the process lifetime).
// The panic must not start another upstream attempt.
func TestHandler_ConcurrencySlotReleasedOnPanic(t *testing.T) {
	var upstreamHits int
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		w.Write([]byte(`{"id":"msg_1","type":"message"}`))
	})
	hs.cfg.snap.RoutesByModelName[1][0].MaxConcurrency = 1
	hs.h.WithObservers(panicAfterAcquireFactory{})

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected injected panic after acquire")
			}
		}()
		hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))
	}()

	if upstreamHits != 0 {
		t.Fatalf("panic before RoundTrip must not hit upstream, got %d hits", upstreamHits)
	}
	if _, open, _ := hs.health.stats(); open != 0 {
		t.Fatalf("concurrency slot stuck after panic: open=%d", open)
	}

	hs.h.WithObservers(nil)
	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))
	if rec.Code != 200 {
		t.Fatalf("next request must acquire again after panic release, got %d", rec.Code)
	}
	if upstreamHits != 1 {
		t.Fatalf("want exactly one upstream hit on the follow-up request, got %d", upstreamHits)
	}
}

// §9.4: RecoveryGate half-open permit must also Release on panic after acquire.
func TestHandler_RecoveryGateReleasedOnPanic(t *testing.T) {
	var upstreamHits int
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		w.Write([]byte(`{"id":"msg_1","type":"message"}`))
	})
	hs.health.recovering[100] = true
	hs.h.WithObservers(panicAfterAcquireFactory{})

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected injected panic after RecoveryGate acquire")
			}
		}()
		hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))
	}()

	if upstreamHits != 0 {
		t.Fatalf("panic before RoundTrip must not hit upstream, got %d hits", upstreamHits)
	}
	if hs.h.recovery.InFlight(100) {
		t.Fatal("RecoveryGate permit stuck after panic")
	}

	hs.h.WithObservers(nil)
	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))
	if rec.Code != 200 {
		t.Fatalf("next request must acquire RecoveryGate again, got %d", rec.Code)
	}
	if upstreamHits != 1 {
		t.Fatalf("want exactly one upstream hit on the follow-up request, got %d", upstreamHits)
	}
}
