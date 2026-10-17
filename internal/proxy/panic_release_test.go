package proxy

import (
	"context"
	"net/http"
	"testing"
	"time"

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

type panicTrafficCallback struct {
	phase    string
	finishes int
}

func (observer *panicTrafficCallback) PrepareAttempt(context.Context, health.AttemptTarget, health.AttemptRequestView) health.AttemptInstrumentation {
	return health.AttemptInstrumentation{Observer: observer, Retry: health.KeepAttemptDecider{}}
}
func (observer *panicTrafficCallback) TryRequest(health.AttemptRequestView) {
	if observer.phase == "request" {
		panic("request callback")
	}
}
func (observer *panicTrafficCallback) TryHeaders(int, http.Header, time.Time) bool {
	if observer.phase == "headers" {
		panic("headers callback")
	}
	return true
}
func (observer *panicTrafficCallback) TryChunk([]byte, time.Time) bool {
	if observer.phase == "chunk" {
		panic("chunk callback")
	}
	return true
}
func (observer *panicTrafficCallback) Finish(health.AttemptFinish) {
	observer.finishes++
	if observer.phase == "finish" {
		panic("finish callback")
	}
}

func TestHandler_ObserverCallbacksCannotInterruptForwarding(t *testing.T) {
	for _, phase := range []string{"request", "headers", "chunk", "finish"} {
		t.Run(phase, func(t *testing.T) {
			body := `{"type":"message","content":[{"type":"text","text":"ok"}]}`
			hs := newHarness(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) })
			observer := &panicTrafficCallback{phase: phase}
			hs.h.WithObservers(observer)
			response := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))
			if response.Code != 200 || response.Body.String() != body || observer.finishes != 1 {
				t.Fatalf("callback interrupted response or duplicated Finish: status=%d finishes=%d body=%s", response.Code, observer.finishes, response.Body.String())
			}
		})
	}
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

	if rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`)); rec.Code != 200 {
		t.Fatalf("observer panic interrupted forwarding: %d", rec.Code)
	}

	if upstreamHits != 1 {
		t.Fatalf("observer panic must preserve exactly one attempt, got %d hits", upstreamHits)
	}
	if _, open, _ := hs.health.stats(); open != 0 {
		t.Fatalf("concurrency slot stuck after panic: open=%d", open)
	}

	hs.h.WithObservers(nil)
	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))
	if rec.Code != 200 {
		t.Fatalf("next request must acquire again after panic release, got %d", rec.Code)
	}
	if upstreamHits != 2 {
		t.Fatalf("want one upstream hit per request, got %d", upstreamHits)
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

	if rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`)); rec.Code != 200 {
		t.Fatalf("observer panic interrupted half-open forwarding: %d", rec.Code)
	}

	if upstreamHits != 1 {
		t.Fatalf("observer panic must preserve exactly one attempt, got %d hits", upstreamHits)
	}
	if hs.h.recovery.InFlight(100) {
		t.Fatal("RecoveryGate permit stuck after panic")
	}

	hs.h.WithObservers(nil)
	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))
	if rec.Code != 200 {
		t.Fatalf("next request must acquire RecoveryGate again, got %d", rec.Code)
	}
	if upstreamHits != 2 {
		t.Fatalf("want one upstream hit per request, got %d", upstreamHits)
	}
}
