package proxy

import (
	"context"
	"net/http"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

type isolatedRetryFactory struct{ panicDecision bool }

func (f isolatedRetryFactory) PrepareAttempt(context.Context, health.AttemptTarget, health.AttemptRequestView) health.AttemptInstrumentation {
	instrument := health.NoopInstrumentation()
	if f.panicDecision {
		instrument.Retry = panicRetryDecision{}
	}
	return instrument
}

type panicRetryDecision struct{}

func (panicRetryDecision) DecidePeek(context.Context, int, http.Header, []byte, bool) health.RetryAdvice {
	panic("injected retry advice failure")
}

func TestRetry_KeepAndPanicAdviceNeverReplaysStructured200(t *testing.T) {
	for _, panicDecision := range []bool{false, true} {
		t.Run(map[bool]string{false: "keep", true: "panic"}[panicDecision], func(t *testing.T) {
			body := `{"error":{"type":"server_error","message":"first"}}`
			hs := newMultiHarness(t, respondStatus(200, body), respondOK(`{"id":"should-not-replay"}`))
			hs.cfg.settings.RetryPolicy = model.RetryPolicyAggressive
			hs.h.WithObservers(isolatedRetryFactory{panicDecision})
			response := hs.serve(hs.req())
			if response.Body.String() != body {
				t.Fatalf("advice failure replayed response: %s", response.Body.String())
			}
			hs.assertHits(t, 1, 0)
		})
	}
}
