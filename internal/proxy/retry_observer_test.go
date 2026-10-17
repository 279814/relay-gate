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

func TestRetryMissingObservationNeverFallsBackToRetiredPayloadParser(t *testing.T) {
	body := `{"error":{"type":"server_error","message":"keep original"}}`
	hs := newMultiHarness(t, respondStatus(200, body), respondOK(`{"id":"must-not-replay"}`))
	hs.cfg.settings.RetryPolicy = model.RetryPolicyAggressive
	hs.h.observers = nil
	response := hs.serve(hs.req())
	if response.Body.String() != body {
		t.Fatalf("missing observer replayed a structured 200: %s", response.Body.String())
	}
	hs.assertHits(t, 1, 0)
}

type targetRecordingFactory struct{ targets []health.AttemptTarget }

func (factory *targetRecordingFactory) PrepareAttempt(_ context.Context, target health.AttemptTarget, _ health.AttemptRequestView) health.AttemptInstrumentation {
	factory.targets = append(factory.targets, target)
	return health.NoopInstrumentation()
}

func TestRetry_EveryAttemptHasSharedRequestIdentityAndOrdinal(t *testing.T) {
	hs := newMultiHarness(t, respondStatus(503, `{"error":{"type":"server_error"}}`), respondOK(`{"id":"final"}`))
	hs.cfg.settings.RetryPolicy = model.RetryPolicyBalanced
	factory := &targetRecordingFactory{}
	hs.h.WithObservers(factory)
	response := hs.serve(hs.req())
	if response.Code != 200 {
		t.Fatalf("final response=%d", response.Code)
	}
	if len(factory.targets) != 2 {
		t.Fatalf("instrumented attempts=%d", len(factory.targets))
	}
	first, second := factory.targets[0], factory.targets[1]
	if first.ReqID == "" || first.ReqID != second.ReqID || first.Attempt != 1 || second.Attempt != 2 || first.RouteID == second.RouteID {
		t.Fatalf("attempt metadata not fixed independently: first=%+v second=%+v", first, second)
	}
}
