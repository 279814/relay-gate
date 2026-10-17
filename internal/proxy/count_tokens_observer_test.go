package proxy

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

type countAttemptObserver struct {
	target   health.AttemptTarget
	status   int
	body     []byte
	finished int
	finish   health.AttemptFinish
}

type observedResultReporter struct{ view *ResultView }

func (r *observedResultReporter) ReportResult(_ int64, _ uint64, view *ResultView) { r.view = view }
func (r *observedResultReporter) TriggerProbe(int64)                               {}

func (o *countAttemptObserver) PrepareAttempt(_ context.Context, target health.AttemptTarget, _ health.AttemptRequestView) health.AttemptInstrumentation {
	o.target = target
	return health.AttemptInstrumentation{Observer: o}
}
func (o *countAttemptObserver) TryHeaders(status int, _ http.Header, _ time.Time) bool {
	o.status = status
	return true
}
func (o *countAttemptObserver) TryChunk(chunk []byte, _ time.Time) bool {
	o.body = append(o.body, chunk...)
	return true
}
func (o *countAttemptObserver) Finish(v health.AttemptFinish) { o.finished++; o.finish = v }

func TestCountTokens_ObserverOwnsCapabilityObservation(t *testing.T) {
	for _, status := range []int{200, 401, 404} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			body := `{"input_tokens":12345}`
			hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = w.Write([]byte(body))
			})
			caps := &memoryCountCaps{}
			observer := &countAttemptObserver{}
			hs.h.WithCountTokensCapability(caps).WithObservers(observer)
			response := hs.serve(hs.countTokensRequest(`{"model":"claude-opus-5","messages":[]}`))
			if response.Code != 200 {
				t.Fatalf("response status=%d", response.Code)
			}
			if observer.target.Endpoint != model.EndpointCountTokens || observer.target.RouteID != 100 ||
				observer.status != status || string(observer.body) != body || observer.finished != 1 {
				t.Fatalf("count_tokens observer not wired: %+v", observer)
			}
			if caps.Effective(model.RecipeScopeRoute, 100, model.EndpointCountTokens, "") != model.CapabilityUnknown {
				t.Fatal("legacy MarkCountTokens wrote alongside committed observer")
			}
			if status == 200 && response.Body.String() != body {
				t.Fatalf("response changed: %s", response.Body.String())
			}
		})
	}
}

func TestModelError_ObserverReceivesBoundedErrorAndOwnsCapability(t *testing.T) {
	body := `{"error":{"code":"model_not_found","message":"missing"}}`
	hs := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		_, _ = w.Write([]byte(body))
	})
	observer := &countAttemptObserver{}
	reporter := &observedResultReporter{}
	hs.h.WithObservers(observer).WithHealthReporter(reporter)
	response := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","messages":[]}`))
	if response.Code != 404 || response.Body.String() != body {
		t.Fatalf("upstream response changed: %d %s", response.Code, response.Body.String())
	}
	if string(observer.body) != body || observer.finished != 1 {
		t.Fatalf("model error not observed: %+v", observer)
	}
	if reporter.view == nil || !reporter.view.CapabilityObserved {
		t.Fatal("Reporter did not yield Capability ownership to observer")
	}
}

func TestLocalConfigError_ObserverFinishesWithoutLegacyWrite(t *testing.T) {
	hs := newHarness(t, nil)
	hs.cfg.snap.Upstreams[10].APIKey = ""
	caps := &routeConfigCaps{}
	observer := &countAttemptObserver{}
	hs.h.WithObservers(observer).WithCountTokensCapability(caps)
	response := hs.serve(hs.anthropicRequest(emptyKeyReqBody))
	if response.Code != 503 {
		t.Fatalf("local auth error status=%d", response.Code)
	}
	if observer.finished != 1 || !observer.finish.ConfigError {
		t.Fatalf("local observer not completed exactly once as config_error: %+v", observer)
	}
	if got := caps.Effective(model.RecipeScopeRoute, 100, model.EndpointMessages, ""); got == model.CapabilityConfigError {
		t.Fatal("legacy synchronous marker wrote alongside observer")
	}
}
