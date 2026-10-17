package probe

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

func TestTrafficLimits_OversizedHeaderKeepsReachabilityOnly(t *testing.T) {
	h := newCountTrafficHarness(t)
	observer := h.begin()
	if observer.TryHeaders(200, http.Header{"X-Unbounded": {strings.Repeat("x", 32<<10)}}, time.Now()) {
		t.Fatal("oversized headers were copied into the observer")
	}
	observer.Finish(health.AttemptFinish{})
	h.commitQueued(t)
	page, err := h.store.ListProbeExecutions(context.Background(), model.ProbeExecutionFilter{Trigger: model.TriggerRealTraffic})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("execution missing: %v", err)
	}
	execution := page.Items[0]
	if !execution.ObserverIncomplete || execution.ObserverIncompleteReason != model.ObserverInputLimit || execution.CapabilityDisposition != model.ApplyNotApplicable || execution.ReachabilityDisposition != model.ApplyCurrent {
		t.Fatalf("header fallback=%+v", execution)
	}
}

type panicTrafficDecoder struct{}

func (panicTrafficDecoder) Feed([]byte) ([]ProtocolEvent, error) { panic("injected decoder failure") }
func (panicTrafficDecoder) Finish() ([]ProtocolEvent, error)     { return nil, nil }
func (panicTrafficDecoder) BytesSeen() int64                     { return 0 }

type panicTrafficFinishDecoder struct{ panicTrafficDecoder }

func (panicTrafficFinishDecoder) Feed([]byte) ([]ProtocolEvent, error) { return nil, nil }
func (panicTrafficFinishDecoder) Finish() ([]ProtocolEvent, error)     { panic("injected finish failure") }

func TestTrafficLimits_DecoderFinishPanicIsIsolated(t *testing.T) {
	h := newCountTrafficHarness(t)
	observer := h.begin().(*trafficObserver)
	observer.status = 200
	observer.capability.classifier = NewResponseClassifier(ObserveReal, model.EndpointCountTokens, 200, nil, time.Now())
	observer.capability.decoder = panicTrafficFinishDecoder{}
	observer.Finish(health.AttemptFinish{})
	h.commitQueued(t)
	if stats := h.manager.Stats(); stats.FullObserversInFlight != 0 || stats.ObserverBytesInFlight != 0 {
		t.Fatalf("Finish panic leaked resources: %+v", stats)
	}
	page, err := h.store.ListProbeExecutions(context.Background(), model.ProbeExecutionFilter{Trigger: model.TriggerRealTraffic})
	if err != nil || len(page.Items) != 1 || page.Items[0].ObserverIncompleteReason != model.ObserverPanic || page.Items[0].CapabilityDisposition != model.ApplyNotApplicable {
		t.Fatalf("Finish panic was not retained as incomplete evidence: %+v, %v", page.Items, err)
	}
}

func TestTrafficLimits_DecoderPanicReleasesBudgetAndLease(t *testing.T) {
	h := newCountTrafficHarness(t)
	observer := h.begin().(*trafficObserver)
	observer.status = 200
	observer.capability.classifier = NewResponseClassifier(ObserveReal, model.EndpointCountTokens, 200, nil, time.Now())
	observer.capability.decoder = panicTrafficDecoder{}
	observer.TryChunk([]byte("input"), time.Now())
	observer.Finish(health.AttemptFinish{})
	h.commitQueued(t)
	if stats := h.manager.Stats(); stats.FullObserversInFlight != 0 || stats.ObserverBytesInFlight != 0 {
		t.Fatalf("panic leaked resources: %+v", stats)
	}
	page, err := h.store.ListProbeExecutions(context.Background(), model.ProbeExecutionFilter{Trigger: model.TriggerRealTraffic})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("execution missing: %v", err)
	}
	if page.Items[0].ObserverIncompleteReason != model.ObserverPanic || page.Items[0].CapabilityDisposition != model.ApplyNotApplicable {
		t.Fatalf("panic applied a capability conclusion: %+v", page.Items[0])
	}
}

func TestTrafficLimits_CapacityKeepsReliableTransportFailure(t *testing.T) {
	h := newCountTrafficHarness(t)
	for i := 0; i < fullObserverLeases; i++ {
		<-h.manager.leases
	}
	observer := h.beginEndpoint(model.EndpointMessages)
	observer.TryHeaders(200, nil, time.Now())
	observer.Finish(health.AttemptFinish{ReadErr: health.ErrStreamBroke})
	h.commitQueued(t)
	page, err := h.store.ListProbeExecutions(context.Background(), model.ProbeExecutionFilter{Trigger: model.TriggerRealTraffic})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("execution missing: %v", err)
	}
	execution := page.Items[0]
	if execution.CapabilityDisposition != model.ApplyCurrent || execution.ErrorClass != model.ErrorTransient || execution.Success {
		t.Fatalf("capacity discarded independent transport evidence: cap=%s class=%s", execution.CapabilityDisposition, execution.ErrorClass)
	}
}
