package probe

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

type pausedTrafficRecorder struct {
	inner            ExecutionRecorder
	entered, release chan struct{}
}

func (p pausedTrafficRecorder) Record(ctx context.Context, value *model.ProbeObservation) (model.ProbeApplyResult, error) {
	close(p.entered)
	select {
	case <-p.release:
		return p.inner.Record(ctx, value)
	case <-ctx.Done():
		return model.ProbeApplyResult{}, ctx.Err()
	}
}

func TestTrafficFlush_WaitsForCommittedPersistence(t *testing.T) {
	h := newCountTrafficHarness(t)
	flusher, ok := any(h.manager).(interface{ Flush(context.Context) error })
	if !ok {
		t.Fatal("traffic manager has no persistence drain barrier")
	}
	pause := pausedTrafficRecorder{h.manager.record, make(chan struct{}), make(chan struct{})}
	h.manager.record = pause
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.manager.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	observer := h.begin()
	observer.TryHeaders(200, nil, time.Now())
	observer.TryChunk([]byte(`{"input_tokens":5}`), time.Now())
	observer.Finish(health.AttemptFinish{})
	<-pause.entered
	short, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer stop()
	if err := flusher.Flush(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked queue flush error=%v", err)
	}
	close(pause.release)
	full, stopFull := context.WithTimeout(context.Background(), time.Second)
	defer stopFull()
	if err := flusher.Flush(full); err != nil {
		t.Fatal(err)
	}
	if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointCountTokens, ""); got != model.CapabilitySupported {
		t.Fatalf("Flush returned before persistence applied: %s", got)
	}
	if stats := h.manager.Stats(); stats.FullObserversInFlight != 0 || stats.ObserverBytesInFlight != 0 || stats.ObservationQueueDepth != 0 {
		t.Fatalf("Flush left work behind: %+v", stats)
	}
}

func TestTrafficClose_ReclaimsUnfinishedObservers(t *testing.T) {
	h := newCountTrafficHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { h.manager.Run(ctx); close(done) }()
	observer := h.begin()
	observer.TryHeaders(200, nil, time.Now())
	observer.TryChunk([]byte(`{"input_tokens":5}`), time.Now())
	closed := make(chan struct{})
	go func() { h.manager.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("traffic shutdown did not finish within its bound")
	}
	stats := h.manager.Stats()
	if stats.FullObserversInFlight != 0 || stats.ObserverBytesInFlight != 0 {
		t.Fatalf("shutdown leaked observer resources: %+v", stats)
	}
	cancel()
	<-done
}
