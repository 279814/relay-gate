package probe

import (
	"context"
	"sync"
	"testing"
	"time"
)

type retentionCall struct {
	limit   int
	now     time.Time
	bounded bool
}
type retentionStoreSpy struct {
	mu    sync.Mutex
	calls []retentionCall
}

func (s *retentionStoreSpy) prune(ctx context.Context, now time.Time, limit int) (int, error) {
	_, bounded := ctx.Deadline()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, retentionCall{limit: limit, now: now, bounded: bounded})
	return 0, nil
}
func (s *retentionStoreSpy) PruneProbeExecutions(ctx context.Context, now time.Time, limit int) (int, error) {
	return s.prune(ctx, now, limit)
}
func (s *retentionStoreSpy) PruneCalibrationHistory(ctx context.Context, now time.Time, limit int) (int, error) {
	return s.prune(ctx, now, limit)
}
func (s *retentionStoreSpy) PruneProbeCostHistory(ctx context.Context, now time.Time, limit int) (int, error) {
	return s.prune(ctx, now, limit)
}

func TestRetentionJanitorBoundsEachCallAndStopsBeforeWorkOnShutdown(t *testing.T) {
	spy := &retentionStoreSpy{}
	j := NewRetentionJanitor(spy, discardLogger())
	j.now = func() time.Time { return time.Date(2026, 10, 18, 8, 0, 0, 0, time.FixedZone("UTC+8", 8*60*60)) }
	j.once(context.Background())
	if len(spy.calls) != 3 {
		t.Fatalf("calls=%d", len(spy.calls))
	}
	for _, call := range spy.calls {
		if !call.bounded || call.limit != 500 || call.now.Location() != time.UTC {
			t.Fatalf("unsafe cleanup budget: %+v", call)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	j.Run(ctx)
	if len(spy.calls) != 3 {
		t.Fatal("janitor started writes after shutdown")
	}
}

type blockingRetentionStore struct {
	retentionStoreSpy
	started chan struct{}
}

func (s *blockingRetentionStore) PruneProbeExecutions(ctx context.Context, _ time.Time, _ int) (int, error) {
	close(s.started)
	<-ctx.Done()
	return 0, ctx.Err()
}

func TestRetentionJanitorShutdownCancelsActivePrune(t *testing.T) {
	st := &blockingRetentionStore{started: make(chan struct{})}
	j := NewRetentionJanitor(st, discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); j.Run(ctx) }()
	select {
	case <-st.started:
	case <-time.After(time.Second):
		t.Fatal("prune did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel active prune")
	}
	if len(st.calls) != 0 {
		t.Fatal("shutdown continued to other cleanup methods")
	}
}
