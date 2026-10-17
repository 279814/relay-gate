package probe

import (
	"context"
	"errors"
)

// Flush follows proxy.Quiesce: no new HTTP admissions may be producing work.
// It first waits for full observers to enqueue, then traverses the same bounded
// persistence queue so completed executions and learning are durable on return.
func (m *TrafficObserverManager) Flush(ctx context.Context) error {
	m.observerMu.Lock()
	idle := m.workersIdle
	m.observerMu.Unlock()
	select {
	case <-idle:
	case <-ctx.Done():
		return ctx.Err()
	}
	done := make(chan error, 1)
	select {
	case m.queue <- trafficWrite{barrier: done}:
	case <-m.stop:
		return errors.New("traffic observer stopped")
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
