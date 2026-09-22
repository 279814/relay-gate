package health

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestRecoveryGateSingleFlight(t *testing.T) {
	g := NewRecoveryGate()
	rel1, ok := g.TryAcquire(7)
	if !ok {
		t.Fatal("first acquire should succeed")
	}
	if _, ok := g.TryAcquire(7); ok {
		t.Fatal("second acquire on same route must fail")
	}
	rel2, ok := g.TryAcquire(8)
	if !ok {
		t.Fatal("other route should acquire")
	}
	rel2()
	rel1()
	if g.InFlight(7) || g.InFlight(8) {
		t.Fatal("release should clear")
	}
	if _, ok := g.TryAcquire(7); !ok {
		t.Fatal("after release should acquire again")
	}
}

func TestRecoveryGateReleaseIdempotent(t *testing.T) {
	g := NewRecoveryGate()
	rel, ok := g.TryAcquire(1)
	if !ok {
		t.Fatal("acquire")
	}
	rel()
	rel() // must not panic or corrupt
	if g.InFlight(1) {
		t.Fatal("still held after double release")
	}
}

func TestRecoveryGateConcurrent(t *testing.T) {
	g := NewRecoveryGate()
	var wins atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rel, ok := g.TryAcquire(42); ok {
				wins.Add(1)
				rel()
			}
		}()
	}
	wg.Wait()
	if wins.Load() == 0 {
		t.Fatal("expected at least one winner")
	}
}
