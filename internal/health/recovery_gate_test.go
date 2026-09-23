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

// Forget 后迟到的 release 不得清掉同 id 新持有者的闸，也不得把计数弄成
// 「空闸可再 acquire 却实际仍有旧语义」的错乱。
func TestRecoveryGate_ReleaseAfterForgetDoesNotPoisonReusedID(t *testing.T) {
	g := NewRecoveryGate()
	const id int64 = 11

	oldRel, ok := g.TryAcquire(id)
	if !ok {
		t.Fatal("acquire before forget")
	}
	g.Forget(id)
	if g.InFlight(id) {
		t.Fatal("Forget should drop the slot")
	}
	oldRel() // no-op: nothing held
	if g.InFlight(id) {
		t.Fatal("stale release must not re-create a held slot")
	}

	newRel, ok := g.TryAcquire(id)
	if !ok {
		t.Fatal("reused id must acquire fresh gate")
	}
	oldRel()
	if !g.InFlight(id) {
		t.Fatal("stale release cleared the new holder's RecoveryGate")
	}
	if _, ok := g.TryAcquire(id); ok {
		t.Fatal("single-flight broken after stale release on reused id")
	}
	newRel()
	if g.InFlight(id) {
		t.Fatal("live release should clear")
	}
}
