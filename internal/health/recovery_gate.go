package health

import (
	"sync"
)

// RecoveryGate is the per-Route single-flight half-open recovery lock (§9.4).
//
// It is independent of max_concurrency: even when max_concurrency=0 (unlimited
// ordinary slots), at most one recovering/dead probe Attempt may hold the gate.
type RecoveryGate struct {
	mu   sync.Mutex
	held map[int64]uint64 // routeID → acquire generation while held
	seq  uint64           // monotonic token source for held values
}

// NewRecoveryGate constructs an empty gate.
func NewRecoveryGate() *RecoveryGate {
	return &RecoveryGate{held: map[int64]uint64{}}
}

// TryAcquire attempts to take the recovery slot for routeID.
// ok=false means another recovering Attempt is already in flight; callers must
// pick another Route or return 503 — they must not queue.
func (g *RecoveryGate) TryAcquire(routeID int64) (release func(), ok bool) {
	if g == nil {
		return func() {}, true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, taken := g.held[routeID]; taken {
		return nil, false
	}
	g.seq++
	token := g.seq
	g.held[routeID] = token
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			// Only clear if this acquire still owns the slot. Forget + reuse of
			// the same route id must not let a stale release drop the new hold.
			if g.held[routeID] == token {
				delete(g.held, routeID)
			}
			g.mu.Unlock()
		})
	}, true
}

// Forget drops a held slot without requiring the release closure (config invalidate).
func (g *RecoveryGate) Forget(routeID int64) {
	if g == nil {
		return
	}
	g.mu.Lock()
	delete(g.held, routeID)
	g.mu.Unlock()
}

// Reset clears all held slots (tests / full invalidate).
func (g *RecoveryGate) Reset() {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.held = map[int64]uint64{}
	g.mu.Unlock()
}

// InFlight reports whether routeID currently holds the gate (tests).
func (g *RecoveryGate) InFlight(routeID int64) bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	_, ok := g.held[routeID]
	return ok
}
