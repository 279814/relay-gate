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
	held map[int64]bool
}

// NewRecoveryGate constructs an empty gate.
func NewRecoveryGate() *RecoveryGate {
	return &RecoveryGate{held: map[int64]bool{}}
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
	if g.held[routeID] {
		return nil, false
	}
	g.held[routeID] = true
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			delete(g.held, routeID)
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
	g.held = map[int64]bool{}
	g.mu.Unlock()
}

// InFlight reports whether routeID currently holds the gate (tests).
func (g *RecoveryGate) InFlight(routeID int64) bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.held[routeID]
}
