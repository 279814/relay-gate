package health

import (
	"sync"

	"github.com/279814/relay-gate/internal/model"
)

// SemanticClearer clears per-Route runtime state required by §9.2 when
// configuration that changes request semantics is updated.
//
// Implementations must be safe to call immediately (no livecfg TTL wait).
type SemanticClearer interface {
	ForgetRoute(routeID int64)
}

// CapabilityClearer clears Endpoint Capability rows for a Route scope.
type CapabilityClearer interface {
	InvalidateScope(scope model.RecipeScope, scopeID int64)
}

// ScheduleClearer clears probe schedule reservations for a Route.
type ScheduleClearer interface {
	InvalidateRoute(routeID int64)
}

// LearnerClearer drops learned client-shape references for a Route/Upstream.
type LearnerClearer interface {
	ForgetUpstream(upstreamID int64)
}

// SemanticInvalidator is the unified entry that clears RouteHealth, cooldown,
// RecoveryGate, Capability, schedule holds, and learning refs (§9.2).
type SemanticInvalidator struct {
	mu       sync.Mutex
	tracker  *Tracker
	recovery *RecoveryGate
	caps     CapabilityClearer
	sched    ScheduleClearer
	learner  LearnerClearer
}

// NewSemanticInvalidator wires the §9.2 clearing surfaces. Any dependency may be nil.
func NewSemanticInvalidator(tracker *Tracker, recovery *RecoveryGate,
	caps CapabilityClearer, sched ScheduleClearer, learner LearnerClearer) *SemanticInvalidator {

	return &SemanticInvalidator{
		tracker: tracker, recovery: recovery, caps: caps, sched: sched, learner: learner,
	}
}

// InvalidateRoute clears all §9.2 runtime state for one Route immediately.
func (s *SemanticInvalidator) InvalidateRoute(routeID int64) {
	if s == nil || routeID <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tracker != nil {
		s.tracker.Forget(routeID)
	}
	if s.recovery != nil {
		s.recovery.Forget(routeID)
	}
	if s.caps != nil {
		s.caps.InvalidateScope(model.RecipeScopeRoute, routeID)
	}
	if s.sched != nil {
		s.sched.InvalidateRoute(routeID)
	}
}

// InvalidateUpstream clears reachability-adjacent Route state for every known
// Route under upstreamID when the caller also passes those route IDs.
func (s *SemanticInvalidator) InvalidateUpstream(upstreamID int64, routeIDs []int64) {
	if s == nil {
		return
	}
	for _, id := range routeIDs {
		s.InvalidateRoute(id)
	}
	if s.learner != nil && upstreamID > 0 {
		s.learner.ForgetUpstream(upstreamID)
	}
}
