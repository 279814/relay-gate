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

// ForgetRouteHealth drops RouteHealth and RecoveryGate for one Route without
// scheduling probes or clearing Capability.
//
// Used when Enabled flips false→true: a pre-disable dead/cooldown verdict must
// not permanently block selection, but re-enable must not start L1/L2.
func (s *SemanticInvalidator) ForgetRouteHealth(routeID int64) {
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
}

// InvalidateUpstream clears reachability-adjacent Route state for every known
// Route under upstreamID when the caller also passes those route IDs.
//
// Also drops EndpointCapability rows keyed by RecipeScopeUpstream + upstreamID
// (L1 /models unsupported / config_error). Without this, delete + SQLite rowid
// reuse would inherit the old station verdict until a new observation.
func (s *SemanticInvalidator) InvalidateUpstream(upstreamID int64, routeIDs []int64) {
	if s == nil {
		return
	}
	for _, id := range routeIDs {
		s.InvalidateRoute(id)
	}
	if s.caps != nil && upstreamID > 0 {
		s.caps.InvalidateScope(model.RecipeScopeUpstream, upstreamID)
	}
	if s.learner != nil && upstreamID > 0 {
		s.learner.ForgetUpstream(upstreamID)
	}
}

// InvalidateModelName clears §9.2 Route runtime state for every Route under a
// ModelName whose Protocol / probe payload / matching name changed.
//
// Unlike InvalidateRoute, this must not invoke ScheduleClearer: ModelName edits
// only change L2 probe content (§4.5), and Scheduler.InvalidateRoute would also
// TriggerL1. Tracker.Forget already drops schedule reservations by deleting the
// route row; the caller then TriggerL2 via ConfigInvalidator.InvalidateModelName.
func (s *SemanticInvalidator) InvalidateModelName(_ int64, routeIDs []int64) {
	if s == nil {
		return
	}
	for _, routeID := range routeIDs {
		if routeID <= 0 {
			continue
		}
		s.mu.Lock()
		if s.tracker != nil {
			s.tracker.Forget(routeID)
		}
		if s.recovery != nil {
			s.recovery.Forget(routeID)
		}
		if s.caps != nil {
			s.caps.InvalidateScope(model.RecipeScopeRoute, routeID)
		}
		s.mu.Unlock()
	}
}
