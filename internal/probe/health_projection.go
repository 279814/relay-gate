package probe

import (
	"context"
	"errors"
	"reflect"

	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
)

// ApplyCurrent describes the SQL commit instant. Health projection separately
// checks its captured expectation against the current immutable published view.
// No TTL refresh, Store access or Tracker lock is involved in these checks.
func healthSnapshot(source any) *livecfg.ProbeSnapshot {
	cache, ok := source.(interface {
		CachedProbeSnapshot() (*livecfg.ProbeSnapshot, error)
	})
	if !ok {
		return nil
	}
	snapshot, err := cache.CachedProbeSnapshot()
	if err != nil {
		return nil
	}
	return snapshot
}

func reachabilityHealthCurrent(source any, captured *model.ReachabilityExpectation) bool {
	snapshot := healthSnapshot(source)
	if snapshot == nil || captured == nil || captured.ObservationToken == "" {
		return false
	}
	upstream := snapshot.Upstreams[captured.UpstreamID]
	if upstream == nil || !upstream.Enabled {
		return false
	}
	current, err := snapshot.ReachabilityExpectation(captured.UpstreamID, captured.PolicySelector)
	return err == nil && current.ObservationToken == captured.ObservationToken && current.Revision == captured.Revision
}

func capabilityHealthCurrent(source any, captured *model.SemanticExpectation) bool {
	snapshot := healthSnapshot(source)
	if snapshot == nil || captured == nil || captured.ObservationToken == "" {
		return false
	}
	upstream := snapshot.Upstreams[captured.Target.UpstreamID]
	if upstream == nil || !upstream.Enabled {
		return false
	}
	if captured.Target.Scope == model.RecipeScopeRoute {
		route := snapshot.Routes[captured.Target.RouteID]
		if route == nil || !route.Enabled || route.UpstreamID != captured.Target.UpstreamID {
			return false
		}
		name := snapshot.ModelNames[route.ModelNameID]
		if name == nil || !name.Enabled {
			return false
		}
	}
	// SemanticExpectation consumes supplied facts; prove their current
	// precedence/absence before reusing them. This resolver reads only this
	// immutable snapshot, never the Store-backed Scheduler recipe source.
	recipes := NewRecipeResolver(snapshotRecipeSource{snapshot}).WithNotFound(func(err error) bool {
		return errors.Is(err, errSnapshotRecipeNotFound)
	})
	binding, err := recipes.Resolve(context.Background(), RecipeQuery{
		UpstreamID: captured.Target.UpstreamID, RouteID: captured.Target.RouteID, Endpoint: captured.Target.Endpoint,
	})
	if err != nil {
		return false
	}
	binding.Facts.Use = captured.BindingFacts.Use
	if !reflect.DeepEqual(binding.Identity, captured.Revision.RecipeIdentity) || !reflect.DeepEqual(binding.Facts, captured.BindingFacts) {
		return false
	}
	// Preserve the attempt's actual binding use, identity and selector. In
	// particular real_traffic_context must not become a newly resolved recipe.
	current, err := snapshot.SemanticExpectation(captured.Target, captured.Revision.RecipeIdentity,
		captured.BindingFacts, captured.PolicySelector)
	return err == nil && current.ObservationToken == captured.ObservationToken && reflect.DeepEqual(current.Revision, captured.Revision)
}
