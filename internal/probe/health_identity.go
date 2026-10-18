package probe

import (
	"context"
	"errors"

	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

func capturedRouteHealthIdentity(snapshot *livecfg.ProbeSnapshot, route *model.SemanticExpectation, reach *model.ReachabilityExpectation, evidence *model.SemanticExpectation) *model.RouteHealthIdentity {
	if snapshot == nil || route == nil || route.Target.Scope != model.RecipeScopeRoute {
		return nil
	}
	rt := snapshot.Routes[route.Target.RouteID]
	if rt == nil {
		return nil
	}
	mn := snapshot.ModelNames[rt.ModelNameID]
	if mn == nil {
		return nil
	}
	return model.CloneRouteHealthIdentity(&model.RouteHealthIdentity{Version: 1, ModelNameID: mn.ID, ModelNameCreatedAt: mn.CreatedAt, Route: *route, Evidence: evidence, Reachability: reach, HealthSettingsFingerprint: revisioncodec.RouteHealthSettingsFingerprint(snapshot.Settings)})
}

// L1 affects captured children, but the child identity must also cover its
// model Endpoint/Recipe. An old station failure cannot be stamped onto a Route
// whose model configuration changed while that L1 request was in flight.
func capturedL1RouteHealthIdentity(snapshot *livecfg.ProbeSnapshot, routeID int64) *model.RouteHealthIdentity {
	if snapshot == nil {
		return nil
	}
	rt := snapshot.Routes[routeID]
	if rt == nil {
		return nil
	}
	mn := snapshot.ModelNames[rt.ModelNameID]
	if mn == nil {
		return nil
	}
	endpoint, ok := mn.Protocol.Endpoint()
	if !ok {
		return nil
	}
	resolver := NewRecipeResolver(snapshotRecipeSource{snapshot}).WithNotFound(func(err error) bool { return errors.Is(err, errSnapshotRecipeNotFound) })
	ctx := context.Background()
	modelRecipe, err := resolver.Resolve(ctx, RecipeQuery{UpstreamID: rt.UpstreamID, RouteID: rt.ID, Endpoint: endpoint})
	if err != nil {
		return nil
	}
	profile := modelRecipe.TimeoutProfile
	if profile == "" {
		profile = model.TimeoutL2Standard
	}
	modelExpectation, err := snapshot.SemanticExpectation(model.SemanticTarget{Scope: model.RecipeScopeRoute, UpstreamID: rt.UpstreamID, RouteID: rt.ID, Endpoint: endpoint}, modelRecipe.Identity, modelRecipe.Facts, model.EvidencePolicySelector{Kind: model.EvidenceL2, Endpoint: endpoint, TimeoutProfile: profile})
	if err != nil {
		return nil
	}
	l1Recipe, err := resolver.Resolve(ctx, RecipeQuery{UpstreamID: rt.UpstreamID, Endpoint: model.EndpointModels})
	if err != nil {
		return nil
	}
	reach, _, evidence, _, err := buildL1Expectations(snapshot, rt.UpstreamID, l1Recipe)
	if err != nil {
		return nil
	}
	identity := capturedRouteHealthIdentity(snapshot, &modelExpectation, reach, evidence)
	if identity != nil {
		identity.RouteContextOnly = true
	}
	return identity
}

func healthIdentityForResult(captured *model.RouteHealthIdentity, status int) *model.RouteHealthIdentity {
	identity := model.CloneRouteHealthIdentity(captured)
	if identity == nil {
		return nil
	}
	if status > 0 {
		// A legal response classifies model health through Capability. A change
		// to the independent reachability reducer cannot make that body stale.
		identity.Reachability = nil
		identity.RouteContextOnly = false
	} else {
		identity.RouteContextOnly = true
	}
	return identity
}

func capabilityContextCurrent(source any, captured *model.SemanticExpectation) bool {
	snapshot := healthSnapshot(source)
	if snapshot == nil || captured == nil {
		return false
	}
	policy, err := revisioncodec.BuildCapabilityEvidencePolicy(snapshot.Settings, captured.PolicySelector)
	if err != nil {
		return false
	}
	current := *captured
	current.Revision.ProbeSettingsFingerprint = revisioncodec.ProbeSettingsFingerprint(policy)
	current.ObservationToken = revisioncodec.NewObservationToken(current.Revision)
	return capabilityHealthCurrent(source, &current)
}
