package probe

import (
	"context"

	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
)

// CapabilityRowSource 读出已落库的 EndpointCapability 行。由 store.Store 实现。
type CapabilityRowSource interface {
	ListEndpointCapabilitiesByState(ctx context.Context, state model.CapabilityState) ([]*model.EndpointCapability, error)
}

// PublishedConfigSource 提供同代已发布配置；首次调用时会从 Store 加载。由 livecfg.Source 实现。
type PublishedConfigSource interface {
	Bundle() (*livecfg.PublishedConfig, error)
}

// RestoreConfigErrors 在启动时把匹配当前 Observation Token 的 config_error 行
// 装回内存（docs/01 §5.2），返回装回的行数。
//
// 当前 token 按 Scheduler.attachExpectations 的同一路径现算：token 编码了行里
// 没有存的 RecipeIdentity，无法从行本身重算。算不出或不相等的行保持 unknown。
// 只恢复 config_error：supported 是旧正结论，unsupported 不跨重启。
func (registry *CapabilityRegistry) RestoreConfigErrors(ctx context.Context, rows CapabilityRowSource,
	configs PublishedConfigSource, recipes *RecipeResolver) (int, error) {

	if registry == nil || rows == nil || configs == nil || recipes == nil {
		return 0, nil
	}
	list, err := rows.ListEndpointCapabilitiesByState(ctx, model.CapabilityConfigError)
	if err != nil {
		return 0, err
	}
	if len(list) == 0 {
		return 0, nil
	}
	pub, err := configs.Bundle()
	if err != nil {
		return 0, err
	}
	if pub == nil || pub.Probe == nil {
		return 0, livecfg.ErrProbeSnapshotUnavailable
	}
	snap := pub.Probe
	restored := 0
	for _, row := range list {
		if row == nil || row.State != model.CapabilityConfigError || row.ObservationToken == "" {
			continue
		}
		token, ok := currentCapabilityToken(ctx, snap, recipes, row)
		if !ok || token != row.ObservationToken {
			continue
		}
		registry.ApplyCommitted(row)
		restored++
	}
	return restored, nil
}

// RestoreRealSuccesses restores only current piggyback evidence. Positive
// capability itself is demoted to unknown until another real/probe observation.
func (registry *CapabilityRegistry) RestoreRealSuccesses(ctx context.Context, rows CapabilityRowSource,
	configs PublishedConfigSource, recipes *RecipeResolver) (int, error) {
	if registry == nil || rows == nil || configs == nil || recipes == nil {
		return 0, nil
	}
	list, err := rows.ListEndpointCapabilitiesByState(ctx, model.CapabilitySupported)
	if err != nil {
		return 0, err
	}
	pub, err := configs.Bundle()
	if err != nil {
		return 0, err
	}
	if pub == nil || pub.Probe == nil {
		return 0, livecfg.ErrProbeSnapshotUnavailable
	}
	count := 0
	for _, row := range list {
		if row == nil || row.ScopeType != model.RecipeScopeRoute || row.Endpoint == model.EndpointCountTokens || row.LastRealOKAt <= 0 || row.LastRealOKToken == "" {
			continue
		}
		primary, ok := currentCapabilityToken(ctx, pub.Probe, recipes, row)
		if !ok || primary != row.ObservationToken {
			continue
		}
		real := *row
		real.PolicySelector = model.EvidencePolicySelector{Kind: model.EvidenceRealTraffic, Endpoint: row.Endpoint}
		realToken, ok := currentCapabilityToken(ctx, pub.Probe, recipes, &real)
		if !ok || realToken != row.LastRealOKToken {
			continue
		}
		restored := *row
		restored.State = model.CapabilityUnknown
		registry.ApplyCommitted(&restored)
		count++
	}
	return count, nil
}

func currentCapabilityToken(ctx context.Context, snap *livecfg.ProbeSnapshot, recipes *RecipeResolver,
	row *model.EndpointCapability) (string, bool) {

	expectation := currentCapabilityExpectation(ctx, snap, recipes, row)
	if expectation == nil {
		return "", false
	}
	return expectation.ObservationToken, true
}

func currentCapabilityExpectation(ctx context.Context, snap *livecfg.ProbeSnapshot, recipes *RecipeResolver,
	row *model.EndpointCapability) *model.SemanticExpectation {

	var upstreamID int64
	var route *model.Route
	switch row.ScopeType {
	case model.RecipeScopeUpstream:
		if row.Endpoint != model.EndpointModels {
			return nil
		}
		upstreamID = row.ScopeID
	case model.RecipeScopeRoute:
		route = snap.Routes[row.ScopeID]
		if route == nil || row.Endpoint == model.EndpointModels {
			return nil
		}
		upstreamID = route.UpstreamID
	default:
		return nil
	}
	var routeID int64
	if route != nil {
		routeID = route.ID
	}
	recipe, err := recipes.Resolve(ctx, RecipeQuery{UpstreamID: upstreamID, RouteID: routeID, Endpoint: row.Endpoint})
	if err != nil {
		return nil
	}
	var expectation *model.SemanticExpectation
	if route == nil {
		_, _, expectation, _, err = buildL1Expectations(snap, upstreamID, recipe)
	} else if row.PolicySelector.Kind == model.EvidenceRealTraffic {
		_, _, expectation, _, err = buildRealExpectations(snap, &model.Upstream{ID: upstreamID}, route, row.Endpoint, recipe)
	} else {
		_, _, expectation, _, err = buildL2Expectations(snap, &model.Upstream{ID: upstreamID}, route, row.Endpoint, recipe)
	}
	if err != nil {
		return nil
	}
	return expectation
}

// WithPublishedConfig supplies the current binding used by calibration and
// restart verification. ResultRecorder owns all live observation persistence.
func (registry *CapabilityRegistry) WithPublishedConfig(configs PublishedConfigSource, recipes *RecipeResolver) *CapabilityRegistry {
	if registry != nil {
		registry.configs = configs
		registry.recipes = recipes
	}
	return registry
}

// currentRouteExpectation 按 RestoreConfigErrors 同一路径现算 Route 端点的
// SemanticExpectation；未装配或算不出时返回 nil。
func (registry *CapabilityRegistry) currentRouteExpectation(ctx context.Context, routeID int64,
	endpoint model.EndpointKind) *model.SemanticExpectation {

	if registry == nil || registry.configs == nil || registry.recipes == nil || routeID <= 0 {
		return nil
	}
	pub, err := registry.configs.Bundle()
	if err != nil || pub == nil || pub.Probe == nil {
		return nil
	}
	return currentCapabilityExpectation(ctx, pub.Probe, registry.recipes, &model.EndpointCapability{
		ScopeType: model.RecipeScopeRoute, ScopeID: routeID, Endpoint: endpoint,
	})
}
