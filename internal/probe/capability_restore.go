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

func currentCapabilityToken(ctx context.Context, snap *livecfg.ProbeSnapshot, recipes *RecipeResolver,
	row *model.EndpointCapability) (string, bool) {

	var upstreamID int64
	var route *model.Route
	switch row.ScopeType {
	case model.RecipeScopeUpstream:
		if row.Endpoint != model.EndpointModels {
			return "", false
		}
		upstreamID = row.ScopeID
	case model.RecipeScopeRoute:
		route = snap.Routes[row.ScopeID]
		if route == nil || row.Endpoint == model.EndpointModels {
			return "", false
		}
		upstreamID = route.UpstreamID
	default:
		return "", false
	}
	var routeID int64
	if route != nil {
		routeID = route.ID
	}
	recipe, err := recipes.Resolve(ctx, RecipeQuery{UpstreamID: upstreamID, RouteID: routeID, Endpoint: row.Endpoint})
	if err != nil {
		return "", false
	}
	var expectation *model.SemanticExpectation
	if route == nil {
		_, _, expectation, _, err = buildL1Expectations(snap, upstreamID, recipe)
	} else {
		_, _, expectation, _, err = buildL2Expectations(snap, &model.Upstream{ID: upstreamID}, route, row.Endpoint, recipe)
	}
	if err != nil || expectation == nil {
		return "", false
	}
	return expectation.ObservationToken, true
}
