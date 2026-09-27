package probe

import (
	"context"
	"time"

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
	} else {
		_, _, expectation, _, err = buildL2Expectations(snap, &model.Upstream{ID: upstreamID}, route, row.Endpoint, recipe)
	}
	if err != nil {
		return nil
	}
	return expectation
}

// ConfigErrorStore 落库真实流量得到的 Route config_error。由 store.Store 实现。
type ConfigErrorStore interface {
	SaveConfigErrorCapability(ctx context.Context, expectation *model.SemanticExpectation,
		statusCode int, errorClass model.ErrorClass, detail string, observedAt int64) error
}

// WithConfigErrorPersistence 让真实流量与校准的 config_error 以当前
// Observation Token 落库，重启后由 RestoreConfigErrors 装回（§5.2）。
// 必须在接流量前调用。
func (registry *CapabilityRegistry) WithConfigErrorPersistence(st ConfigErrorStore,
	configs PublishedConfigSource, recipes *RecipeResolver) *CapabilityRegistry {

	if registry != nil {
		registry.configErrors = st
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

const configErrorPersistTimeout = 5 * time.Second

// persistRouteConfigError 尽力落库；失败时内存标记照常生效，只是不跨重启。
func (registry *CapabilityRegistry) persistRouteConfigError(routeID int64, endpoint model.EndpointKind,
	statusCode int, errorClass model.ErrorClass, observedAt int64) {

	if registry == nil || registry.configErrors == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), configErrorPersistTimeout)
	defer cancel()
	expectation := registry.currentRouteExpectation(ctx, routeID, endpoint)
	if expectation == nil {
		return
	}
	_ = registry.configErrors.SaveConfigErrorCapability(ctx, expectation, statusCode, errorClass,
		string(errorClass), observedAt)
}
