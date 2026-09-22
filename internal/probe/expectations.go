package probe

// expectation 构造：Scheduler 在发送前从同一 ProbeSnapshot 计算双期望（§4.8）。

import (
	"fmt"

	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

// buildL1Expectations 为站级 /models 探活构造 Reachability + Capability 期望。
func buildL1Expectations(snap *livecfg.ProbeSnapshot, upstreamID int64, recipe ResolvedRecipe) (
	reach *model.ReachabilityExpectation, reachPolicy *model.ReachabilityReductionPolicy,
	cap *model.SemanticExpectation, capPolicy *model.CapabilityReductionPolicy, err error) {

	if snap == nil {
		return nil, nil, nil, nil, livecfg.ErrProbeSnapshotUnavailable
	}
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	reachExp, err := snap.ReachabilityExpectation(upstreamID, selector)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	reachPolicyBuilt, err := revisioncodec.BuildReachabilityEvidencePolicy(snap.Settings, selector)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	target := model.SemanticTarget{
		Scope: model.RecipeScopeUpstream, UpstreamID: upstreamID, Endpoint: model.EndpointModels,
	}
	capExp, err := snap.SemanticExpectation(target, recipe.Identity, recipe.Facts, selector)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	capPolicyBuilt, err := revisioncodec.BuildCapabilityEvidencePolicy(snap.Settings, selector)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return &reachExp, &reachPolicyBuilt.State, &capExp, &capPolicyBuilt.State, nil
}

// buildL2Expectations 为 Route 级模型探活构造双期望。
func buildL2Expectations(snap *livecfg.ProbeSnapshot, up *model.Upstream, rt *model.Route,
	endpoint model.EndpointKind, recipe ResolvedRecipe) (
	reach *model.ReachabilityExpectation, reachPolicy *model.ReachabilityReductionPolicy,
	cap *model.SemanticExpectation, capPolicy *model.CapabilityReductionPolicy, err error) {

	if snap == nil {
		return nil, nil, nil, nil, livecfg.ErrProbeSnapshotUnavailable
	}
	if up == nil || rt == nil {
		return nil, nil, nil, nil, fmt.Errorf("L2 expectation 缺少 upstream/route")
	}
	timeout := recipe.TimeoutProfile
	if timeout == "" {
		timeout = model.TimeoutL2Standard
	}
	selector := model.EvidencePolicySelector{
		Kind: model.EvidenceL2, Endpoint: endpoint, TimeoutProfile: timeout,
	}
	reachExp, err := snap.ReachabilityExpectation(up.ID, selector)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	reachPolicyBuilt, err := revisioncodec.BuildReachabilityEvidencePolicy(snap.Settings, selector)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	target := model.SemanticTarget{
		Scope: model.RecipeScopeRoute, UpstreamID: up.ID, RouteID: rt.ID, Endpoint: endpoint,
	}
	capExp, err := snap.SemanticExpectation(target, recipe.Identity, recipe.Facts, selector)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	capPolicyBuilt, err := revisioncodec.BuildCapabilityEvidencePolicy(snap.Settings, selector)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return &reachExp, &reachPolicyBuilt.State, &capExp, &capPolicyBuilt.State, nil
}
