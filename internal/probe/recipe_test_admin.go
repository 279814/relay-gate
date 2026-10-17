package probe

import (
	"context"

	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/probetemplate"
	"github.com/279814/relay-gate/internal/sample"
	"github.com/279814/relay-gate/internal/store"
)

type ManualTestInput struct{ RouteID, ExpectedRevision int64 }

func (s *Service) Test(ctx context.Context, versionID int64, in ManualTestInput) (model.ProbeExecution, error) {
	version, err := s.GetVersion(ctx, versionID)
	if err != nil {
		return model.ProbeExecution{}, err
	}
	recipe, err := s.GetRecipe(ctx, version.RecipeID)
	if err != nil {
		return model.ProbeExecution{}, err
	}
	if in.ExpectedRevision < 1 {
		return model.ProbeExecution{}, model.WrapValidation("expected_revision 必须是正整数")
	}
	if recipe.Revision != in.ExpectedRevision {
		return model.ProbeExecution{}, store.ErrRevisionConflict
	}
	if recipe.Status == model.RecipeArchived {
		return model.ProbeExecution{}, model.WrapValidation("归档 Recipe 不能测试或发布")
	}
	snap, err := s.adminProbeSnapshot()
	if err != nil {
		return model.ProbeExecution{}, err
	}
	current := snap.Recipes[recipe.ID]
	if current == nil || current.Revision != recipe.Revision {
		return model.ProbeExecution{}, livecfg.ErrProbeSnapshotUnavailable
	}
	upConfig, route, mn, err := previewTarget(snap, recipe, in.RouteID)
	if err != nil {
		return model.ProbeExecution{}, err
	}
	compiled, err := probetemplate.Compile(recipe.Endpoint, version)
	if err != nil {
		return model.ProbeExecution{}, err
	}
	facts := model.RecipeBindingFacts{Use: model.BindingExplicitTest, ExplicitRecipeID: recipe.ID, ExplicitVersionID: version.ID, ExplicitRecipeRowRevision: recipe.Revision}
	layer := model.ResolvedUpstream
	if recipe.ScopeType == model.RecipeScopeRoute {
		layer = model.ResolvedRoute
		facts.ResolvedLayer = layer
		facts.RouteRecipeID = recipe.ID
		facts.RoutePublishedVersionID = version.ID
		facts.RouteBindingRevision = recipe.ActiveBindingRevision
	} else {
		facts.ResolvedLayer = layer
		facts.UpstreamRecipeID = recipe.ID
		facts.UpstreamPublishedVersionID = version.ID
		facts.UpstreamBindingRevision = recipe.ActiveBindingRevision
	}
	explicit := ResolvedRecipe{Layer: layer, Identity: model.RecipeIdentity{Storage: model.RecipeStorageDB, Origin: version.Origin, DBVersionID: version.ID}, Facts: facts, Compiled: compiled, SecretRefs: snap.RecipeVersionSecretRefs[version.ID], StreamExpected: version.StreamExpected, TimeoutProfile: version.TimeoutProfile}
	return s.executeAdminTest(ctx, snap, upConfig, route, mn, recipe.Endpoint, explicit)
}

func (s *Service) executeAdminTest(ctx context.Context, snap *livecfg.ProbeSnapshot, upConfig *model.ProbeUpstreamConfig, route *model.Route, mn *model.ModelName, endpoint model.EndpointKind, explicit ResolvedRecipe) (model.ProbeExecution, error) {
	if s.executor == nil || s.manual == nil {
		return model.ProbeExecution{}, model.WrapValidation("显式测试执行器/全局 observation sequencer 未装配")
	}
	up, err := s.store.GetUpstream(upConfig.ID)
	if err != nil {
		return model.ProbeExecution{}, err
	}
	if up.NetworkRevision != upConfig.NetworkRevision || up.CredentialRevision != upConfig.CredentialRevision || up.CreatedAt != upConfig.CreatedAt {
		return model.ProbeExecution{}, livecfg.ErrProbeSnapshotUnavailable
	}
	if err := errDisabledProbeTarget(route, up); err != nil {
		return model.ProbeExecution{}, err
	}
	if mn != nil && !mn.Enabled {
		return model.ProbeExecution{}, model.WrapValidation("ModelName 已停用，不能测试")
	}
	req := ExecutionRequest{ExecutionID: sample.NewReqID(), Trigger: model.TriggerManual, Upstream: up, Route: route, ModelName: mn, Endpoint: endpoint, Mode: ObserveProbe, ExplicitRecipe: &explicit}
	if err := s.manual.PrepareManual(ctx, &req); err != nil {
		return model.ProbeExecution{}, err
	}
	if req.ObservationOrder < 1 {
		return model.ProbeExecution{}, model.WrapValidation("没有可用 observation order，未发送测试")
	}
	// The manual preparer allocates the shared order, but its normal resolved
	// binding is deliberately replaced by this exact immutable candidate.
	if endpoint == model.EndpointModels {
		req.ReachabilityExpectation, req.ReachabilityPolicy, req.CapabilityExpectation, req.CapabilityPolicy, err = buildL1Expectations(snap, up.ID, explicit)
		req.Budget = outbound.L1Budget(snap.Settings)
	} else {
		req.ReachabilityExpectation, req.ReachabilityPolicy, req.CapabilityExpectation, req.CapabilityPolicy, err = buildL2Expectations(snap, up, route, endpoint, explicit)
		if endpoint == model.EndpointCountTokens {
			req.Budget = outbound.CountTokensBudget(snap.Settings)
		} else {
			req.Budget = outbound.L2BudgetForProfile(snap.Settings, explicit.TimeoutProfile)
		}
	}
	if err != nil {
		return model.ProbeExecution{}, err
	}
	result, err := s.executor.Execute(ctx, req)
	if err != nil {
		return model.ProbeExecution{}, err
	}
	return result.Execution, nil
}

func (s *Service) Publish(ctx context.Context, recipeID, versionID int64, testExecutionID string, expectedRevision int64, force bool) (model.ProbeRecipe, error) {
	if expectedRevision < 1 || testExecutionID == "" {
		return model.ProbeRecipe{}, model.WrapValidation("发布必须提供 expected_revision 和 test_execution_id")
	}
	recipe, err := s.GetRecipe(ctx, recipeID)
	if err != nil {
		return recipe, err
	}
	if recipe.Revision != expectedRevision {
		return recipe, store.ErrRevisionConflict
	}
	version, err := s.GetVersion(ctx, versionID)
	if err != nil {
		return recipe, err
	}
	if version.RecipeID != recipeID {
		return recipe, model.WrapValidation("版本不属于该 Recipe")
	}
	execution, err := s.GetExecution(ctx, testExecutionID)
	if err != nil {
		return recipe, err
	}
	if force && execution.Success {
		return recipe, model.WrapValidation("成功测试不允许 Force；请正常发布")
	}
	if err := s.store.PublishRecipeVersion(recipeID, versionID, testExecutionID, expectedRevision, force); err != nil {
		return recipe, err
	}
	if err := s.publishAdminCommit("probe_recipe", recipeID, expectedRevision+1, func() { s.invalidateRecipeScope(recipe.ScopeType, recipe.ScopeID) }); err != nil {
		return recipe, err
	}
	return s.GetRecipe(ctx, recipeID)
}
