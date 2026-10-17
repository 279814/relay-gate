package probe

import (
	"context"

	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

func sanitizeAdminProfile(profile *model.ClientProbeProfile) error {
	safe, err := sanitizeLearnedShape(profile.Endpoint, model.ClientRequestShape{SafeHeaders: profile.SafeHeaders, FixedRawQuery: profile.FixedRawQuery, BodyTemplate: profile.BodyTemplate, BodyShapeJSON: profile.BodyShapeJSON})
	if err != nil {
		return err
	}
	profile.SafeHeaders = safe.SafeHeaders
	profile.FixedRawQuery = safe.FixedRawQuery
	profile.BodyTemplate = safe.BodyTemplate
	profile.BodyShapeJSON = safe.BodyShapeJSON
	profile.QueryShapeJSON = safe.QueryShapeJSON
	profile.ClientFamily = safe.ClientFamily
	profile.ShapeHash = ShapeHash(safe)
	return nil
}

func (s *Service) GetClientProfile(ctx context.Context, id int64) (model.ClientProbeProfile, error) {
	profile, err := s.store.GetClientProfile(ctx, id)
	if err != nil {
		return model.ClientProbeProfile{}, err
	}
	if err := sanitizeAdminProfile(profile); err != nil {
		return model.ClientProbeProfile{}, err
	}
	return *profile, nil
}

func (s *Service) PreviewClientProfile(ctx context.Context, id int64, in PreviewInput) (RedactedPreview, error) {
	stored, err := s.store.GetClientProfile(ctx, id)
	if err != nil {
		return RedactedPreview{}, err
	}
	if _, err := compileAdminProfile(*stored); err != nil {
		return RedactedPreview{}, err
	}
	if err := sanitizeAdminProfile(stored); err != nil {
		return RedactedPreview{}, err
	}
	profile := *stored
	return s.previewVersion(ctx, model.ProbeRecipeVersion{Method: profile.Endpoint.Method(), FixedRawQuery: profile.FixedRawQuery, Headers: profile.SafeHeaders, Body: profile.BodyTemplate, BodyIsText: true, StreamExpected: learnedStreamExpected(profile.BodyTemplate), TimeoutProfile: defaultTimeoutProfile(profile.Endpoint)}, model.ProbeRecipe{ScopeType: model.RecipeScopeUpstream, ScopeID: profile.UpstreamID, Endpoint: profile.Endpoint}, in)
}

func (s *Service) TestClientProfile(ctx context.Context, id, routeID, expectedRevision int64) (model.ProbeExecution, error) {
	stored, err := s.store.GetClientProfile(ctx, id)
	if err != nil {
		return model.ProbeExecution{}, err
	}
	profile := *stored
	if expectedRevision < 1 {
		return model.ProbeExecution{}, model.WrapValidation("expected_revision 必须是正整数")
	}
	if profile.Revision != expectedRevision {
		return model.ProbeExecution{}, store.ErrRevisionConflict
	}
	if profile.Status != model.ProfileCandidate {
		return model.ProbeExecution{}, model.WrapValidation("只能测试并启用 candidate；已停用的形状需由新候选重新测试")
	}
	snap, err := s.adminProbeSnapshot()
	if err != nil {
		return model.ProbeExecution{}, err
	}
	current := snap.ClientProfilesByID[id]
	if current == nil || current.Revision != profile.Revision || current.Status != profile.Status {
		return model.ProbeExecution{}, livecfg.ErrProbeSnapshotUnavailable
	}
	up, route, mn, err := previewTarget(snap, model.ProbeRecipe{ScopeType: model.RecipeScopeUpstream, ScopeID: profile.UpstreamID, Endpoint: profile.Endpoint}, routeID)
	if err != nil {
		return model.ProbeExecution{}, err
	}
	// Reuse the resolver's existing read-side sanitizer/compiler without treating
	// the candidate as an already active binding in its observation identity.
	explicit, err := compileAdminProfile(profile)
	if err != nil {
		return model.ProbeExecution{}, err
	}
	explicit.Facts = model.RecipeBindingFacts{Use: model.BindingExplicitProfileTest, ExplicitProfileID: profile.ID, ExplicitProfileRevision: profile.Revision, ExplicitProfileStatus: profile.Status}
	execution, err := s.executeAdminTest(ctx, snap, up, route, mn, profile.Endpoint, explicit)
	if err != nil {
		return execution, err
	}
	if !execution.Success {
		return execution, nil
	}
	if err := s.store.MarkClientProfileTested(ctx, id, execution.ID, expectedRevision); err != nil {
		return execution, err
	}
	if err := s.publishAdminCommit("client_profile", id, expectedRevision+1, func() { s.invalidateRecipeScope(model.RecipeScopeUpstream, profile.UpstreamID) }); err != nil {
		return execution, err
	}
	return execution, nil
}

func compileAdminProfile(profile model.ClientProbeProfile) (ResolvedRecipe, error) {
	// Compile the stored declaration before removing forbidden fields. This must
	// match automatic resolution, including its pre-sanitization Secret guard.
	// The value copy is only a compile view, never a persisted activation.
	profile.Status = model.ProfileTested
	return NewRecipeResolver(nil).fromProfile(RecipeQuery{UpstreamID: profile.UpstreamID, Endpoint: profile.Endpoint}, &profile)
}

func (s *Service) DisableClientProfile(ctx context.Context, id, expectedRevision int64) error {
	profile, err := s.GetClientProfile(ctx, id)
	if err != nil {
		return err
	}
	if err := s.store.DisableClientProfile(ctx, id, expectedRevision); err != nil {
		return err
	}
	return s.publishAdminCommit("client_profile", id, expectedRevision+1, func() { s.invalidateRecipeScope(model.RecipeScopeUpstream, profile.UpstreamID) })
}
