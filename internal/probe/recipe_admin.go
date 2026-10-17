package probe

import (
	"context"

	"github.com/279814/relay-gate/internal/model"
)

// RecipeVersionMutation excludes provenance and storage identity. Only trusted
// migration/calibration/learner code can materialize non-manual versions.
type RecipeVersionMutation struct {
	Method         string
	FixedRawQuery  string
	Headers        []model.HeaderTemplate
	Body           []byte
	BodyIsText     bool
	StreamExpected bool
	TimeoutProfile model.ProbeTimeoutProfile
}

// ActivationPendingError means SQL committed while the new snapshot could not
// activate. Clients must reload this revision rather than retry a stale write.
type ActivationPendingError struct {
	Resource     string
	ID, Revision int64
}

func (e *ActivationPendingError) Error() string { return "配置已保存，等待运行快照激活" }

func (s *Service) publishAdminCommit(resource string, id, revision int64, invalidate func()) error {
	publisher, _ := s.snapshots.(ConfigPublisher)
	if publisher != nil {
		publisher.Invalidate()
	}
	if invalidate != nil {
		invalidate()
	}
	if publisher != nil {
		if err := publisher.Refresh(); err != nil {
			return &ActivationPendingError{Resource: resource, ID: id, Revision: revision}
		}
	}
	return nil
}

func (s *Service) AddVersion(ctx context.Context, recipeID, expectedRevision int64, in RecipeVersionMutation) (model.ProbeRecipeVersion, error) {
	version := model.ProbeRecipeVersion{RecipeID: recipeID, Origin: model.RecipeManual, Method: in.Method, FixedRawQuery: in.FixedRawQuery, Headers: in.Headers, Body: in.Body, BodyIsText: in.BodyIsText, StreamExpected: in.StreamExpected, TimeoutProfile: in.TimeoutProfile}
	if err := s.store.AddRecipeVersion(&version, expectedRevision); err != nil {
		return model.ProbeRecipeVersion{}, err
	}
	if err := s.publishAdminCommit("probe_recipe", recipeID, expectedRevision+1, nil); err != nil {
		return version, err
	}
	return version, nil
}

func (s *Service) ListClientProfiles(ctx context.Context, filter model.ClientProfileFilter) (model.Page[model.ClientProbeProfile], error) {
	page, err := s.store.ListClientProfilesPage(ctx, filter)
	if err != nil {
		return model.Page[model.ClientProbeProfile]{}, err
	}
	for _, profile := range page.Items {
		if err := sanitizeAdminProfile(profile); err != nil {
			return model.Page[model.ClientProbeProfile]{}, err
		}
	}
	return derefAdminPage(page), nil
}
