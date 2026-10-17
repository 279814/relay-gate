package probe

import (
	"context"
	"errors"

	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
)

// snapshotRecipeSource keeps real-traffic observation preparation in memory and
// resolves the recipe against the same immutable configuration as its token.
type snapshotRecipeSource struct{ snap *livecfg.ProbeSnapshot }

var errSnapshotRecipeNotFound = errors.New("recipe absent from snapshot")

func (s snapshotRecipeSource) binding(scope model.RecipeScope, id int64, endpoint model.EndpointKind) (*model.PublishedRecipeBinding, error) {
	for _, recipe := range s.snap.Recipes {
		if recipe.ScopeType != scope || recipe.ScopeID != id || recipe.Endpoint != endpoint ||
			(recipe.Status != model.RecipePublished && recipe.Status != model.RecipeLegacy) || recipe.PublishedVersionID <= 0 {
			continue
		}
		version := s.snap.RecipeVersions[recipe.PublishedVersionID]
		if version == nil {
			return nil, model.WrapValidation("published recipe version absent from snapshot")
		}
		return &model.PublishedRecipeBinding{Recipe: *recipe, Version: *version}, nil
	}
	return nil, errSnapshotRecipeNotFound
}

func (s snapshotRecipeSource) PublishedRouteRecipe(_ context.Context, id int64, endpoint model.EndpointKind) (*model.PublishedRecipeBinding, error) {
	return s.binding(model.RecipeScopeRoute, id, endpoint)
}

func (s snapshotRecipeSource) PublishedUpstreamRecipe(_ context.Context, id int64, endpoint model.EndpointKind) (*model.PublishedRecipeBinding, error) {
	return s.binding(model.RecipeScopeUpstream, id, endpoint)
}

func (s snapshotRecipeSource) TestedClientProfile(_ context.Context, upstreamID int64, endpoint model.EndpointKind) (*model.ClientProbeProfile, error) {
	profile := s.snap.TestedClientProfiles[upstreamID][endpoint]
	if profile == nil {
		return nil, errSnapshotRecipeNotFound
	}
	return profile, nil
}

func (s snapshotRecipeSource) RecipeVersionSecretRefs(_ context.Context, versionID int64) ([]model.RequiredSecretRef, error) {
	return s.snap.RecipeVersionSecretRefs[versionID], nil
}
