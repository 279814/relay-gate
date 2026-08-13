package model

import (
	"errors"
	"testing"
)

func TestProbeRecipeVersionValidatesEndpointMethodAndBody(t *testing.T) {
	tests := []struct {
		name     string
		endpoint EndpointKind
		version  ProbeRecipeVersion
		wantErr  bool
	}{
		{"models GET", EndpointModels, ProbeRecipeVersion{Method: "GET", TimeoutProfile: TimeoutL1}, false},
		{"models HEAD", EndpointModels, ProbeRecipeVersion{Method: "HEAD", TimeoutProfile: TimeoutL1}, false},
		{"messages POST", EndpointMessages, ProbeRecipeVersion{Method: "POST", Body: []byte(`{}`), BodyIsText: true, TimeoutProfile: TimeoutL2Standard}, false},
		{"count tokens POST", EndpointCountTokens, ProbeRecipeVersion{Method: "POST", Body: []byte(`{}`), BodyIsText: true, TimeoutProfile: TimeoutCountTokens}, false},
		{"lowercase method", EndpointMessages, ProbeRecipeVersion{Method: "post", TimeoutProfile: TimeoutL2Standard}, true},
		{"GET body", EndpointModels, ProbeRecipeVersion{Method: "GET", Body: []byte(`{}`), TimeoutProfile: TimeoutL1}, true},
		{"model endpoint GET", EndpointMessages, ProbeRecipeVersion{Method: "GET", TimeoutProfile: TimeoutL2Standard}, true},
		{"models POST", EndpointModels, ProbeRecipeVersion{Method: "POST", TimeoutProfile: TimeoutL1}, true},
		{"bad timeout profile", EndpointMessages, ProbeRecipeVersion{Method: "POST", TimeoutProfile: "unknown"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.version.ValidateForEndpoint(tc.endpoint)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateForEndpoint() error = %v, wantErr=%v", err, tc.wantErr)
			}
			if err != nil && !errors.Is(err, ErrValidation) {
				t.Fatalf("error = %v, want ErrValidation", err)
			}
		})
	}
}

func TestRecipeIdentityRequiresOneStorageDiscriminator(t *testing.T) {
	valid := []RecipeIdentity{
		{Storage: RecipeStorageDB, Origin: RecipeManual, DBVersionID: 7},
		{Storage: RecipeStorageProfile, Origin: RecipeLearned, ClientProfileID: 8, Revision: 3},
		{Storage: RecipeStorageEmbedded, Origin: RecipeCompact, TemplateID: "anthropic-compact-v1", Revision: 2},
	}
	for _, identity := range valid {
		if err := identity.Validate(); err != nil {
			t.Errorf("valid identity %+v: %v", identity, err)
		}
	}
	invalid := []RecipeIdentity{
		{},
		{Storage: RecipeStorageDB, Origin: RecipeManual, DBVersionID: 7, Revision: 1},
		{Storage: RecipeStorageDB, Origin: RecipeManual, DBVersionID: 7, ClientProfileID: 8},
		{Storage: RecipeStorageProfile, Origin: RecipeLearned, ClientProfileID: 8},
		{Storage: RecipeStorageEmbedded, Origin: RecipeCompact, Revision: 1},
		{Storage: "unknown", Origin: RecipeManual, DBVersionID: 1},
	}
	for _, identity := range invalid {
		if err := identity.Validate(); !errors.Is(err, ErrValidation) {
			t.Errorf("invalid identity %+v error = %v", identity, err)
		}
	}
}

func TestSemanticTargetValidatesScopeKeys(t *testing.T) {
	valid := []SemanticTarget{
		{Scope: RecipeScopeUpstream, UpstreamID: 1, Endpoint: EndpointModels},
		{Scope: RecipeScopeRoute, UpstreamID: 1, RouteID: 2, Endpoint: EndpointMessages},
	}
	for _, target := range valid {
		if err := target.Validate(); err != nil {
			t.Errorf("valid target %+v: %v", target, err)
		}
	}
	invalid := []SemanticTarget{
		{Scope: RecipeScopeUpstream, UpstreamID: 1, RouteID: 2, Endpoint: EndpointModels},
		{Scope: RecipeScopeRoute, UpstreamID: 1, Endpoint: EndpointMessages},
		{Scope: RecipeScopeRoute, RouteID: 2, Endpoint: EndpointMessages},
		{Scope: RecipeScopeRoute, UpstreamID: 1, RouteID: 2, Endpoint: "unknown"},
	}
	for _, target := range invalid {
		if err := target.Validate(); !errors.Is(err, ErrValidation) {
			t.Errorf("invalid target %+v error = %v", target, err)
		}
	}
}
