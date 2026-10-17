package store

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

// Build fixture evidence from one real database snapshot, independently of the
// publish gate. Production obtains the same revision codec inputs from livecfg.
func completeExplicitTestEvidence(t *testing.T, st *Store, execution *model.ProbeExecution) {
	t.Helper()
	ctx := context.Background()
	bundle, err := st.LoadConfigBundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	identity := model.RecipeIdentity{Storage: execution.RecipeStorage, Origin: execution.RecipeOrigin, DBVersionID: execution.RecipeVersionID, ClientProfileID: execution.ClientProfileID, Revision: execution.RecipeIdentityRevision}
	facts := model.RecipeBindingFacts{Use: execution.RecipeBindingUse}
	revision := model.SemanticRevision{RecipeIdentity: identity}
	for _, up := range bundle.Upstreams {
		if up.ID == execution.UpstreamID {
			revision.UpstreamNetwork, revision.UpstreamCredential = up.NetworkRevision, up.CredentialRevision
		}
	}
	for _, endpoint := range bundle.Endpoints {
		if endpoint.UpstreamID == execution.UpstreamID && endpoint.Kind == execution.Endpoint {
			revision.EndpointID, revision.EndpointRevision, revision.AuthProfile = endpoint.ID, endpoint.Revision, endpoint.AuthProfile.Revision
		}
	}
	for _, route := range bundle.Routes {
		if route.ID == execution.RouteID {
			revision.RouteCapability = route.CapabilityRevision
			for _, name := range bundle.ModelNames {
				if name.ID == route.ModelNameID {
					revision.ModelCapability = name.CapabilityRevision
				}
			}
		}
	}
	refs := append([]model.RequiredSecretRef(nil), bundle.EndpointSecretRefs[revision.EndpointID]...)
	if identity.Storage == model.RecipeStorageDB {
		refs = append(refs, bundle.RecipeVersionSecretRefs[identity.DBVersionID]...)
		for _, recipe := range bundle.Recipes {
			if recipe.ID == execution.RecipeID {
				facts.ExplicitRecipeID, facts.ExplicitVersionID, facts.ExplicitRecipeRowRevision = recipe.ID, identity.DBVersionID, recipe.Revision
				revision.RecipeBindingRevision = recipe.ActiveBindingRevision
				if recipe.ScopeType == model.RecipeScopeRoute {
					facts.ResolvedLayer = model.ResolvedRoute
					facts.RouteRecipeID, facts.RoutePublishedVersionID, facts.RouteBindingRevision = recipe.ID, identity.DBVersionID, recipe.ActiveBindingRevision
				} else {
					facts.ResolvedLayer = model.ResolvedUpstream
					facts.UpstreamRecipeID, facts.UpstreamPublishedVersionID, facts.UpstreamBindingRevision = recipe.ID, identity.DBVersionID, recipe.ActiveBindingRevision
				}
			}
		}
	} else {
		for _, profile := range bundle.ClientProfiles {
			if profile.ID == identity.ClientProfileID {
				facts.ExplicitProfileID, facts.ExplicitProfileRevision, facts.ExplicitProfileStatus = profile.ID, profile.Revision, profile.Status
			}
		}
		revision.RecipeBindingRevision = identity.Revision
		rows, err := st.db.Query(`SELECT name,bound_secret_id_snapshot FROM client_profile_required_secret WHERE client_profile_id=?`, identity.ClientProfileID)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var ref model.RequiredSecretRef
			if err := rows.Scan(&ref.Name, &ref.BoundSecretID); err != nil {
				t.Fatal(err)
			}
			refs = append(refs, ref)
		}
		rows.Close()
	}
	seen := map[string]bool{}
	for _, ref := range refs {
		if seen[ref.Name] {
			continue
		}
		seen[ref.Name] = true
		value := model.SecretRevision{Name: ref.Name, ID: ref.BoundSecretID}
		for _, secret := range bundle.SecretRevisions {
			if secret.Name == ref.Name {
				value = secret
			}
		}
		revision.ProbeSecrets = append(revision.ProbeSecrets, value)
	}
	sort.Slice(revision.ProbeSecrets, func(i, j int) bool { return revision.ProbeSecrets[i].Name < revision.ProbeSecrets[j].Name })
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL2, Endpoint: execution.Endpoint, TimeoutProfile: model.TimeoutL2Standard}
	if execution.Endpoint == model.EndpointModels {
		selector.Kind, selector.TimeoutProfile = model.EvidenceL1, ""
	} else if execution.Endpoint == model.EndpointCountTokens {
		selector.Kind, selector.TimeoutProfile = model.EvidenceCountTokens, ""
	}
	policy, err := revisioncodec.BuildCapabilityEvidencePolicy(bundle.Settings, selector)
	if err != nil {
		t.Fatal(err)
	}
	revision.ProbeSettingsFingerprint = revisioncodec.ProbeSettingsFingerprint(policy)
	execution.UpstreamNetworkRevision, execution.UpstreamCredentialRevision = revision.UpstreamNetwork, revision.UpstreamCredential
	execution.EndpointID, execution.EndpointRevision, execution.AuthProfileRevision = revision.EndpointID, revision.EndpointRevision, revision.AuthProfile
	execution.RouteCapabilityRevision, execution.ModelCapabilityRevision = revision.RouteCapability, revision.ModelCapability
	execution.ProbeSettingsFingerprint, execution.ProbeSecretRevisionsHash = revision.ProbeSettingsFingerprint, revisioncodec.SecretRevisionSetHash(revision.ProbeSecrets)
	execution.RecipeBindingFacts, execution.RecipeBindingRevision = facts, revision.RecipeBindingRevision
	execution.CapabilityPolicySelector, execution.CapabilityToken = selector, revisioncodec.NewObservationToken(revision)
}

func TestPublishRecipeVersionRejectsChangesAfterTest(t *testing.T) {
	for _, change := range []string{"url", "network", "auth", "credential", "secret", "endpoint-secret", "settings", "recipe", "binding", "reenable"} {
		t.Run(change, func(t *testing.T) {
			st := testStore(t)
			ctx := context.Background()
			up := mkUpstream(t, st, "current-publish")
			secret, err := st.CreateProbeSecret("publish-proof", []byte("before"))
			if err != nil {
				t.Fatal(err)
			}
			recipeID, err := st.CreateRecipe(model.RecipeScopeUpstream, up.ID, model.EndpointModels)
			if err != nil {
				t.Fatal(err)
			}
			version := &model.ProbeRecipeVersion{RecipeID: recipeID, Origin: model.RecipeManual, Method: "GET", TimeoutProfile: model.TimeoutL1, Headers: []model.HeaderTemplate{{Name: "X-Probe", Values: []string{"{{SECRET:publish-proof}}"}}}}
			if err := st.AddRecipeVersion(version, 1); err != nil {
				t.Fatal(err)
			}
			var endpointSecret *model.ProbeSecret
			if change == "endpoint-secret" {
				endpointSecret = addTestEndpointSecret(t, st, up.ID, model.EndpointModels)
			}
			execution := recipeTestExecution(t, st, up, recipeID, version.ID, "test-before-change")
			completeExplicitTestEvidence(t, st, &execution)
			if err := st.InsertProbeExecution(ctx, &execution); err != nil {
				t.Fatal(err)
			}
			ep, _ := st.Endpoint(ctx, up.ID, model.EndpointModels)
			recipe, _ := st.GetRecipe(ctx, recipeID)
			switch change {
			case "url":
				ep.URLOverride = up.BaseURL + "/changed-models"
				err = st.UpdateEndpoint(ep, ep.Revision)
			case "network":
				up.BaseURL = "https://changed.example"
				err = st.UpdateUpstream(up)
			case "auth":
				ep.AuthProfile.Mode = model.AuthModeXAPIKey
				ep.LegacyCompatRealOnly = false
				err = st.UpdateEndpoint(ep, ep.Revision)
			case "credential":
				up.APIKey = "changed-current-upstream-secret"
				err = st.UpdateUpstream(up)
			case "secret":
				_, err = st.UpdateProbeSecret(secret.ID, secret.Revision, []byte("after"))
			case "endpoint-secret":
				_, err = st.UpdateProbeSecret(endpointSecret.ID, endpointSecret.Revision, []byte("after-endpoint-secret"))
			case "settings":
				settings, settingsRevision, _ := st.GetSettingsWithRevision()
				settings.L1TotalSec++
				_, err = st.SaveSettingsWithRevision(settings, settingsRevision)
			case "recipe":
				other := &model.ProbeRecipeVersion{RecipeID: recipeID, Origin: model.RecipeManual, Method: "HEAD", TimeoutProfile: model.TimeoutL1}
				err = st.AddRecipeVersion(other, recipe.Revision)
			case "binding":
				err = st.DisableRecipe(ctx, recipeID, recipe.Revision)
			case "reenable":
				up.Enabled = false
				if err = st.UpdateUpstream(up); err == nil {
					up.Enabled = true
					err = st.UpdateUpstream(up)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			recipe, _ = st.GetRecipe(ctx, recipeID)
			if err := st.PublishRecipeVersion(recipeID, version.ID, execution.ID, recipe.Revision, false); !errors.Is(err, ErrRevisionConflict) {
				t.Errorf("%s change allowed stale test to publish: %v", change, err)
			}
			current, _ := st.GetRecipe(ctx, recipeID)
			if current.PublishedVersionID != 0 || current.Revision != recipe.Revision {
				t.Error("rejected stale test changed binding/revision")
			}
		})
	}
}

func TestPublishRecipeForceRequiresFinalSentFailure(t *testing.T) {
	for _, outcome := range []string{"success", "not-final", "not-sent", "canceled", "failed"} {
		t.Run(outcome, func(t *testing.T) {
			st := testStore(t)
			up := mkUpstream(t, st, "force-current")
			recipeID, version := mkDraftRecipe(t, st, up)
			execution := recipeTestExecution(t, st, up, recipeID, version.ID, "force-outcome")
			completeExplicitTestEvidence(t, st, &execution)
			if outcome != "success" {
				execution.Success, execution.Reachable, execution.ErrorClass = false, false, model.ErrorUnsupported
			}
			switch outcome {
			case "not-final":
				execution.Final = false
			case "not-sent":
				execution.SentAtMS = 0
			case "canceled":
				execution.ExpectedCancel, execution.ErrorClass = true, model.ErrorIgnored
			}
			if err := st.InsertProbeExecution(context.Background(), &execution); err != nil {
				t.Fatal(err)
			}
			recipe, _ := st.GetRecipe(context.Background(), recipeID)
			err := st.PublishRecipeVersion(recipeID, version.ID, execution.ID, recipe.Revision, true)
			if outcome == "failed" {
				if err != nil {
					t.Fatalf("current sent failure with explicit force rejected: %v", err)
				}
			} else if err == nil {
				t.Errorf("force accepted %s execution", outcome)
			}
		})
	}
}

func TestMarkClientProfileTestedRejectsChangedTarget(t *testing.T) {
	for _, change := range []string{"url", "credential", "auth", "endpoint-secret", "settings", "reenable"} {
		t.Run(change, func(t *testing.T) {
			st := testStore(t)
			ctx := context.Background()
			up := mkUpstream(t, st, "profile-current")
			var endpointSecret *model.ProbeSecret
			if change == "endpoint-secret" {
				endpointSecret = addTestEndpointSecret(t, st, up.ID, model.EndpointMessages)
			}
			profile := mkCandidate(t, st, up.ID, "cli", "current-shape")
			execution := profileTestExecution(t, st, profile, up, "candidate-before-change")
			completeExplicitTestEvidence(t, st, &execution)
			if err := st.InsertProbeExecution(ctx, &execution); err != nil {
				t.Fatal(err)
			}
			ep, _ := st.Endpoint(ctx, up.ID, model.EndpointMessages)
			var err error
			switch change {
			case "url":
				ep.URLOverride = up.BaseURL + "/changed-messages"
				err = st.UpdateEndpoint(ep, ep.Revision)
			case "auth":
				ep.AuthProfile.Mode = model.AuthModeXAPIKey
				ep.LegacyCompatRealOnly = false
				err = st.UpdateEndpoint(ep, ep.Revision)
			case "credential":
				up.APIKey = "changed-profile-target-key"
				err = st.UpdateUpstream(up)
			case "endpoint-secret":
				_, err = st.UpdateProbeSecret(endpointSecret.ID, endpointSecret.Revision, []byte("after-profile-endpoint-secret"))
			case "settings":
				settings, settingsRevision, _ := st.GetSettingsWithRevision()
				settings.L2TotalSec++
				_, err = st.SaveSettingsWithRevision(settings, settingsRevision)
			case "reenable":
				up.Enabled = false
				if err = st.UpdateUpstream(up); err == nil {
					up.Enabled = true
					err = st.UpdateUpstream(up)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := st.MarkClientProfileTested(ctx, profile.ID, execution.ID, profile.Revision); !errors.Is(err, ErrRevisionConflict) {
				t.Errorf("%s change allowed stale profile test: %v", change, err)
			}
			current, err := loadProfile(t, st, profile.ID)
			if err != nil || current.Status != model.ProfileCandidate || current.Revision != profile.Revision {
				t.Fatal("rejected test changed candidate binding")
			}
		})
	}
}

func addTestEndpointSecret(t *testing.T, st *Store, upstreamID int64, kind model.EndpointKind) *model.ProbeSecret {
	t.Helper()
	secret, err := st.CreateProbeSecret("endpoint-proof", []byte("before-endpoint-secret"))
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := st.Endpoint(context.Background(), upstreamID, kind)
	if err != nil {
		t.Fatal(err)
	}
	endpoint.FixedQueryTemplate = "probe_nonce={{SECRET:endpoint-proof}}"
	if err := st.UpdateEndpoint(endpoint, endpoint.Revision); err != nil {
		t.Fatal(err)
	}
	return secret
}

func TestExplicitTestBindingRejectsChangedRouteAndModel(t *testing.T) {
	for _, resource := range []string{"recipe", "profile"} {
		for _, change := range []string{"route-model", "model-prompt", "route-disable", "model-disable", "route-reenable", "model-reenable", "upstream-disable"} {
			t.Run(resource+"/"+change, func(t *testing.T) {
				st := testStore(t)
				ctx := context.Background()
				route := mkRoute(t, st)
				up, _ := st.GetUpstream(route.UpstreamID)
				name, _ := st.GetModelName(route.ModelNameID)
				var recipeID, versionID, profileID, revision int64
				execution := model.ProbeExecution{ID: "route-explicit", Trigger: model.TriggerManual, UpstreamID: up.ID, RouteID: route.ID, Endpoint: model.EndpointMessages, EvidenceHash: "route-explicit-evidence", ErrorClass: model.ErrorNone, Capability: model.CapabilityUnknown, Scope: model.ScopeRouteEndpoint, Reachable: true, Final: true, Success: true, ObservationOrder: 1, SentAtMS: 1, DoneAtMS: 2}
				if resource == "recipe" {
					var err error
					recipeID, err = st.CreateRecipe(model.RecipeScopeRoute, route.ID, model.EndpointMessages)
					if err != nil {
						t.Fatal(err)
					}
					version := &model.ProbeRecipeVersion{RecipeID: recipeID, Origin: model.RecipeManual, Method: "POST", Body: []byte(`{"model":"{{UPSTREAM_MODEL}}","max_tokens":1}`), BodyIsText: true, TimeoutProfile: model.TimeoutL2Standard}
					if err := st.AddRecipeVersion(version, 1); err != nil {
						t.Fatal(err)
					}
					versionID, revision = version.ID, 2
					execution.RecipeID, execution.RecipeVersionID = recipeID, versionID
					execution.RecipeBindingUse, execution.RecipeStorage, execution.RecipeOrigin = model.BindingExplicitTest, model.RecipeStorageDB, model.RecipeManual
				} else {
					profile := mkCandidate(t, st, up.ID, "route-cli", "route-shape")
					profileID, revision = profile.ID, profile.Revision
					execution.ClientProfileID, execution.RecipeIdentityRevision = profileID, revision
					execution.RecipeBindingUse, execution.RecipeStorage, execution.RecipeOrigin = model.BindingExplicitProfileTest, model.RecipeStorageProfile, model.RecipeLearned
				}
				completeExplicitTestEvidence(t, st, &execution)
				if err := st.InsertProbeExecution(ctx, &execution); err != nil {
					t.Fatal(err)
				}
				var err error
				switch change {
				case "route-model":
					route.UpstreamModel = "changed-model-name"
					err = st.UpdateRoute(route)
				case "model-prompt":
					name.ProbePrompt = "changed-probe-prompt"
					err = st.UpdateModelName(name)
				case "route-disable", "route-reenable":
					route.Enabled = false
					err = st.UpdateRoute(route)
					if err == nil && change == "route-reenable" {
						route.Enabled = true
						err = st.UpdateRoute(route)
					}
				case "model-disable", "model-reenable":
					name.Enabled = false
					err = st.UpdateModelName(name)
					if err == nil && change == "model-reenable" {
						name.Enabled = true
						err = st.UpdateModelName(name)
					}
				case "upstream-disable":
					up.Enabled = false
					err = st.UpdateUpstream(up)
				}
				if err != nil {
					t.Fatal(err)
				}
				if resource == "recipe" {
					err = st.PublishRecipeVersion(recipeID, versionID, execution.ID, revision, false)
				} else {
					err = st.MarkClientProfileTested(ctx, profileID, execution.ID, revision)
				}
				if !errors.Is(err, ErrRevisionConflict) {
					t.Fatalf("%s allowed stale %s test binding: %v", change, resource, err)
				}
			})
		}
	}
}

func TestPublishRecipeForceCannotBypassCurrentToken(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "force-stale")
	recipeID, version := mkDraftRecipe(t, st, up)
	execution := recipeTestExecution(t, st, up, recipeID, version.ID, "failed-before-settings-change")
	execution.Success, execution.Reachable, execution.ErrorClass = false, false, model.ErrorUnsupported
	if err := st.InsertProbeExecution(context.Background(), &execution); err != nil {
		t.Fatal(err)
	}
	settings, settingsRevision, _ := st.GetSettingsWithRevision()
	settings.L1TotalSec++
	if _, err := st.SaveSettingsWithRevision(settings, settingsRevision); err != nil {
		t.Fatal(err)
	}
	if err := st.PublishRecipeVersion(recipeID, version.ID, execution.ID, 2, true); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("force bypassed settings freshness: %v", err)
	}
}

func TestProfileTestTelemetryKeepsCurrentEvidenceUsable(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "profile-telemetry-publish")
	profile := mkCandidate(t, st, up.ID, "cli", "telemetry-shape")
	execution := profileTestExecution(t, st, profile, up, "profile-before-telemetry")
	ctx := context.Background()
	if err := st.InsertProbeExecution(ctx, &execution); err != nil {
		t.Fatal(err)
	}
	if err := st.TouchClientProfile(ctx, profile.ID, profile.LastSeenAt+1000); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkClientProfileTested(ctx, profile.ID, execution.ID, profile.Revision); err != nil {
		t.Fatalf("telemetry invalidated unchanged candidate test: %v", err)
	}
}

func TestPublishRecipeRechecksTargetAfterWaitingForDatabaseWriter(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "publish-waits-for-write")
	recipeID, version := mkDraftRecipe(t, st, up)
	execution := recipeTestExecution(t, st, up, recipeID, version.ID, "before-committed-writer")
	if err := st.InsertProbeExecution(context.Background(), &execution); err != nil {
		t.Fatal(err)
	}
	tx, err := st.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE upstream SET network_revision=network_revision+1 WHERE id=?`, up.ID); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	waits := st.db.Stats().WaitCount
	go func() { result <- st.PublishRecipeVersion(recipeID, version.ID, execution.ID, 2, false) }()
	deadline := time.Now().Add(time.Second)
	for st.db.Stats().WaitCount == waits {
		if time.Now().After(deadline) {
			t.Fatal("publication did not wait behind the database writer")
		}
		time.Sleep(time.Millisecond)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrRevisionConflict) {
			t.Fatalf("publication ignored prior writer commit: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("publication did not finish after writer commit")
	}
}
