package probe

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

func TestRouteHealthClearFailureRollsBackConfigurationTransaction(t *testing.T) {
	ctx := context.Background()
	for _, change := range []string{"route", "upstream", "model", "endpoint", "settings", "secret"} {
		t.Run(change, func(t *testing.T) {
			var secret *model.ProbeSecret
			st, up, mn, route, row := boundNegativeSnapshot(t, func(st *store.Store, up *model.Upstream, _ *model.ModelName, _ *model.Route) {
				if change != "secret" {
					return
				}
				var err error
				secret, err = st.CreateProbeSecret("atomic_health", []byte("fixture-atomic-health-secret"))
				if err != nil {
					t.Fatal(err)
				}
				ep, err := st.Endpoint(ctx, up.ID, model.EndpointMessages)
				if err != nil {
					t.Fatal(err)
				}
				ep.AuthProfile = model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: "probe:atomic_health"}
				ep.LegacyCompatRealOnly = false
				if err := st.UpdateEndpoint(ep, ep.Revision); err != nil {
					t.Fatal(err)
				}
			})
			if err := st.SaveRouteHealth([]*store.RouteHealth{row}); err != nil {
				t.Fatal(err)
			}
			before, err := st.LoadConfigBundle(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := st.DB().Exec(`CREATE TRIGGER deny_health_clear BEFORE UPDATE OF state ON route_health BEGIN SELECT RAISE(ABORT,'health clear denied'); END`); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "route":
				route.UpstreamModel = "new-model"
				err = st.UpdateRouteWithRevision(ctx, route, route.Revision)
			case "upstream":
				up.APIKey = "replacement-atomic-health-key"
				err = st.UpdateUpstreamWithRevision(ctx, up, up.Revision)
			case "model":
				mn.ProbePrompt = "new probe"
				err = st.UpdateModelNameWithRevision(ctx, mn, mn.Revision)
			case "endpoint":
				var ep *model.UpstreamEndpoint
				ep, err = st.Endpoint(ctx, up.ID, model.EndpointMessages)
				if err == nil {
					ep.FixedQueryTemplate = "changed=true"
					err = st.UpdateEndpoint(ep, ep.Revision)
				}
			case "settings":
				var s model.Settings
				var rev int64
				s, rev, err = st.GetSettingsWithRevision()
				if err == nil {
					s.CooldownSec++
					_, err = st.SaveSettingsWithRevision(s, rev)
				}
			case "secret":
				_, err = st.UpdateProbeSecret(secret.ID, secret.Revision, []byte("replacement-atomic-health-secret"))
			}
			if err == nil || !strings.Contains(err.Error(), "health clear denied") {
				t.Fatalf("configuration did not reach the rejected health clear: %v", err)
			}
			after, err := st.LoadConfigBundle(ctx)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("configuration or semantic revisions escaped the rolled-back transaction", err)
			}
			assertDurableHealthState(t, st, route.ID, true)
		})
	}
}

func TestRouteHealthUnrelatedEndpointAndCandidateEditsKeepEvidence(t *testing.T) {
	st, up, _, route, row := boundNegativeSnapshot(t)
	if err := st.SaveRouteHealth([]*store.RouteHealth{row}); err != nil {
		t.Fatal(err)
	}
	ep, err := st.Endpoint(context.Background(), up.ID, model.EndpointCountTokens)
	if err != nil {
		t.Fatal(err)
	}
	ep.FixedQueryTemplate = "count_only=true"
	if err := st.UpdateEndpoint(ep, ep.Revision); err != nil {
		t.Fatal(err)
	}
	assertDurableHealthState(t, st, route.ID, true)
	shape, reason := SanitizeRequestShape(model.EndpointMessages, health.AttemptRequestView{Body: []byte(`{"model":"private","messages":[],"stream":false}`)})
	if reason != "" {
		t.Fatal(reason)
	}
	for n := 0; n < 2; n++ {
		if err := NewLearner(st).ObserveSuccessful(context.Background(), up.ID, model.EndpointMessages, shape); err != nil {
			t.Fatal(err)
		}
	}
	page, err := st.ListClientProfilesPage(context.Background(), model.ClientProfileFilter{UpstreamID: up.ID})
	if err != nil || len(page.Items) != 1 {
		t.Fatal("candidate fixture missing", err)
	}
	if err := st.DisableClientProfile(context.Background(), page.Items[0].ID, page.Items[0].Revision); err != nil {
		t.Fatal(err)
	}
	assertDurableHealthState(t, st, route.ID, true)
}

func TestLegacyHealthCapturedBeforeConfigurationResetCannotReturn(t *testing.T) {
	for _, change := range []string{"route", "upstream", "model", "threshold", "unrelated endpoint"} {
		t.Run(change, func(t *testing.T) {
			ctx := context.Background()
			st, up, mn, route, _ := boundNegativeSnapshot(t)
			if err := st.SaveRouteHealth([]*store.RouteHealth{{RouteID: route.ID, State: model.StateDead, LastErrAt: route.CreatedAt, ConsecutiveFail: 8}}); err != nil {
				t.Fatal(err)
			}
			cfg, _ := restoreTestDeps(st)
			tracker := health.NewTracker(cfg)
			if n, err := RestoreRouteHealth(ctx, tracker, st, cfg); err != nil || n != 1 {
				t.Fatalf("legacy fixture did not require recovery: n=%d err=%v", n, err)
			}
			// The persister captured this old state before the configuration
			// transaction. Its write can reach SQLite after that transaction.
			captured := capturedHealthStatuses(tracker.AllStatus())
			var err error
			switch change {
			case "route":
				route.UpstreamModel = "legacy-reset-model"
				err = st.UpdateRouteWithRevision(ctx, route, route.Revision)
			case "upstream":
				up.APIKey = "legacy-reset-key"
				err = st.UpdateUpstreamWithRevision(ctx, up, up.Revision)
			case "model":
				mn.ProbePrompt = "legacy reset prompt"
				err = st.UpdateModelNameWithRevision(ctx, mn, mn.Revision)
			case "threshold":
				var settings model.Settings
				var revision int64
				settings, revision, err = st.GetSettingsWithRevision()
				if err == nil {
					settings.FailThreshold++
					_, err = st.SaveSettingsWithRevision(settings, revision)
				}
			case "unrelated endpoint":
				var ep *model.UpstreamEndpoint
				ep, err = st.Endpoint(ctx, up.ID, model.EndpointCountTokens)
				if err == nil {
					ep.FixedQueryTemplate = "legacy_unrelated=true"
					err = st.UpdateEndpoint(ep, ep.Revision)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if change != "unrelated endpoint" {
				assertDurableHealthState(t, st, route.ID, false)
			}
			flush, cancel := context.WithCancel(ctx)
			cancel()
			health.NewPersister(captured, st, discardLogger()).Run(flush)
			cfg, _ = restoreTestDeps(st)
			fresh := health.NewTracker(cfg)
			n, err := RestoreRouteHealth(ctx, fresh, st, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if change == "unrelated endpoint" {
				if n != 1 || fresh.State(route.ID) != model.StateRecovering {
					t.Fatalf("unrelated edit erased legacy RecoveryGate requirement: n=%d state=%s", n, fresh.State(route.ID))
				}
			} else {
				assertDurableHealthState(t, st, route.ID, false)
				if n != 0 || fresh.State(route.ID) != model.StateUnknown {
					t.Fatalf("late legacy snapshot revived after explicit reset: n=%d state=%s", n, fresh.State(route.ID))
				}
			}
			current := healthSnapshotForCurrent(t, st, up, route)
			fresh.Report(health.Report{RouteID: route.ID, Verdict: health.VerdictOK, Source: health.SourceReal, HalfOpen: true, Identity: current.Identity})
			flushHealthSnapshot(fresh, st)
			rows, err := st.ListRouteHealth()
			if err != nil || len(rows) != 1 || rows[0].State != model.StateAlive || rows[0].Identity == nil {
				t.Fatalf("new verified observation did not replace legacy evidence: rows=%+v err=%v", rows, err)
			}
		})
	}
}

type capturedHealthStatuses []health.Status

func (snapshots capturedHealthStatuses) AllStatus() []health.Status { return snapshots }

func TestRouteHealthProfileActivationAndRetirementClearOnlySelectedBinding(t *testing.T) {
	for _, routeOverride := range []bool{false, true} {
		t.Run(map[bool]string{false: "profile selected", true: "route override"}[routeOverride], func(t *testing.T) {
			remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				drainBody(r)
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"type":"message","content":[{"type":"text","text":"tested"}]}`)
			}))
			defer remote.Close()
			st, up, _, route, row := boundNegativeSnapshot(t, func(st *store.Store, up *model.Upstream, _ *model.ModelName, _ *model.Route) {
				up.BaseURL = remote.URL
				if err := st.UpdateUpstreamWithRevision(context.Background(), up, up.Revision); err != nil {
					t.Fatal(err)
				}
				ep, err := st.Endpoint(context.Background(), up.ID, model.EndpointMessages)
				if err != nil {
					t.Fatal(err)
				}
				ep.AuthProfile = model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: "upstream_api_key"}
				ep.LegacyCompatRealOnly = false
				if err := st.UpdateEndpoint(ep, ep.Revision); err != nil {
					t.Fatal(err)
				}
			})
			cfg, admin := healthRestoreAdmin(t, st)
			var routeRecipeID int64
			if routeOverride {
				routeRecipeID = healthPublishRecipe(t, admin, model.RecipeScopeRoute, route.ID, route.ID)
				row = healthSnapshotForCurrent(t, st, up, route)
			}
			if err := st.SaveRouteHealth([]*store.RouteHealth{row}); err != nil {
				t.Fatal(err)
			}
			shape, reason := SanitizeRequestShape(model.EndpointMessages, health.AttemptRequestView{Body: []byte(`{"model":"private","messages":[],"stream":false}`)})
			if reason != "" {
				t.Fatal(reason)
			}
			if err := NewLearner(st).ObserveSuccessful(context.Background(), up.ID, model.EndpointMessages, shape); err != nil {
				t.Fatal(err)
			}
			page, err := st.ListClientProfilesPage(context.Background(), model.ClientProfileFilter{UpstreamID: up.ID})
			if err != nil || len(page.Items) != 1 {
				t.Fatal("candidate fixture missing", err)
			}
			if err := cfg.Refresh(); err != nil {
				t.Fatal(err)
			}
			profile := page.Items[0]
			tested, err := admin.TestClientProfile(context.Background(), profile.ID, route.ID, profile.Revision)
			if err != nil || !tested.Success {
				t.Fatalf("real profile test did not activate: success=%t err=%v", tested.Success, err)
			}
			assertDurableHealthState(t, st, route.ID, routeOverride)
			if !routeOverride {
				row = healthSnapshotForCurrent(t, st, up, route)
				if err := st.SaveRouteHealth([]*store.RouteHealth{row}); err != nil {
					t.Fatal(err)
				}
			}
			if err := admin.DisableClientProfile(context.Background(), profile.ID, profile.Revision+1); err != nil {
				t.Fatal(err)
			}
			assertDurableHealthState(t, st, route.ID, routeOverride)
			if routeOverride {
				// Publishing and retiring a lower-priority live binding do not
				// alter the selected Route recipe. Retiring that Route binding does.
				upstreamRecipeID := healthPublishRecipe(t, admin, model.RecipeScopeUpstream, up.ID, route.ID)
				assertDurableHealthState(t, st, route.ID, true)
				upstreamRecipe, err := st.GetRecipe(context.Background(), upstreamRecipeID)
				if err != nil {
					t.Fatal(err)
				}
				if err := st.ArchiveRecipe(context.Background(), upstreamRecipe.ID, upstreamRecipe.Revision); err != nil {
					t.Fatal(err)
				}
				assertDurableHealthState(t, st, route.ID, true)
				recipe, err := st.GetRecipe(context.Background(), routeRecipeID)
				if err != nil {
					t.Fatal(err)
				}
				if err := st.DisableRecipe(context.Background(), recipe.ID, recipe.Revision); err != nil {
					t.Fatal(err)
				}
				assertDurableHealthState(t, st, route.ID, false)
			}
		})
	}
}

func healthSnapshotForCurrent(t *testing.T, st *store.Store, up *model.Upstream, route *model.Route) *store.RouteHealth {
	t.Helper()
	cfg, recipes := restoreTestDeps(st)
	pub, err := cfg.Bundle()
	if err != nil {
		t.Fatal(err)
	}
	recipe, err := recipes.Resolve(context.Background(), RecipeQuery{UpstreamID: up.ID, RouteID: route.ID, Endpoint: model.EndpointMessages})
	if err != nil {
		t.Fatal(err)
	}
	recipe.Facts.Use = model.BindingRealTrafficContext
	_, _, cap, _, err := buildRealExpectations(pub.Probe, up, route, model.EndpointMessages, recipe)
	if err != nil {
		t.Fatal(err)
	}
	return &store.RouteHealth{RouteID: route.ID, State: model.StateDead, ConsecutiveFail: 2, RecoveryRequired: true, Identity: capturedRouteHealthIdentity(pub.Probe, cap, nil, nil)}
}

func healthPublishRecipe(t *testing.T, admin *Service, scope model.RecipeScope, scopeID, routeID int64) int64 {
	t.Helper()
	ctx := context.Background()
	recipe, err := admin.CreateRecipe(ctx, scope, scopeID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	version, err := admin.AddVersion(ctx, recipe.ID, recipe.Revision, RecipeVersionMutation{Method: http.MethodPost, Body: []byte(`{"model":"{{UPSTREAM_MODEL}}","messages":[],"max_tokens":1}`), BodyIsText: true, TimeoutProfile: model.TimeoutL2Standard})
	if err != nil {
		t.Fatal(err)
	}
	recipe, err = admin.GetRecipe(ctx, recipe.ID)
	if err != nil {
		t.Fatal(err)
	}
	tested, err := admin.Test(ctx, version.ID, ManualTestInput{RouteID: routeID, ExpectedRevision: recipe.Revision})
	if err != nil || !tested.Success {
		t.Fatalf("real recipe test failed: success=%t err=%v", tested.Success, err)
	}
	if _, err := admin.Publish(ctx, recipe.ID, version.ID, tested.ID, recipe.Revision, false); err != nil {
		t.Fatal(err)
	}
	return recipe.ID
}
