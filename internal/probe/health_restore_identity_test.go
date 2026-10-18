package probe

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/observationseq"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/store"
)

func TestRouteHealthBoundProbeSecretChangeCannotReviveNegative(t *testing.T) {
	var secret *model.ProbeSecret
	st, up, _, route, row := boundNegativeSnapshot(t, func(st *store.Store, up *model.Upstream, _ *model.ModelName, _ *model.Route) {
		var err error
		secret, err = st.CreateProbeSecret("health_auth", []byte("fixture-bound-health-auth"))
		if err != nil {
			t.Fatal(err)
		}
		ep, err := st.Endpoint(context.Background(), up.ID, model.EndpointMessages)
		if err != nil {
			t.Fatal(err)
		}
		ep.AuthProfile = model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: "probe:health_auth"}
		ep.LegacyCompatRealOnly = false
		if err := st.UpdateEndpoint(ep, ep.Revision); err != nil {
			t.Fatal(err)
		}
	})
	if len(row.Identity.Route.Revision.ProbeSecrets) != 1 || row.Identity.Route.Revision.ProbeSecrets[0].ID != secret.ID {
		t.Fatal("fixture lacks the real Auth Secret binding")
	}
	if err := st.SaveRouteHealth([]*store.RouteHealth{row}); err != nil {
		t.Fatal(err)
	}
	before, err := st.Endpoint(context.Background(), up.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateProbeSecret(secret.ID, secret.Revision, []byte("replacement-bound-health-auth")); err != nil {
		t.Fatal(err)
	}
	after, err := st.Endpoint(context.Background(), up.ID, model.EndpointMessages)
	if err != nil || after.Revision != before.Revision {
		t.Fatal("test must change only the bound Secret revision")
	}
	cfg, _ := restoreTestDeps(st)
	tracker := health.NewTracker(cfg)
	if n, err := RestoreRouteHealth(context.Background(), tracker, st, cfg); err != nil || n != 0 || tracker.State(route.ID) != model.StateUnknown {
		t.Fatalf("rotated Secret revived negative: n=%d state=%s err=%v", n, tracker.State(route.ID), err)
	}
}

func TestRouteHealthL1RestorationUsesOnlyItsActualStagePolicy(t *testing.T) {
	for _, related := range []bool{false, true} {
		t.Run(map[bool]string{false: "unrelated L2", true: "actual L1"}[related], func(t *testing.T) {
			st, _, _, route, row := boundNegativeSnapshot(t)
			cfg, _ := restoreTestDeps(st)
			pub, err := cfg.Bundle()
			if err != nil {
				t.Fatal(err)
			}
			row.Identity = capturedL1RouteHealthIdentity(pub.Probe, route.ID)
			if row.Identity == nil || !row.Identity.RouteContextOnly {
				t.Fatal("L1 child model context not captured")
			}
			if err := st.SaveRouteHealth([]*store.RouteHealth{row}); err != nil {
				t.Fatal(err)
			}
			settings, revision, err := st.GetSettingsWithRevision()
			if err != nil {
				t.Fatal(err)
			}
			if related {
				settings.L1TotalSec++
			} else {
				settings.L2FirstSemanticSec++
			}
			if _, err := st.SaveSettingsWithRevision(settings, revision); err != nil {
				t.Fatal(err)
			}
			freshCfg, _ := restoreTestDeps(st)
			fresh := health.NewTracker(freshCfg)
			n, err := RestoreRouteHealth(context.Background(), fresh, st, freshCfg)
			if err != nil {
				t.Fatal(err)
			}
			if (n == 1) == related || (fresh.State(route.ID) == model.StateDead) == related {
				t.Fatalf("L1 current=%d state=%s related=%t", n, fresh.State(route.ID), related)
			}
		})
	}
}

func TestRouteHealthCannotRestoreAReusedOrDeletedRoute(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		t.Run(map[bool]string{false: "deleted", true: "reused"}[reuse], func(t *testing.T) {
			st, up, mn, route, row := boundNegativeSnapshot(t)
			if err := st.SaveRouteHealth([]*store.RouteHealth{row}); err != nil {
				t.Fatal(err)
			}
			if err := st.DeleteRouteWithRevision(context.Background(), route.ID, route.Revision); err != nil {
				t.Fatal(err)
			}
			if reuse {
				if _, err := st.DB().Exec(`DELETE FROM sqlite_sequence WHERE name='route'`); err != nil {
					t.Fatal(err)
				}
				fresh := &model.Route{UpstreamID: up.ID, ModelNameID: mn.ID, Enabled: true, Weight: 100}
				if err := st.CreateRoute(fresh); err != nil {
					t.Fatal(err)
				}
				if fresh.ID != route.ID {
					t.Fatal("test did not reuse the numeric id")
				}
				if _, err := st.DB().Exec(`UPDATE route SET created_at=? WHERE id=?`, route.CreatedAt+1000, fresh.ID); err != nil {
					t.Fatal(err)
				}
			}
			// A persister captured before deletion must not stamp the old snapshot
			// onto either an absent row or the fresh row reusing its numeric id.
			if err := st.SaveRouteHealth([]*store.RouteHealth{row}); err != nil {
				t.Fatal(err)
			}
			cfg, _ := restoreTestDeps(st)
			tracker := health.NewTracker(cfg)
			if n, err := RestoreRouteHealth(context.Background(), tracker, st, cfg); err != nil || n != 0 || tracker.State(route.ID) != model.StateUnknown {
				t.Fatalf("old incarnation revived: n=%d state=%s err=%v", n, tracker.State(route.ID), err)
			}
		})
	}
}

func TestRouteHealthRecipePublishAfterActualTestRejectsOldSnapshot(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		drainBody(r)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"type":"message","content":[{"type":"text","text":"tested"}]}`)
	}))
	defer remote.Close()
	st, _, _, route, row := boundNegativeSnapshot(t, func(st *store.Store, up *model.Upstream, _ *model.ModelName, _ *model.Route) {
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
	if err := st.SaveRouteHealth([]*store.RouteHealth{row}); err != nil {
		t.Fatal(err)
	}
	cfg, recipes := restoreTestDeps(st)
	if _, err := cfg.Bundle(); err != nil {
		t.Fatal(err)
	}
	transport := outbound.NewManager()
	defer transport.CloseIdleConnections()
	executor := NewExecutor(outbound.NewProvider(cfg, st, outbound.NewResolver(testHasher{})), st, recipes, ManagerTransports{Manager: transport}, NewExecutionOnlyRecorder(st), AlwaysOpenAdmission(), WallClock(), discardLogger())
	ctx := context.Background()
	seq, err := observationseq.Open(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	defer seq.Close()
	manual := NewScheduler(cfg, health.NewTracker(cfg), health.NewReachabilityTracker(cfg), discardLogger()).WithRecipes(recipes).WithExecutor(executor).WithSequencer(seq)
	admin := NewService(st, executor, nil, cfg, nil, nil).WithManualPreparer(manual)
	recipe, err := admin.CreateRecipe(ctx, model.RecipeScopeRoute, route.ID, model.EndpointMessages)
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
	tested, err := admin.Test(ctx, version.ID, ManualTestInput{RouteID: route.ID, ExpectedRevision: recipe.Revision})
	if err != nil || !tested.Success {
		t.Fatalf("explicit real HTTP test=%+v err=%v", tested, err)
	}
	if _, err := admin.Publish(ctx, recipe.ID, version.ID, tested.ID, recipe.Revision, false); err != nil {
		t.Fatal(err)
	}
	fresh := health.NewTracker(cfg)
	if n, err := RestoreRouteHealth(ctx, fresh, st, cfg); err != nil || n != 0 || fresh.State(route.ID) != model.StateUnknown {
		t.Fatalf("old embedded absence survived publish: n=%d state=%s err=%v", n, fresh.State(route.ID), err)
	}
}

func TestRouteHealthNewReducerPolicyDoesNotReuseOldCounters(t *testing.T) {
	st, up, _, route, row := boundNegativeSnapshot(t)
	cfg, recipes := restoreTestDeps(st)
	if _, err := cfg.Bundle(); err != nil {
		t.Fatal(err)
	}
	tracker := health.NewTracker(cfg)
	for n := 0; n < 2; n++ {
		tracker.Report(health.Report{RouteID: route.ID, Verdict: health.VerdictUnavailable, Identity: row.Identity})
	}
	settings, revision, err := st.GetSettingsWithRevision()
	if err != nil {
		t.Fatal(err)
	}
	settings.FailThreshold = 3
	if _, err := st.SaveSettingsWithRevision(settings, revision); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Refresh(); err != nil {
		t.Fatal(err)
	}
	pub, _ := cfg.Bundle()
	recipe, err := recipes.Resolve(context.Background(), RecipeQuery{UpstreamID: up.ID, RouteID: route.ID, Endpoint: model.EndpointMessages})
	if err != nil {
		t.Fatal(err)
	}
	recipe.Facts.Use = model.BindingRealTrafficContext
	_, _, expectation, _, err := buildRealExpectations(pub.Probe, up, route, model.EndpointMessages, recipe)
	if err != nil {
		t.Fatal(err)
	}
	identity := capturedRouteHealthIdentity(pub.Probe, expectation, nil, nil)
	if changed := tracker.Report(health.Report{RouteID: route.ID, Verdict: health.VerdictUnavailable, Identity: identity}); !changed {
		t.Fatal("new-policy dead→unknown transition was not reported")
	}
	if got := tracker.Status(route.ID); got.State != model.StateUnknown || got.ConsecutiveFail != 1 {
		t.Fatalf("old policy counters blessed by new identity: %+v", got)
	}
}
