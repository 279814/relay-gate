package store

import (
	"context"
	"errors"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func assertDeleteHistoryConflict(t *testing.T, st *Store, remove func() error) {
	t.Helper()
	var before, after int64
	if err := st.db.QueryRow(`SELECT total_changes()`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := remove(); !errors.Is(err, ErrDependencyConflict) {
		t.Errorf("history/reference deletion must conflict: %v", err)
	}
	if err := st.db.QueryRow(`SELECT total_changes()`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Error("rejected delete executed mutations, including hidden history rehoming")
	}
}

func TestEntityDeletePreservesOwnedHistoryAndExternalRoutes(t *testing.T) {
	for _, kind := range []string{"upstream", "model", "route"} {
		for _, history := range []string{"version", "capability", "sample", "cost", "external-route"} {
			if kind == "route" && history == "external-route" {
				continue
			}
			t.Run(kind+"/"+history, func(t *testing.T) {
				st := testStore(t)
				ctx := context.Background()
				route := mkRoute(t, st)
				switch history {
				case "version":
					recipeID, err := st.CreateRecipe(model.RecipeScopeRoute, route.ID, model.EndpointMessages)
					if err != nil {
						t.Fatal(err)
					}
					version := &model.ProbeRecipeVersion{RecipeID: recipeID, Origin: model.RecipeLegacyMigration, Method: "POST", Body: []byte(`{"model":"{{UPSTREAM_MODEL}}","max_tokens":1}`), BodyIsText: true, TimeoutProfile: model.TimeoutL2Standard}
					if err := st.AddRecipeVersion(version, 1); err != nil {
						t.Fatal(err)
					}
				case "capability":
					ep := endpointOf(t, st, route.UpstreamID, model.EndpointMessages)
					insertScopedCapability(t, st, model.RecipeScopeRoute, route.ID, ep.ID, model.EndpointMessages, model.CapabilitySupported)
				case "sample":
					sample := mkSample(42)
					sample.RouteID, sample.ModelNameID, sample.UpstreamID = route.ID, route.ModelNameID, route.UpstreamID
					if err := st.InsertSample(sample); err != nil {
						t.Fatal(err)
					}
				case "cost":
					insertProbeCostDaily(t, st, route.ID, route.UpstreamID)
				}
				remove := func() error { return st.DeleteRouteWithRevision(ctx, route.ID, route.Revision) }
				if kind == "upstream" {
					remove = func() error { return st.DeleteUpstreamWithRevision(ctx, route.UpstreamID, 1) }
				} else if kind == "model" {
					remove = func() error { return st.DeleteModelNameWithRevision(ctx, route.ModelNameID, 1) }
				}
				assertDeleteHistoryConflict(t, st, remove)
				if _, err := st.GetRoute(route.ID); err != nil {
					t.Error("protected Route disappeared")
				}
				if _, err := st.GetUpstream(route.UpstreamID); err != nil {
					t.Error("protected Upstream disappeared")
				}
				if _, err := st.GetModelName(route.ModelNameID); err != nil {
					t.Error("protected ModelName disappeared")
				}
			})
		}
	}
}

func TestUpstreamDeletePreservesHistoryWithoutRoutes(t *testing.T) {
	for _, history := range []string{"version", "profile", "cost", "sample"} {
		t.Run(history, func(t *testing.T) {
			st := testStore(t)
			up := mkUpstream(t, st, "history-without-routes")
			switch history {
			case "version":
				mkDraftRecipe(t, st, up)
			case "profile":
				mkCandidate(t, st, up.ID, "history-cli", "history-shape")
			case "cost":
				insertProbeCostDaily(t, st, 0, up.ID)
			case "sample":
				sample := mkSample(42)
				sample.UpstreamID, sample.RouteID, sample.ModelNameID = up.ID, 0, 0
				if err := st.InsertSample(sample); err != nil {
					t.Fatal(err)
				}
			}
			assertDeleteHistoryConflict(t, st, func() error { return st.DeleteUpstreamWithRevision(context.Background(), up.ID, up.Revision) })
		})
	}
}

func TestEmptyEntityDeleteCleansOnlyOwnedCurrentRows(t *testing.T) {
	for _, kind := range []string{"upstream", "model", "route"} {
		t.Run(kind, func(t *testing.T) {
			st := testStore(t)
			ctx := context.Background()
			var err error
			switch kind {
			case "upstream":
				up := mkUpstream(t, st, "empty-delete")
				if _, err := st.CreateRecipe(model.RecipeScopeUpstream, up.ID, model.EndpointModels); err != nil {
					t.Fatal(err)
				}
				err = st.DeleteUpstreamWithRevision(ctx, up.ID, up.Revision)
			case "model":
				name := mkModelName(t, st, "empty-delete", model.ProtoAnthropic)
				err = st.DeleteModelNameWithRevision(ctx, name.ID, name.Revision)
			case "route":
				route := mkRoute(t, st)
				if _, err := st.CreateRecipe(model.RecipeScopeRoute, route.ID, model.EndpointMessages); err != nil {
					t.Fatal(err)
				}
				err = st.DeleteRouteWithRevision(ctx, route.ID, route.Revision)
			}
			if err != nil {
				t.Fatalf("history-free delete rejected: %v", err)
			}
			var recipes, holders int
			if err := st.db.QueryRow(`SELECT COUNT(*) FROM probe_recipe`).Scan(&recipes); err != nil {
				t.Fatal(err)
			}
			if err := st.db.QueryRow(`SELECT COUNT(*) FROM upstream WHERE id<0`).Scan(&holders); err != nil {
				t.Fatal(err)
			}
			if recipes != 0 || holders != 0 {
				t.Fatal("empty delete rehomed unused configuration or invented an archive holder")
			}
		})
	}
}

func TestParentDeleteAndConcurrentRouteCreateHaveOneWinner(t *testing.T) {
	for _, kind := range []string{"upstream", "model"} {
		for attempt := 0; attempt < 5; attempt++ {
			t.Run(kind+"/"+string(rune('a'+attempt)), func(t *testing.T) {
				st := testStore(t)
				up := mkUpstream(t, st, "concurrent-parent")
				name := mkModelName(t, st, "concurrent-model", model.ProtoAnthropic)
				start := make(chan struct{})
				createResult, deleteResult := make(chan error, 1), make(chan error, 1)
				route := &model.Route{UpstreamID: up.ID, ModelNameID: name.ID, Enabled: true}
				go func() { <-start; createResult <- st.CreateRoute(route) }()
				go func() {
					<-start
					if kind == "upstream" {
						deleteResult <- st.DeleteUpstreamWithRevision(context.Background(), up.ID, up.Revision)
					} else {
						deleteResult <- st.DeleteModelNameWithRevision(context.Background(), name.ID, name.Revision)
					}
				}()
				close(start)
				created, removed := <-createResult, <-deleteResult
				if (created == nil) == (removed == nil) {
					t.Fatalf("concurrent parent delete and route create must have one winner: create=%v delete=%v", created, removed)
				}
				if created == nil && !errors.Is(removed, ErrDependencyConflict) {
					t.Fatalf("new Route was not protected from parent deletion: %v", removed)
				}
				if err := validateForeignKeys(context.Background(), st.db); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestUpstreamDeleteKeepsExternalEndpointTransformReference(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "external-endpoint-reference")
	ep := endpointOf(t, st, up.ID, model.EndpointMessages)
	// Historical/externally supplied bindings can name an Endpoint without a
	// current Route on its owning Upstream. A parent delete must not erase it.
	insertTransformBinding(t, st, 999, ep.ID, 88)
	assertDeleteHistoryConflict(t, st, func() error { return st.DeleteUpstream(up.ID) })
}
