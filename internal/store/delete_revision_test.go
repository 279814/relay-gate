package store

import (
	"context"
	"errors"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestConfigDeleteRevisionConflictKeepsRowsAndChildren(t *testing.T) {
	for _, kind := range []string{"upstream", "model_name", "route"} {
		t.Run(kind, func(t *testing.T) {
			st := testStore(t)
			route := mkRoute(t, st)
			up, err := st.GetUpstream(route.UpstreamID)
			if err != nil {
				t.Fatal(err)
			}
			mn, err := st.GetModelName(route.ModelNameID)
			if err != nil {
				t.Fatal(err)
			}
			var remove func(context.Context, int64) error
			var revision int64
			switch kind {
			case "upstream":
				revision = up.Revision
				up.Name += "-updated"
				if err := st.UpdateUpstreamWithRevision(context.Background(), up, revision); err != nil {
					t.Fatal(err)
				}
				remove = func(ctx context.Context, rev int64) error { return st.DeleteUpstreamWithRevision(ctx, up.ID, rev) }
			case "model_name":
				revision = mn.Revision
				mn.Name += "-updated"
				if err := st.UpdateModelNameWithRevision(context.Background(), mn, revision); err != nil {
					t.Fatal(err)
				}
				remove = func(ctx context.Context, rev int64) error { return st.DeleteModelNameWithRevision(ctx, mn.ID, rev) }
			case "route":
				revision = route.Revision
				route.Weight++
				if err := st.UpdateRouteWithRevision(context.Background(), route, revision); err != nil {
					t.Fatal(err)
				}
				remove = func(ctx context.Context, rev int64) error { return st.DeleteRouteWithRevision(ctx, route.ID, rev) }
			}
			if err := remove(context.Background(), revision); !errors.Is(err, ErrRevisionConflict) {
				t.Fatalf("stale delete should conflict: %v", err)
			}
			for _, rev := range []int64{0, -1} {
				if err := remove(context.Background(), rev); !errors.Is(err, model.ErrValidation) {
					t.Fatalf("missing/negative revision should fail validation: %v", err)
				}
			}
			if _, err := st.GetRoute(route.ID); err != nil {
				t.Fatalf("rejected deletion removed child route: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := remove(ctx, revision+1); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled deletion ignored context: %v", err)
			}
			if kind != "route" {
				if err := remove(context.Background(), revision+1); !errors.Is(err, ErrDependencyConflict) {
					t.Fatalf("parent delete must retain external route: %v", err)
				}
				if err := st.DeleteRouteWithRevision(context.Background(), route.ID, route.Revision); err != nil {
					t.Fatal(err)
				}
			}
			if err := remove(context.Background(), revision+1); err != nil {
				t.Fatal(err)
			}
			if _, err := st.GetRoute(route.ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("current deletion did not remove route: %v", err)
			}
		})
	}
}
