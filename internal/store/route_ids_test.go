package store

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRouteIDCommandsUseCoveringFKIndexesAndHonorContext(t *testing.T) {
	st := testStore(t)
	for _, command := range []struct {
		name  string
		query string
		read  func(context.Context, int64) ([]int64, error)
	}{
		{"upstream", `SELECT id FROM route WHERE upstream_id=? ORDER BY id`, st.RouteIDsOfUpstream},
		{"model_name", `SELECT id FROM route WHERE model_name_id=? ORDER BY id`, st.RouteIDsOfModelName},
	} {
		t.Run(command.name, func(t *testing.T) {
			var step, parent, unused int
			var plan string
			if err := st.db.QueryRow(`EXPLAIN QUERY PLAN `+command.query, 1).Scan(&step, &parent, &unused, &plan); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(plan, "COVERING INDEX idx_route_"+command.name) || strings.Contains(plan, "TEMP B-TREE") {
				t.Fatalf("identity command did not use covering FK index: %s", plan)
			}
			if _, err := command.read(context.Background(), 0); err == nil {
				t.Fatal("zero parent cannot enumerate all route IDs")
			}
			if ids, err := command.read(context.Background(), 999); err != nil || len(ids) != 0 {
				t.Fatal("absent parent returned identities")
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := command.read(ctx, 1); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled command=%v", err)
			}
		})
	}
}
