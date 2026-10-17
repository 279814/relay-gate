package store

import (
	"context"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func insertProbeCostDaily(t *testing.T, store *Store, routeID, upstreamID int64) {
	t.Helper()
	_, err := store.db.Exec(`INSERT INTO probe_cost_daily
		(day_utc,trigger,origin,endpoint,route_id,upstream_id,requests,succeeded)
		VALUES ('2099-01-01','scheduled','basic_protocol','models',?,?,7,7)`, routeID, upstreamID)
	if err != nil {
		t.Fatal(err)
	}
}

func countProbeCostByRoute(t *testing.T, store *Store, routeID int64) int {
	t.Helper()
	var n int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM probe_cost_daily WHERE route_id=?`, routeID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func countProbeCostByUpstream(t *testing.T, store *Store, upstreamID int64) int {
	t.Helper()
	var n int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM probe_cost_daily WHERE upstream_id=?`, upstreamID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Retention is an explicit, separate operation. Entity deletion cannot silently
// remove accounting history, including rollups with no live execution row.
func TestEntityDeletePreservesProbeCostUntilExplicitRetentionCleanup(t *testing.T) {
	for _, kind := range []string{"route", "upstream", "model"} {
		t.Run(kind, func(t *testing.T) {
			st := testStore(t)
			target := mkRoute(t, st)
			siblingUp := mkUpstream(t, st, "cost-sibling")
			sibling := &model.Route{UpstreamID: siblingUp.ID, ModelNameID: target.ModelNameID, Enabled: true}
			if err := st.CreateRoute(sibling); err != nil {
				t.Fatal(err)
			}
			insertProbeCostDaily(t, st, target.ID, target.UpstreamID)
			insertProbeCostDaily(t, st, sibling.ID, sibling.UpstreamID)
			remove := func() error { return st.DeleteRoute(target.ID) }
			if kind == "upstream" {
				remove = func() error { return st.DeleteUpstream(target.UpstreamID) }
			}
			if kind == "model" {
				remove = func() error { return st.DeleteModelName(target.ModelNameID) }
			}
			assertDeleteHistoryConflict(t, st, remove)
			if countProbeCostByRoute(t, st, target.ID) != 1 || countProbeCostByUpstream(t, st, sibling.UpstreamID) != 1 {
				t.Fatal("refused delete changed accounting history")
			}
			// ModelName also has an independently owned sibling Route, so retain it.
			if kind == "model" {
				return
			}
			if _, err := st.db.Exec(`DELETE FROM probe_cost_daily WHERE route_id=?`, target.ID); err != nil {
				t.Fatal(err)
			}
			if kind == "upstream" {
				if err := st.DeleteRoute(target.ID); err != nil {
					t.Fatal(err)
				}
			}
			if err := remove(); err != nil {
				t.Fatalf("history-free deletion after retention cleanup: %v", err)
			}
			page, err := st.ListProbeCostDaily(context.Background(), model.ProbeCostFilter{UpstreamID: sibling.UpstreamID})
			if err != nil || len(page.Items) != 1 {
				t.Fatal("unrelated accounting history changed")
			}
		})
	}
}
