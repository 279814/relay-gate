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

// DeleteRoute must drop probe_cost_daily rows in the same transaction. A failed
// delete rolls the detach back; a sibling route's rollups stay. After a
// successful delete, a row that reuses the id must not see the old totals.
func TestDeleteRoute_DetachesProbeCostDailyInSameTx(t *testing.T) {
	store := testStore(t)
	up := mkUpstream(t, store, "cost-rt-detach-u")
	upSibling := mkUpstream(t, store, "cost-rt-detach-u2")
	mn := mkModelName(t, store, "cost-rt-detach-m", model.ProtoAnthropic)
	target := &model.Route{ModelNameID: mn.ID, UpstreamID: up.ID}
	target.Defaults()
	if err := store.CreateRoute(target); err != nil {
		t.Fatal(err)
	}
	sibling := &model.Route{ModelNameID: mn.ID, UpstreamID: upSibling.ID}
	sibling.Defaults()
	if err := store.CreateRoute(sibling); err != nil {
		t.Fatal(err)
	}

	insertProbeCostDaily(t, store, target.ID, up.ID)
	insertProbeCostDaily(t, store, sibling.ID, upSibling.ID)
	if got := countProbeCostByRoute(t, store, target.ID); got != 1 {
		t.Fatalf("setup target cost rows=%d", got)
	}

	if _, err := store.db.Exec(`INSERT INTO calibration_run (id,route_id,endpoint,state,created_at)
		VALUES ('cost-rt-cal',?,'models','planned',?)`, target.ID, nowMS()); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteRoute(target.ID); err == nil {
		t.Fatal("DeleteRoute must fail while calibration_run pins the route")
	}
	if got := countProbeCostByRoute(t, store, target.ID); got != 1 {
		t.Fatalf("failed delete must keep cost rows: got %d", got)
	}
	if got := countProbeCostByRoute(t, store, sibling.ID); got != 1 {
		t.Fatalf("sibling cost rows must stay after failed delete: got %d", got)
	}

	if _, err := store.db.Exec(`DELETE FROM calibration_run WHERE id='cost-rt-cal'`); err != nil {
		t.Fatal(err)
	}
	oldID := target.ID
	if err := store.DeleteRoute(oldID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got := countProbeCostByRoute(t, store, oldID); got != 0 {
		t.Fatalf("successful delete must detach cost rows: got %d", got)
	}
	if got := countProbeCostByRoute(t, store, sibling.ID); got != 1 {
		t.Fatalf("sibling cost rows must stay: got %d", got)
	}

	// Drop the sibling so a sequence reset can reuse oldID (SQLite next id is
	// max(existing)+1 even after sqlite_sequence is cleared).
	if err := store.DeleteRoute(sibling.ID); err != nil {
		t.Fatalf("delete sibling: %v", err)
	}
	if _, err := store.db.Exec(`DELETE FROM sqlite_sequence WHERE name='route'`); err != nil {
		t.Fatalf("reset sequence: %v", err)
	}
	neu := &model.Route{ModelNameID: mn.ID, UpstreamID: up.ID, Enabled: true}
	if err := store.CreateRoute(neu); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	if neu.ID != oldID {
		t.Fatalf("forced reuse failed: new id=%d old=%d", neu.ID, oldID)
	}
	page, err := store.ListProbeCostDaily(context.Background(), model.ProbeCostFilter{RouteID: neu.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 0 {
		t.Fatalf("reused route must not inherit old cost totals: got %d rows", len(page.Items))
	}
}

// DeleteUpstream must drop its probe_cost_daily rows (and child-route rollups)
// in the same transaction. A sibling upstream's rollups stay; a reused id must
// not see the old totals.
func TestDeleteUpstream_DetachesProbeCostDailyInSameTx(t *testing.T) {
	store := testStore(t)
	targetUp := mkUpstream(t, store, "cost-up-detach-u")
	siblingUp := mkUpstream(t, store, "cost-up-detach-u2")
	mn := mkModelName(t, store, "cost-up-detach-m", model.ProtoAnthropic)
	target := &model.Route{ModelNameID: mn.ID, UpstreamID: targetUp.ID}
	target.Defaults()
	if err := store.CreateRoute(target); err != nil {
		t.Fatal(err)
	}
	sibling := &model.Route{ModelNameID: mn.ID, UpstreamID: siblingUp.ID}
	sibling.Defaults()
	if err := store.CreateRoute(sibling); err != nil {
		t.Fatal(err)
	}

	insertProbeCostDaily(t, store, target.ID, targetUp.ID)
	insertProbeCostDaily(t, store, sibling.ID, siblingUp.ID)
	insertProbeCostDaily(t, store, 0, targetUp.ID) // L1-style upstream-only row

	if err := store.DeleteUpstream(0); err == nil {
		t.Fatal("DeleteUpstream(0) must fail")
	}
	if got := countProbeCostByUpstream(t, store, targetUp.ID); got != 2 {
		t.Fatalf("failed delete must keep cost rows: got %d", got)
	}

	oldID := targetUp.ID
	oldRouteID := target.ID
	if err := store.DeleteUpstream(oldID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got := countProbeCostByUpstream(t, store, oldID); got != 0 {
		t.Fatalf("successful delete must detach upstream cost rows: got %d", got)
	}
	if got := countProbeCostByRoute(t, store, oldRouteID); got != 0 {
		t.Fatalf("successful delete must detach child-route cost rows: got %d", got)
	}
	if got := countProbeCostByUpstream(t, store, siblingUp.ID); got != 1 {
		t.Fatalf("sibling cost rows must stay: got %d", got)
	}

	// Drop the sibling so a sequence reset can reuse oldID.
	if err := store.DeleteUpstream(siblingUp.ID); err != nil {
		t.Fatalf("delete sibling: %v", err)
	}
	if _, err := store.db.Exec(`DELETE FROM sqlite_sequence WHERE name='upstream'`); err != nil {
		t.Fatalf("reset sequence: %v", err)
	}
	if _, err := store.db.Exec(`DELETE FROM sqlite_sequence WHERE name='upstream_endpoint'`); err != nil {
		t.Fatalf("reset endpoint sequence: %v", err)
	}
	neu := &model.Upstream{Name: "cost-up-detach-reuse", BaseURL: "https://reuse.example", APIKey: "sk-bbbbbbbbbbbb", Enabled: true}
	if err := store.CreateUpstream(neu); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	if neu.ID != oldID {
		t.Fatalf("forced reuse failed: new id=%d old=%d", neu.ID, oldID)
	}
	page, err := store.ListProbeCostDaily(context.Background(), model.ProbeCostFilter{UpstreamID: neu.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 0 {
		t.Fatalf("reused upstream must not inherit old cost totals: got %d rows", len(page.Items))
	}
}

// DeleteModelName must drop child-route probe_cost_daily rows in the same
// transaction (CASCADE skips DeleteRoute). A failed delete rolls the detach
// back; a sibling model_name's route rollups stay.
func TestDeleteModelName_DetachesProbeCostDailyInSameTx(t *testing.T) {
	store := testStore(t)
	up := mkUpstream(t, store, "cost-mn-detach-u")
	upSibling := mkUpstream(t, store, "cost-mn-detach-u2")
	targetMN := mkModelName(t, store, "cost-mn-detach-m", model.ProtoAnthropic)
	siblingMN := mkModelName(t, store, "cost-mn-detach-m2", model.ProtoAnthropic)
	target := &model.Route{ModelNameID: targetMN.ID, UpstreamID: up.ID}
	target.Defaults()
	if err := store.CreateRoute(target); err != nil {
		t.Fatal(err)
	}
	sibling := &model.Route{ModelNameID: siblingMN.ID, UpstreamID: upSibling.ID}
	sibling.Defaults()
	if err := store.CreateRoute(sibling); err != nil {
		t.Fatal(err)
	}

	insertProbeCostDaily(t, store, target.ID, up.ID)
	insertProbeCostDaily(t, store, sibling.ID, upSibling.ID)

	if _, err := store.db.Exec(`INSERT INTO calibration_run (id,route_id,endpoint,state,created_at)
		VALUES ('cost-mn-cal',?,'models','planned',?)`, target.ID, nowMS()); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteModelName(targetMN.ID); err == nil {
		t.Fatal("DeleteModelName must fail while calibration_run pins the route")
	}
	if got := countProbeCostByRoute(t, store, target.ID); got != 1 {
		t.Fatalf("failed delete must keep cost rows: got %d", got)
	}
	if got := countProbeCostByRoute(t, store, sibling.ID); got != 1 {
		t.Fatalf("sibling cost rows must stay after failed delete: got %d", got)
	}

	if _, err := store.db.Exec(`DELETE FROM calibration_run WHERE id='cost-mn-cal'`); err != nil {
		t.Fatal(err)
	}
	oldRouteID := target.ID
	if err := store.DeleteModelName(targetMN.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got := countProbeCostByRoute(t, store, oldRouteID); got != 0 {
		t.Fatalf("successful delete must detach child-route cost rows: got %d", got)
	}
	if got := countProbeCostByRoute(t, store, sibling.ID); got != 1 {
		t.Fatalf("sibling cost rows must stay: got %d", got)
	}

	// Drop the sibling route so a sequence reset can reuse oldRouteID.
	if err := store.DeleteRoute(sibling.ID); err != nil {
		t.Fatalf("delete sibling: %v", err)
	}
	if _, err := store.db.Exec(`DELETE FROM sqlite_sequence WHERE name='route'`); err != nil {
		t.Fatalf("reset sequence: %v", err)
	}
	neuMN := mkModelName(t, store, "cost-mn-detach-reuse", model.ProtoAnthropic)
	neu := &model.Route{ModelNameID: neuMN.ID, UpstreamID: up.ID, Enabled: true}
	if err := store.CreateRoute(neu); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	if neu.ID != oldRouteID {
		t.Fatalf("forced reuse failed: new id=%d old=%d", neu.ID, oldRouteID)
	}
	page, err := store.ListProbeCostDaily(context.Background(), model.ProbeCostFilter{RouteID: neu.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 0 {
		t.Fatalf("reused route must not inherit old cost totals: got %d rows", len(page.Items))
	}
}
