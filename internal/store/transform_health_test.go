package store

import (
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/transform"
)

func TestLiveTransformBindingAdvancesHealthLifecycleInItsTransaction(t *testing.T) {
	st := testStore(t)
	route := mkRoute(t, st)
	registry := transform.NewRegistry(8).WithPersist(st)
	set, err := registry.CreateSet("health-binding")
	if err != nil {
		t.Fatal(err)
	}
	draft := func() {
		t.Helper()
		if _, err := registry.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindSetHeader, Name: "X-Live", Value: "1"}}, transform.FailClosed, transform.FailOpen, ""); err != nil {
			t.Fatal(err)
		}
	}
	draft()
	check := func(revision int64, state model.HealthState) {
		t.Helper()
		got, err := st.GetRoute(route.ID)
		if err != nil || got.CapabilityRevision != revision || got.Revision != route.Revision {
			t.Fatalf("lifecycle=%+v err=%v want=%d", got, err, revision)
		}
		rows, err := st.ListRouteHealth()
		if err != nil || len(rows) != 1 || rows[0].State != state {
			t.Fatalf("health=%+v %v", rows, err)
		}
	}
	if err := st.SaveRouteHealth([]*RouteHealth{{RouteID: route.ID, State: model.StateDead, ConsecutiveFail: 8}}); err != nil {
		t.Fatal(err)
	}
	_, version, err := registry.PublishSnapshot(set.ID, route.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	check(route.CapabilityRevision+1, model.StateUnknown)
	if err := st.SaveRouteHealth([]*RouteHealth{{RouteID: route.ID, State: model.StateDead, ConsecutiveFail: 8}}); err != nil {
		t.Fatal(err)
	}
	draft()
	if _, _, err := registry.ShadowSnapshot(set.ID, route.ID, 1); err != nil {
		t.Fatal(err)
	}
	check(route.CapabilityRevision+1, model.StateDead)
	if _, err := registry.Rollback(route.ID, 1, version.ID); err != nil {
		t.Fatal(err)
	}
	check(route.CapabilityRevision+1, model.StateDead)
	if _, err := registry.ClearPublished(route.ID, 1); err != nil {
		t.Fatal(err)
	}
	check(route.CapabilityRevision+2, model.StateUnknown)
	if err := st.SaveRouteHealth([]*RouteHealth{{RouteID: route.ID, State: model.StateDead, ConsecutiveFail: 8}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`CREATE TRIGGER reject_binding BEFORE INSERT ON transform_binding BEGIN SELECT RAISE(ABORT,'binding denied'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Rollback(route.ID, 1, version.ID); err == nil {
		t.Fatal("fixture did not reject the transform transaction")
	}
	check(route.CapabilityRevision+2, model.StateDead)
}
