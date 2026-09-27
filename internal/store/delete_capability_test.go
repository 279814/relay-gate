package store

import (
	"context"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

// routeWithCapability creates a Route that already has a route-scoped
// endpoint_capability row, as any L2 probe on messages leaves behind.
func routeWithCapability(t *testing.T, st *Store, name string) (*model.ModelName, *model.Route) {
	t.Helper()
	up := mkUpstream(t, st, name+"-up")
	mn := mkModelName(t, st, name+"-mn", model.ProtoAnthropic)
	r := &model.Route{ModelNameID: mn.ID, UpstreamID: up.ID}
	r.Defaults()
	if err := st.CreateRoute(r); err != nil {
		t.Fatal(err)
	}
	ep := endpointOf(t, st, up.ID, model.EndpointMessages)
	tx, err := st.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := saveCapability(context.Background(), tx, &model.EndpointCapability{
		ScopeType: model.RecipeScopeRoute, ScopeID: r.ID, Endpoint: model.EndpointMessages,
		EndpointID: ep.ID, State: model.CapabilitySupported,
		PolicySelector: model.EvidencePolicySelector{Kind: model.EvidenceL2, Endpoint: model.EndpointMessages},
	}); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return mn, r
}

func routeCapabilityCount(t *testing.T, st *Store, routeID int64) int {
	t.Helper()
	var n int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM endpoint_capability WHERE scope_route_id=?`, routeID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// §9.2: Route delete clears Capability. The route-scoped row is ON DELETE
// RESTRICT, so leaving it makes every probed Route undeletable.
func TestDeleteRoute_ClearsRouteScopedCapability(t *testing.T) {
	st := testStore(t)
	_, r := routeWithCapability(t, st, "del-rt-cap")
	if err := st.DeleteRoute(r.ID); err != nil {
		t.Fatalf("DeleteRoute with route-scoped capability: %v", err)
	}
	if _, err := st.GetRoute(r.ID); err == nil {
		t.Fatal("route still exists after delete")
	}
	if n := routeCapabilityCount(t, st, r.ID); n != 0 {
		t.Fatalf("route-scoped capability rows left behind: %d", n)
	}
}

// §9.2: ModelName delete CASCADEs child Routes and clears their Capability.
func TestDeleteModelName_ClearsChildRouteScopedCapability(t *testing.T) {
	st := testStore(t)
	mn, r := routeWithCapability(t, st, "del-mn-cap")
	if err := st.DeleteModelName(mn.ID); err != nil {
		t.Fatalf("DeleteModelName with child route capability: %v", err)
	}
	if _, err := st.GetModelName(mn.ID); err == nil {
		t.Fatal("model name still exists after delete")
	}
	if _, err := st.GetRoute(r.ID); err == nil {
		t.Fatal("child route still exists after model name delete")
	}
	if n := routeCapabilityCount(t, st, r.ID); n != 0 {
		t.Fatalf("child route-scoped capability rows left behind: %d", n)
	}
}
