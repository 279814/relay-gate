package store

import (
	"context"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

// §9.2: Enabled false→true must clear Capability. Enabled is not part of the
// Observation Token, so a stored config_error row would otherwise be put back by
// RestoreConfigErrors on restart and kept by the §8.13 sticky reducer.

func insertScopedCapability(t *testing.T, st *Store, scope model.RecipeScope, scopeID, endpointID int64,
	endpoint model.EndpointKind, state model.CapabilityState) {
	t.Helper()
	var upstreamID, routeID any
	if scope == model.RecipeScopeRoute {
		routeID = scopeID
	} else {
		upstreamID = scopeID
	}
	if _, err := st.db.Exec(`INSERT INTO endpoint_capability
		(scope_upstream_id,scope_route_id,endpoint,endpoint_id,evidence_kind,state,observation_token,
		 upstream_network_revision,upstream_credential_revision,endpoint_revision,
		 auth_profile_revision,recipe_binding_revision,probe_settings_fingerprint,
		 probe_secret_revisions_hash,observed_at,expires_at)
		VALUES (?,?,?,?,'l2',?,'tok',1,1,1,1,1,'fp','sh',1,0)`,
		upstreamID, routeID, endpoint, endpointID, state); err != nil {
		t.Fatal(err)
	}
}

type capKey struct {
	scope    model.RecipeScope
	scopeID  int64
	endpoint model.EndpointKind
}

func storedCapStates(t *testing.T, st *Store) map[capKey]model.CapabilityState {
	t.Helper()
	out := map[capKey]model.CapabilityState{}
	for _, state := range []model.CapabilityState{model.CapabilityConfigError, model.CapabilityUnsupported} {
		rows, err := st.ListEndpointCapabilitiesByState(context.Background(), state)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			out[capKey{row.ScopeType, row.ScopeID, row.Endpoint}] = row.State
		}
	}
	return out
}

func setRouteEnabled(t *testing.T, st *Store, id int64, enabled bool) {
	t.Helper()
	current, err := st.GetRoute(id)
	if err != nil {
		t.Fatal(err)
	}
	current.Enabled = enabled
	if err := st.UpdateRouteWithRevision(context.Background(), current, current.Revision); err != nil {
		t.Fatal(err)
	}
}

func setUpstreamEnabled(t *testing.T, st *Store, id int64, enabled bool) {
	t.Helper()
	current, err := st.GetUpstream(id)
	if err != nil {
		t.Fatal(err)
	}
	current.Enabled = enabled
	if err := st.UpdateUpstreamWithRevision(context.Background(), current, current.Revision); err != nil {
		t.Fatal(err)
	}
}

func TestRouteReEnableDeletesStoredConfigError(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "reen-route")
	messages := endpointOf(t, st, up.ID, model.EndpointMessages)
	count := endpointOf(t, st, up.ID, model.EndpointCountTokens)
	models := endpointOf(t, st, up.ID, model.EndpointModels)
	target := &model.Route{ModelNameID: mkModelName(t, st, "reen-a", model.ProtoAnthropic).ID, UpstreamID: up.ID, Enabled: true}
	sibling := &model.Route{ModelNameID: mkModelName(t, st, "reen-b", model.ProtoAnthropic).ID, UpstreamID: up.ID, Enabled: true}
	for _, r := range []*model.Route{target, sibling} {
		if err := st.CreateRoute(r); err != nil {
			t.Fatal(err)
		}
	}
	insertScopedCapability(t, st, model.RecipeScopeRoute, target.ID, messages.ID, model.EndpointMessages, model.CapabilityConfigError)
	insertScopedCapability(t, st, model.RecipeScopeRoute, target.ID, count.ID, model.EndpointCountTokens, model.CapabilityConfigError)
	insertScopedCapability(t, st, model.RecipeScopeRoute, sibling.ID, messages.ID, model.EndpointMessages, model.CapabilityConfigError)
	insertScopedCapability(t, st, model.RecipeScopeUpstream, up.ID, models.ID, model.EndpointModels, model.CapabilityConfigError)

	setRouteEnabled(t, st, target.ID, false)
	if got := len(storedCapStates(t, st)); got != 4 {
		t.Fatalf("disable must not touch stored Capability: %d rows, want 4", got)
	}
	setRouteEnabled(t, st, target.ID, true)

	got := storedCapStates(t, st)
	for _, ep := range []model.EndpointKind{model.EndpointMessages, model.EndpointCountTokens} {
		if state, ok := got[capKey{model.RecipeScopeRoute, target.ID, ep}]; ok {
			t.Errorf("re-enabled route %s config_error survived: %s", ep, state)
		}
	}
	if got[capKey{model.RecipeScopeRoute, sibling.ID, model.EndpointMessages}] != model.CapabilityConfigError {
		t.Error("sibling route config_error must survive")
	}
	if got[capKey{model.RecipeScopeUpstream, up.ID, model.EndpointModels}] != model.CapabilityConfigError {
		t.Error("route re-enable must not clear upstream-scoped Capability")
	}

	// A non-Enabled edit on an already enabled route leaves stored rows alone.
	insertScopedCapability(t, st, model.RecipeScopeRoute, target.ID, messages.ID, model.EndpointMessages, model.CapabilityConfigError)
	current, err := st.GetRoute(target.ID)
	if err != nil {
		t.Fatal(err)
	}
	current.Priority++
	if err := st.UpdateRouteWithRevision(context.Background(), current, current.Revision); err != nil {
		t.Fatal(err)
	}
	if storedCapStates(t, st)[capKey{model.RecipeScopeRoute, target.ID, model.EndpointMessages}] != model.CapabilityConfigError {
		t.Error("priority edit must not clear stored config_error")
	}
}

func TestUpstreamReEnableDeletesStoredConfigError(t *testing.T) {
	st := testStore(t)
	mn := mkModelName(t, st, "reen-up", model.ProtoAnthropic)
	upA := mkUpstream(t, st, "reen-a")
	upB := mkUpstream(t, st, "reen-b")
	routeOf := func(up *model.Upstream) *model.Route {
		r := &model.Route{ModelNameID: mn.ID, UpstreamID: up.ID, Enabled: true}
		if err := st.CreateRoute(r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	routeA, routeB := routeOf(upA), routeOf(upB)
	for _, pair := range []struct {
		up *model.Upstream
		rt *model.Route
	}{{upA, routeA}, {upB, routeB}} {
		insertScopedCapability(t, st, model.RecipeScopeUpstream, pair.up.ID,
			endpointOf(t, st, pair.up.ID, model.EndpointModels).ID, model.EndpointModels, model.CapabilityConfigError)
		insertScopedCapability(t, st, model.RecipeScopeRoute, pair.rt.ID,
			endpointOf(t, st, pair.up.ID, model.EndpointMessages).ID, model.EndpointMessages, model.CapabilityConfigError)
	}

	setUpstreamEnabled(t, st, upA.ID, false)
	if got := len(storedCapStates(t, st)); got != 4 {
		t.Fatalf("disable must not touch stored Capability: %d rows, want 4", got)
	}
	setUpstreamEnabled(t, st, upA.ID, true)

	got := storedCapStates(t, st)
	if _, ok := got[capKey{model.RecipeScopeUpstream, upA.ID, model.EndpointModels}]; ok {
		t.Error("re-enabled upstream-scoped config_error survived")
	}
	if _, ok := got[capKey{model.RecipeScopeRoute, routeA.ID, model.EndpointMessages}]; ok {
		t.Error("re-enabled upstream child route config_error survived")
	}
	if got[capKey{model.RecipeScopeUpstream, upB.ID, model.EndpointModels}] != model.CapabilityConfigError {
		t.Error("sibling upstream config_error must survive")
	}
	if got[capKey{model.RecipeScopeRoute, routeB.ID, model.EndpointMessages}] != model.CapabilityConfigError {
		t.Error("sibling upstream child route config_error must survive")
	}
}
