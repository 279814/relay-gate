package store

import (
	"context"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestModelNameReEnableClearsOnlyItsChildConfigErrors(t *testing.T) {
	st := testStore(t)
	target := mkModelName(t, st, "reenable-model", model.ProtoAnthropic)
	sibling := mkModelName(t, st, "reenable-other-model", model.ProtoAnthropic)
	upA := mkUpstream(t, st, "reenable-model-a")
	upB := mkUpstream(t, st, "reenable-model-b")
	var children []*model.Route
	for _, pair := range []struct {
		mn *model.ModelName
		up *model.Upstream
	}{{target, upA}, {target, upB}, {sibling, upA}} {
		route := &model.Route{ModelNameID: pair.mn.ID, UpstreamID: pair.up.ID, Enabled: true}
		if err := st.CreateRoute(route); err != nil {
			t.Fatal(err)
		}
		children = append(children, route)
		for _, endpoint := range []model.EndpointKind{model.EndpointMessages, model.EndpointCountTokens} {
			insertScopedCapability(t, st, model.RecipeScopeRoute, route.ID,
				endpointOf(t, st, pair.up.ID, endpoint).ID, endpoint, model.CapabilityConfigError)
		}
	}
	insertScopedCapability(t, st, model.RecipeScopeUpstream, upA.ID,
		endpointOf(t, st, upA.ID, model.EndpointModels).ID, model.EndpointModels, model.CapabilityConfigError)
	before := target.CapabilityRevision
	target.Enabled = false
	if err := st.UpdateModelNameWithRevision(context.Background(), target, target.Revision); err != nil {
		t.Fatal(err)
	}
	if len(storedCapStates(t, st)) != 7 || target.CapabilityRevision != before {
		t.Fatal("disabling must preserve prior evidence and semantic revision")
	}
	target.Enabled = true
	if err := st.UpdateModelNameWithRevision(context.Background(), target, target.Revision); err != nil {
		t.Fatal(err)
	}
	if target.CapabilityRevision != before+1 {
		t.Errorf("re-enable revision=%d want %d", target.CapabilityRevision, before+1)
	}
	states := storedCapStates(t, st)
	for _, route := range children[:2] {
		for _, endpoint := range []model.EndpointKind{model.EndpointMessages, model.EndpointCountTokens} {
			if state, exists := states[capKey{model.RecipeScopeRoute, route.ID, endpoint}]; exists {
				t.Errorf("re-enabled model retained child %d %s: %s", route.ID, endpoint, state)
			}
		}
	}
	if len(states) != 3 || states[capKey{model.RecipeScopeRoute, children[2].ID, model.EndpointMessages}] != model.CapabilityConfigError ||
		states[capKey{model.RecipeScopeUpstream, upA.ID, model.EndpointModels}] != model.CapabilityConfigError {
		t.Fatalf("model re-enable changed sibling/upstream evidence: %+v", states)
	}
}

func TestModelNameMatchEditPreservesCapabilityEvidence(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "model-match-edit")
	mn := mkModelName(t, st, "model-prefix", model.ProtoAnthropic)
	route := &model.Route{ModelNameID: mn.ID, UpstreamID: up.ID, Enabled: true}
	if err := st.CreateRoute(route); err != nil {
		t.Fatal(err)
	}
	insertScopedCapability(t, st, model.RecipeScopeRoute, route.ID,
		endpointOf(t, st, up.ID, model.EndpointMessages).ID, model.EndpointMessages, model.CapabilityConfigError)
	mn.MatchMode = model.MatchPrefix
	if err := st.UpdateModelNameWithRevision(context.Background(), mn, mn.Revision); err != nil {
		t.Fatal(err)
	}
	if mn.CapabilityRevision != 1 || storedCapStates(t, st)[capKey{model.RecipeScopeRoute, route.ID, model.EndpointMessages}] != model.CapabilityConfigError {
		t.Fatal("matching-only edit invalidated model health")
	}
}
