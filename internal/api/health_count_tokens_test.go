package api

import (
	"net/http"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

// stubCountTokensView 按 Route ID 返回 count_tokens Capability，并记下被问到的 scope/endpoint。
type stubCountTokensView struct {
	states map[int64]model.CapabilityState
	scopes map[model.RecipeScope]int
	eps    map[model.EndpointKind]int
}

func (v *stubCountTokensView) Effective(scope model.RecipeScope, scopeID int64,
	endpoint model.EndpointKind, _ string) model.CapabilityState {
	v.scopes[scope]++
	v.eps[endpoint]++
	if st, ok := v.states[scopeID]; ok {
		return st
	}
	return model.CapabilityUnknown
}

func healthRowsByRoute(t *testing.T, h http.Handler) map[int64]map[string]any {
	t.Helper()
	rec := do(t, h, "GET", "/admin/api/health", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("/health: %d %s", rec.Code, rec.Body.String())
	}
	body := decodeBody[map[string]any](t, rec)
	out := map[int64]map[string]any{}
	for _, raw := range body["routes"].([]any) {
		row := raw.(map[string]any)
		out[int64(row["route_id"].(float64))] = row
	}
	return out
}

func TestGetHealth_CountTokensPerRoute(t *testing.T) {
	s, _ := newTestServer(t)
	seedConfig(t, s, 2, 2)
	routes, err := s.st.ListRoutes(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 4 {
		t.Fatalf("want 4 routes, got %d", len(routes))
	}
	want := map[int64]model.CapabilityState{
		routes[0].ID: model.CapabilitySupported,
		routes[1].ID: model.CapabilityUnsupported,
		routes[2].ID: model.CapabilityConfigError,
	}
	view := &stubCountTokensView{
		states: want,
		scopes: map[model.RecipeScope]int{},
		eps:    map[model.EndpointKind]int{},
	}
	h := s.WithHealth(stubHealth{}, nil, nil).WithCountTokensView(view).Routes(testAdminPW)

	rows := healthRowsByRoute(t, h)
	for _, rt := range routes {
		exp := want[rt.ID]
		if exp == "" {
			exp = model.CapabilityUnknown
		}
		if got := rows[rt.ID]["count_tokens"]; got != string(exp) {
			t.Errorf("route %d count_tokens=%v, want %s", rt.ID, got, exp)
		}
	}
	if view.scopes[model.RecipeScopeRoute] != len(routes) || len(view.scopes) != 1 {
		t.Errorf("must read route-scope capability only: %v", view.scopes)
	}
	if view.eps[model.EndpointCountTokens] != len(routes) || len(view.eps) != 1 {
		t.Errorf("must read count_tokens endpoint only: %v", view.eps)
	}
}

func TestGetHealth_CountTokensOmittedWithoutView(t *testing.T) {
	s, _ := newTestServer(t)
	h := withHealthView(t, s)
	seedConfig(t, s, 1, 1)

	for id, row := range healthRowsByRoute(t, h) {
		if v, ok := row["count_tokens"]; ok {
			t.Errorf("route %d: count_tokens must be omitted when view is not wired, got %v", id, v)
		}
	}
}
