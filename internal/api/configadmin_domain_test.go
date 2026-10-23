package api

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/transform"
)

func explicitEndpointUpstream(t *testing.T, h http.Handler) int64 {
	t.Helper()
	var input map[string]any
	if err := json.Unmarshal([]byte(upstreamFixture(t, `{"name":"explicit-domain","base_url":"https://explicit.example.test","api_key":"temporary-domain-upstream-fixture"}`)), &input); err != nil {
		t.Fatal(err)
	}
	ep := input["initial_endpoints"].([]any)[0].(map[string]any)
	ep["url_override"] = "https://explicit.example.test/custom-models"
	ep["auth_profile"] = map[string]any{"mode": "x_api_key", "secret_ref": "upstream_api_key"}
	body, _ := json.Marshal(input)
	response := do(t, h, "POST", "/admin/api/upstreams", string(body), true)
	if response.Code != http.StatusCreated {
		t.Fatalf("setup explicit Endpoint bundle: HTTP %d", response.Code)
	}
	return int64(decodeBody[map[string]any](t, response)["id"].(float64))
}

func TestConfigAdminHTTP_UpstreamEditCannotOverwriteExplicitEndpoints(t *testing.T) {
	for _, change := range []string{"base_url", "auth_style", "l1_path", "full_url_mode", "probe_headers", "cross-origin"} {
		t.Run(change, func(t *testing.T) {
			s, h := newTestServer(t)
			id := explicitEndpointUpstream(t, h)
			before, err := s.st.ListEndpointsPage(context.Background(), model.EndpointFilter{UpstreamID: id})
			if err != nil {
				t.Fatal(err)
			}
			input := map[string]any{"expected_revision": 1}
			switch change {
			case "base_url":
				input["base_url"] = "https://explicit.example.test/"
			case "cross-origin":
				input["base_url"] = "https://different.example.test"
			case "auth_style":
				input["auth_style"] = "bearer"
			case "l1_path":
				input["l1_path"] = "/old-global-models"
			case "full_url_mode":
				input["full_url_mode"] = true
			case "probe_headers":
				input["probe_headers"] = map[string]string{"User-Agent": "old-global-probe"}
			}
			body, _ := json.Marshal(input)
			response := do(t, h, "PUT", "/admin/api/upstreams/"+itoa(id), string(body), true)
			want := http.StatusBadRequest
			if change == "base_url" {
				want = http.StatusOK
			}
			if response.Code != want {
				t.Errorf("%s update HTTP %d, want %d", change, response.Code, want)
			}
			after, err := s.st.ListEndpointsPage(context.Background(), model.EndpointFilter{UpstreamID: id})
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Error("upstream edit mutated explicit Endpoint URL/Auth/configuration versions")
			}
			if want != http.StatusOK {
				up, err := s.st.GetUpstream(id)
				if err != nil || up.Revision != 1 {
					t.Error("rejected update changed parent revision")
				}
			}
		})
	}
}

func TestConfigAdminHTTP_ImmutableHistoryDeleteRejectsBeforePublishing(t *testing.T) {
	s, h := newTestServer(t)
	id := explicitEndpointUpstream(t, h)
	recipeID, err := s.st.CreateRecipe(model.RecipeScopeUpstream, id, model.EndpointModels)
	if err != nil {
		t.Fatal(err)
	}
	version := &model.ProbeRecipeVersion{RecipeID: recipeID, Origin: model.RecipeManual, Method: "GET", TimeoutProfile: model.TimeoutL1}
	if err := s.st.AddRecipeVersion(version, 1); err != nil {
		t.Fatal(err)
	}
	pub := &recordingPublisher{}
	s.WithConfigPublisher(pub)
	response := do(t, h, "DELETE", "/admin/api/upstreams/"+itoa(id)+"?expected_revision=1", "", true)
	if response.Code != http.StatusConflict {
		t.Fatalf("history delete returned HTTP %d", response.Code)
	}
	if inv, ref := pub.counts(); inv != 0 || ref != 0 {
		t.Fatal("rejected history delete published runtime configuration")
	}
	recipe, err := s.st.GetRecipe(context.Background(), recipeID)
	if err != nil || recipe.ScopeID != id || recipe.Status != model.RecipeDraft || recipe.Revision != 2 {
		t.Fatal("refused delete changed immutable recipe ownership/status")
	}
}

func TestConfigAdminHTTP_UpdateValidationNeverEchoesCurrentOrSubmittedAPIKey(t *testing.T) {
	for _, source := range []string{"submitted", "current"} {
		t.Run(source, func(t *testing.T) {
			s, h := newTestServer(t)
			id := explicitEndpointUpstream(t, h)
			before, err := s.st.GetUpstream(id)
			if err != nil {
				t.Fatal(err)
			}
			secret := before.APIKey
			input := map[string]any{"expected_revision": 1}
			if source == "submitted" {
				secret = "temporary-private-submitted-update-key"
				input["api_key"] = secret
			}
			input["base_url"] = "invalid-scheme://" + secret
			body, _ := json.Marshal(input)
			response := do(t, h, "PUT", "/admin/api/upstreams/"+itoa(id), string(body), true)
			if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), secret) {
				t.Errorf("update validation exposed %s API key or accepted invalid URL", source)
			}
			after, err := s.st.GetUpstream(id)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Error("refused update changed persisted Upstream")
			}
		})
	}
}

func TestConfigAdminHTTP_DeleteSQLFailureRestoresTransformAndEmptyDraft(t *testing.T) {
	s, _ := newTestServer(t)
	seedConfig(t, s, 1, 1)
	registry := transform.NewRegistry(20).WithPersist(s.st)
	pub := &recordingPublisher{}
	h := s.WithTransformRegistry(registry).WithConfigPublisher(pub).Routes(testAdminPW)
	h = freshTransformFixtureHandler(t, registry, h)
	response := do(t, h, "POST", "/admin/api/transforms", `{"name":"rollback-current-binding"}`, true)
	if response.Code != http.StatusCreated {
		t.Fatal("cannot create Transform fixture")
	}
	setID := int64(decodeBody[map[string]any](t, response)["id"].(float64))
	if response := do(t, h, "PUT", "/admin/api/transforms/"+itoa(setID)+"/draft", `{"rules":[{"kind":"replace_bytes","from":"OLD","to":"NEW"}]}`, true); response.Code != http.StatusOK {
		t.Fatal("cannot create Transform draft fixture")
	}
	if response := do(t, h, "POST", "/admin/api/transforms/"+itoa(setID)+"/publish", `{"route_id":1,"endpoint_id":1}`, true); response.Code != http.StatusOK {
		t.Fatal("cannot publish Transform fixture")
	}
	recipeID, err := s.st.CreateRecipe(model.RecipeScopeRoute, 1, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	forceTableDeleteFail(t, s, "route")
	beforeInv, beforeRef := pub.counts()
	response = do(t, h, "DELETE", "/admin/api/routes/1?expected_revision=1", "", true)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("SQL failure not reported: HTTP %d", response.Code)
	}
	if compiled, _, err := registry.PublishedCompiled(1, 1); err != nil || compiled == nil {
		t.Error("failed SQL delete lost the in-memory Transform binding")
	}
	var bindings int
	if err := s.st.DB().QueryRow(`SELECT COUNT(*) FROM transform_binding WHERE route_id=1`).Scan(&bindings); err != nil || bindings != 1 {
		t.Error("failed SQL delete lost the persisted Transform binding")
	}
	if recipe, err := s.st.GetRecipe(context.Background(), recipeID); err != nil || recipe.Status != model.RecipeDraft || recipe.Revision != 1 {
		t.Error("failed SQL delete did not restore the empty current draft")
	}
	if inv, ref := pub.counts(); inv != beforeInv || ref != beforeRef {
		t.Error("failed SQL delete published configuration")
	}
}

func TestConfigAdminHTTP_RealSnapshotReadFailureRecoversCommittedRevision(t *testing.T) {
	s, h, source, _ := newLivecfgServer(t)
	seedConfig(t, s, 1, 1)
	warm, err := source.Snapshot()
	if err != nil || len(warm.RoutesByModelName[1]) != 1 {
		t.Fatal("cannot warm real routing snapshot")
	}
	// Break a read that belongs only to ConfigBundle publication. The Route
	// mutation still commits successfully; no fake publisher reports success.
	if _, err := s.st.DB().Exec(`ALTER TABLE client_probe_profile RENAME TO audit_unavailable_profiles`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.st.DB().Exec(`ALTER TABLE audit_unavailable_profiles RENAME TO client_probe_profile`) })
	response := do(t, h, "PUT", "/admin/api/routes/1", `{"expected_revision":1,"priority":8}`, true)
	var state struct {
		Persisted bool   `json:"persisted"`
		Revision  int64  `json:"revision"`
		Code      string `json:"code"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusServiceUnavailable || !state.Persisted || state.Revision != 2 || state.Code != "config_activation_pending" {
		t.Fatalf("real snapshot failure did not report committed revision: HTTP %d", response.Code)
	}
	if _, err := source.ProbeSnapshot(); err == nil {
		t.Error("failed publication left a probe snapshot eligible for sending")
	}
	if _, err := s.st.DB().Exec(`ALTER TABLE audit_unavailable_profiles RENAME TO client_probe_profile`); err != nil {
		t.Fatal(err)
	}
	refreshed, err := source.Snapshot()
	if err != nil || len(refreshed.RoutesByModelName[1]) != 1 || refreshed.RoutesByModelName[1][0].Priority != 8 {
		t.Fatal("real snapshot did not recover the committed mutation after storage repair")
	}
	response = do(t, h, "PUT", "/admin/api/routes/1", `{"expected_revision":2,"priority":8}`, true)
	if response.Code != http.StatusOK {
		t.Fatalf("retry with confirmed revision did not activate configuration: HTTP %d", response.Code)
	}
	row, err := s.st.GetRoute(1)
	if err != nil || row.Revision != 2 {
		t.Error("activation recovery repeated the already committed mutation")
	}
}
