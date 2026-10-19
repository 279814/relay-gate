package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/observationseq"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/probe"
	"github.com/279814/relay-gate/internal/probetemplate"
	"github.com/279814/relay-gate/internal/store"
)

func TestRecipeVersionHTTPUsesRevisionAndRestoresAfterRefresh(t *testing.T) {
	s, _ := newTestServer(t)
	up := &model.Upstream{Name: "recipe-local", BaseURL: "https://recipe.example.invalid", APIKey: "fixture-api-key-long-enough", Enabled: true}
	if err := s.st.CreateUpstream(up); err != nil {
		t.Fatal(err)
	}
	admin := probe.NewService(s.st, nil, nil, livecfg.New(s.st, s.log), nil, nil)
	h := s.WithProbeAdmin(admin).Routes(testAdminPW)
	created := do(t, h, "POST", "/admin/api/probe-recipes", fmt.Sprintf(`{"scope":"upstream","scope_id":%d,"endpoint":"models"}`, up.ID), true)
	if created.Code != http.StatusCreated {
		t.Fatal(created.Body.String())
	}
	recipe := decodeBody[model.ProbeRecipe](t, created)
	path := fmt.Sprintf("/admin/api/probe-recipes/%d/versions", recipe.ID)
	body := fmt.Sprintf(`{"expected_revision":%d,"method":"GET","headers":[],"timeout_profile":"l1"}`, recipe.Revision)
	response := do(t, h, "POST", path, body, true)
	if response.Code != http.StatusCreated {
		t.Fatalf("add immutable version: got %d %s", response.Code, response.Body.String())
	}
	for _, bad := range []string{body, `{"method":"GET","timeout_profile":"l1"}`} {
		result := do(t, h, "POST", path, bad, true)
		if result.Code != 409 && result.Code != 400 {
			t.Fatalf("missing/stale revision accepted: %d %s", result.Code, result.Body.String())
		}
	}
	versions := do(t, h, "GET", path+"?limit=1", "", true)
	if versions.Code != 200 {
		t.Fatalf("reload immutable versions: %d %s", versions.Code, versions.Body.String())
	}
	var page struct {
		Items []map[string]any `json:"items"`
		Next  string           `json:"next_cursor"`
	}
	page = decodeBody[struct {
		Items []map[string]any `json:"items"`
		Next  string           `json:"next_cursor"`
	}](t, versions)
	if len(page.Items) != 1 || page.Items[0]["origin"] != "manual" {
		t.Fatalf("manual provenance lost after reload: %+v", page)
	}
}

func recipeHTTPFixture(t *testing.T) (*Server, http.Handler, *livecfg.Source, *probe.SyntheticCoordinator, *atomic.Int32, int64, *model.ProbeRecipeVersion, *model.Route) {
	t.Helper()
	s, _ := newTestServer(t)
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("X-Fixture-Outcome") == "reject" || r.Header.Get("User-Agent") == "claude-cli/2.1.0" {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":{"type":"invalid_request_error","message":"fixture shape rejected"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}]}`))
	}))
	t.Cleanup(upstream.Close)
	up := &model.Upstream{Name: "real-recipe-test", BaseURL: upstream.URL, APIKey: "fixture-api-key-local-test", Enabled: true}
	if err := s.st.CreateUpstream(up); err != nil {
		t.Fatal(err)
	}
	mn := &model.ModelName{Name: "test-model", Protocol: model.ProtoOpenAIChat, Enabled: true}
	if err := s.st.CreateModelName(mn); err != nil {
		t.Fatal(err)
	}
	route := &model.Route{UpstreamID: up.ID, ModelNameID: mn.ID, Enabled: true}
	if err := s.st.CreateRoute(route); err != nil {
		t.Fatal(err)
	}
	ep, err := s.st.Endpoint(context.Background(), up.ID, model.EndpointChatCompletions)
	if err != nil {
		t.Fatal(err)
	}
	ep.AuthProfile = model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: "upstream_api_key", Revision: ep.AuthProfile.Revision}
	ep.LegacyCompatRealOnly = false
	if err := s.st.UpdateEndpoint(ep, ep.Revision); err != nil {
		t.Fatal(err)
	}
	recipeID, err := s.st.CreateRecipe(model.RecipeScopeRoute, route.ID, model.EndpointChatCompletions)
	if err != nil {
		t.Fatal(err)
	}
	version := &model.ProbeRecipeVersion{RecipeID: recipeID, Origin: model.RecipeManual, Method: "POST", Body: []byte(`{"model":"{{UPSTREAM_MODEL}}","max_tokens":1,"messages":[{"role":"user","content":"{{PROBE_PROMPT}}"}]}`), BodyIsText: true, TimeoutProfile: model.TimeoutL2Standard}
	if err := s.st.AddRecipeVersion(version, 1); err != nil {
		t.Fatal(err)
	}
	source := livecfg.New(s.st, s.log)
	if err := source.Refresh(); err != nil {
		t.Fatal(err)
	}
	cipher, _ := store.NewCipher("test-passphrase-at-least-16-chars")
	targets := outbound.NewProvider(source, s.st, outbound.NewResolver(cipher))
	transports := outbound.NewManager()
	t.Cleanup(transports.CloseIdleConnections)
	recipes := probe.NewRecipeResolver(s.st).WithNotFound(func(err error) bool { return errors.Is(err, store.ErrNotFound) })
	coordinator := probe.NewSyntheticCoordinator(model.RunStateRunning)
	t.Cleanup(coordinator.Close)
	executor := probe.NewExecutor(targets, s.st, recipes, probe.ManagerTransports{Manager: transports}, probe.NewResultRecorder(s.st, health.NewObservationReducer(nil), nil, nil), coordinator, nil, s.log)
	seq, err := observationseq.Open(context.Background(), s.st)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(seq.Close)
	scheduler := probe.NewScheduler(source, nil, nil, s.log).WithSequencer(seq).WithRecipes(recipes)
	admin := probe.NewService(s.st, executor, nil, source, nil, nil).WithManualPreparer(scheduler)
	h := s.WithProbeAdmin(admin).Routes(testAdminPW)
	return s, h, source, coordinator, &calls, recipeID, version, route
}

func TestRecipeHTTPTestAndPublishAreSeparateRealExecutions(t *testing.T) {
	s, h, _, coordinator, calls, recipeID, version, route := recipeHTTPFixture(t)
	path := fmt.Sprintf("/admin/api/probe-recipes/%d/versions/%d", recipeID, version.ID)
	versionPath := fmt.Sprintf("/admin/api/probe-recipe-versions/%d", version.ID)
	body := fmt.Sprintf(`{"expected_revision":2,"route_id":%d}`, route.ID)
	response := do(t, h, "POST", versionPath+"/test", body, true)
	if response.Code != 200 {
		t.Fatalf("explicit single test missing: %d %s", response.Code, response.Body.String())
	}
	execution := decodeBody[model.ProbeExecution](t, response)
	if execution.ProbeSecretRevisionsHash == "" {
		t.Fatal("explicit test omitted Secret revision-set diagnostic hash")
	}
	if !execution.Success || execution.RecipeBindingUse != model.BindingExplicitTest || calls.Load() != 1 || execution.CapabilityToken == "" {
		t.Fatalf("wrong explicit test evidence/call count: %+v calls=%d", execution, calls.Load())
	}
	fresh, err := s.st.GetRecipe(context.Background(), recipeID)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.PublishedVersionID != 0 {
		t.Fatal("test implicitly published")
	}
	for _, body := range []string{`{"expected_revision":2}`, fmt.Sprintf(`{"expected_revision":2,"test_execution_id":%q,"force":true}`, execution.ID)} {
		if rec := do(t, h, "POST", path+"/publish", body, true); rec.Code != 400 {
			t.Fatalf("untested/success-force publish accepted: %d %s", rec.Code, rec.Body.String())
		}
	}
	published := do(t, h, "POST", path+"/publish", fmt.Sprintf(`{"expected_revision":2,"test_execution_id":%q}`, execution.ID), true)
	if published.Code != 200 {
		t.Fatalf("publish tested version: %d %s", published.Code, published.Body.String())
	}
	latestAudit(t, s, "recipe_publish", "succeeded")
	if calls.Load() != 1 {
		t.Fatal("publish sent another probe")
	}
	coordinator.CloseAdmission()
	paused := do(t, h, "POST", versionPath+"/test", fmt.Sprintf(`{"expected_revision":3,"route_id":%d}`, route.ID), true)
	if paused.Code != 503 || calls.Load() != 1 {
		t.Fatalf("paused test was not rejected with zero sends: %d %s", paused.Code, paused.Body.String())
	}
	latestAudit(t, s, "recipe_test", "failed")
}

func TestClientProfileHTTPTestsExactCandidateAndEnablesOnlySuccess(t *testing.T) {
	s, h, source, _, calls, _, _, route := recipeHTTPFixture(t)
	profile := &model.ClientProbeProfile{UpstreamID: route.UpstreamID, Endpoint: model.EndpointChatCompletions, ClientFamily: "generic", ShapeHash: "fixture-only-profile-shape", SeenCount: 1}
	if err := s.st.CreateClientProfileCandidate(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	source.Invalidate()
	if err := source.Refresh(); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/admin/api/client-probe-profiles/%d", profile.ID)
	read := do(t, h, "GET", path, "", true)
	if read.Code != 200 {
		t.Fatalf("profile detail missing: %d %s", read.Code, read.Body.String())
	}
	tested := do(t, h, "POST", path+"/test", fmt.Sprintf(`{"expected_revision":%d,"route_id":%d}`, profile.Revision, route.ID), true)
	if tested.Code != 200 {
		t.Fatalf("profile exact test/enable missing: %d %s", tested.Code, tested.Body.String())
	}
	execution := decodeBody[model.ProbeExecution](t, tested)
	if !execution.Success || execution.ClientProfileID != profile.ID || execution.RecipeBindingUse != model.BindingExplicitProfileTest || calls.Load() != 1 {
		t.Fatalf("wrong profile test evidence: %+v calls=%d", execution, calls.Load())
	}
	current, err := s.st.GetClientProfile(context.Background(), profile.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Status != model.ProfileTested || current.Revision != profile.Revision+1 {
		t.Fatalf("successful candidate not atomically enabled: %+v", current)
	}
	latestAudit(t, s, "profile_test_activate", "succeeded")
	stale := do(t, h, "POST", path+"/disable", fmt.Sprintf(`{"expected_revision":%d}`, profile.Revision), true)
	if stale.Code != 409 {
		t.Fatalf("profile stale disable=%d %s", stale.Code, stale.Body.String())
	}
	latestAudit(t, s, "profile_disable", "failed")
	disabled := do(t, h, "POST", path+"/disable", fmt.Sprintf(`{"expected_revision":%d}`, current.Revision), true)
	if disabled.Code != 200 {
		t.Fatalf("profile disable=%d %s", disabled.Code, disabled.Body.String())
	}
	latestAudit(t, s, "profile_disable", "succeeded")
	if calls.Load() != 1 {
		t.Fatal("disable emitted another request")
	}
}

type previewOnlyStore struct{ *store.Store }

func (previewOnlyStore) GetUpstream(int64) (*model.Upstream, error) {
	return nil, errors.New("preview attempted to load plaintext API key")
}
func (previewOnlyStore) ResolveProbeSecret(context.Context, string) (probetemplate.ResolvedSecret, error) {
	return probetemplate.ResolvedSecret{}, errors.New("preview attempted to resolve plaintext Probe Secret")
}

type previewOnlySource struct{ *livecfg.Source }

func (previewOnlySource) ProbeSnapshot() (*livecfg.ProbeSnapshot, error) {
	return nil, errors.New("preview attempted a credential-loading TTL refresh")
}

func TestRecipePreviewIsSecretIndependentAndUsesDeclaredTokenCeiling(t *testing.T) {
	s, _ := newTestServer(t)
	up := &model.Upstream{Name: "preview-local", BaseURL: "https://preview.example.invalid", APIKey: "fixture-api-key-never-in-preview", Enabled: true}
	if err := s.st.CreateUpstream(up); err != nil {
		t.Fatal(err)
	}
	mn := &model.ModelName{Name: "preview-model", Protocol: model.ProtoOpenAIChat, Enabled: true, ProbeMaxTokens: 1}
	if err := s.st.CreateModelName(mn); err != nil {
		t.Fatal(err)
	}
	route := &model.Route{UpstreamID: up.ID, ModelNameID: mn.ID, Enabled: true}
	if err := s.st.CreateRoute(route); err != nil {
		t.Fatal(err)
	}
	ep, err := s.st.Endpoint(context.Background(), up.ID, model.EndpointChatCompletions)
	if err != nil {
		t.Fatal(err)
	}
	ep.AuthProfile = model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: "upstream_api_key", Revision: ep.AuthProfile.Revision}
	ep.LegacyCompatRealOnly = false
	if err := s.st.UpdateEndpoint(ep, ep.Revision); err != nil {
		t.Fatal(err)
	}
	secret, err := s.st.CreateProbeSecret("preview-secret", []byte("tiny-secret-one"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.st.CreateRecipe(model.RecipeScopeUpstream, up.ID, model.EndpointChatCompletions)
	if err != nil {
		t.Fatal(err)
	}
	version := &model.ProbeRecipeVersion{RecipeID: id, Origin: model.RecipeManual, Method: "POST", FixedRawQuery: "token={{SECRET:preview-secret}}", Headers: []model.HeaderTemplate{{Name: "X-Probe-Secret", Values: []string{"{{SECRET:preview-secret}}"}}}, Body: []byte(`{"model":"{{UPSTREAM_MODEL}}","max_tokens":512,"messages":[{"role":"user","content":"{{SECRET:preview-secret}}"}]}`), BodyIsText: true, TimeoutProfile: model.TimeoutL2Standard}
	if err := s.st.AddRecipeVersion(version, 1); err != nil {
		t.Fatal(err)
	}
	source := livecfg.New(s.st, s.log)
	if err := source.Refresh(); err != nil {
		t.Fatal(err)
	}
	h := s.WithProbeAdmin(probe.NewService(previewOnlyStore{s.st}, nil, nil, previewOnlySource{source}, nil, nil)).Routes(testAdminPW)
	path := fmt.Sprintf("/admin/api/probe-recipe-versions/%d/preview", version.ID)
	body := fmt.Sprintf(`{"route_id":%d}`, route.ID)
	first := do(t, h, "POST", path, body, true)
	if first.Code != 200 {
		_, domainErr := s.probeAdmin.Preview(context.Background(), version.ID, probe.PreviewInput{RouteID: route.ID})
		t.Fatalf("safe preview missing: %d %s (domain: %v)", first.Code, first.Body.String(), domainErr)
	}
	if _, err := s.st.UpdateProbeSecret(secret.ID, secret.Revision, []byte("much-much-longer-secret-two-never-returned")); err != nil {
		t.Fatal(err)
	}
	source.Invalidate()
	if err := source.Refresh(); err != nil {
		t.Fatal(err)
	}
	second := do(t, h, "POST", path, body, true)
	if second.Code != 200 {
		t.Fatalf("repeat preview: %d %s", second.Code, second.Body.String())
	}
	if first.Body.String() != second.Body.String() {
		t.Fatalf("Secret value/revision changed redacted preview: %s / %s", first.Body.String(), second.Body.String())
	}
	var preview struct {
		OutputLimit int    `json:"output_token_upper_bound"`
		Bytes       int    `json:"redacted_template_body_bytes"`
		Hash        string `json:"redacted_template_hash"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	if preview.OutputLimit < 512 || preview.Bytes == 0 || preview.Hash == "" {
		t.Fatalf("preview underestimated configured template: %+v", preview)
	}
	if _, err := s.st.GetRecipe(context.Background(), id); err != nil {
		t.Fatal(err)
	}
}

func TestClientProfileHTTPCollectionRequiresAdminAndReturnsPage(t *testing.T) {
	s, _ := newTestServer(t)
	h := s.WithProbeAdmin(probe.NewService(s.st, nil, nil, nil, nil, nil)).Routes(testAdminPW)
	if response := do(t, h, "GET", "/admin/api/client-probe-profiles", "", false); response.Code != 401 {
		t.Fatalf("profile auth=%d", response.Code)
	}
	response := do(t, h, "GET", "/admin/api/client-probe-profiles?limit=1", "", true)
	if response.Code != 200 {
		t.Fatalf("profile collection missing: %d %s", response.Code, response.Body.String())
	}
}

type recipePendingSource struct{ *livecfg.Source }

func (s recipePendingSource) Refresh() error { return errors.New("injected activation failure") }

func TestRecipeHTTPCommitPendingReportsPersistedRevision(t *testing.T) {
	s, _ := newTestServer(t)
	up := &model.Upstream{Name: "pending-recipe", BaseURL: "https://pending.example.invalid", APIKey: "fixture-pending-key", Enabled: true}
	if err := s.st.CreateUpstream(up); err != nil {
		t.Fatal(err)
	}
	source := livecfg.New(s.st, s.log)
	if err := source.Refresh(); err != nil {
		t.Fatal(err)
	}
	h := s.WithProbeAdmin(probe.NewService(s.st, nil, nil, recipePendingSource{source}, nil, nil)).Routes(testAdminPW)
	response := do(t, h, "POST", "/admin/api/probe-recipes", fmt.Sprintf(`{"scope":"upstream","scope_id":%d,"endpoint":"models"}`, up.ID), true)
	if response.Code != 503 {
		t.Fatalf("committed configuration reported as internal failure: %d %s", response.Code, response.Body.String())
	}
	var body struct {
		Persisted    bool   `json:"persisted"`
		Code         string `json:"code"`
		ID, Revision int64
		NewRevision  int64 `json:"new_revision"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Persisted || body.Code != "config_activation_pending" || body.ID < 1 || body.NewRevision < 1 {
		t.Fatalf("missing committed identity: %s", response.Body.String())
	}
	if _, err := s.st.GetRecipe(context.Background(), body.ID); err != nil {
		t.Fatal("persisted=true without SQL commit")
	}
}

func TestRecipeAndProfileListsHonorFiltersAndRejectMalformedPagination(t *testing.T) {
	s, h, _, _, _, _, version, route := recipeHTTPFixture(t)
	if _, err := s.st.CreateRecipe(model.RecipeScopeUpstream, route.UpstreamID, model.EndpointModels); err != nil {
		t.Fatal(err)
	}
	filtered := do(t, h, "GET", "/admin/api/probe-recipes?endpoint=models&limit=1", "", true)
	if filtered.Code != 200 {
		t.Fatalf("filter=%d %s", filtered.Code, filtered.Body.String())
	}
	page := decodeBody[model.Page[model.ProbeRecipe]](t, filtered)
	if len(page.Items) != 1 || page.Items[0].Endpoint != model.EndpointModels {
		t.Fatalf("server ignored endpoint filter: %+v", page)
	}
	first := do(t, h, "GET", "/admin/api/probe-recipes?limit=1", "", true)
	cursor := decodeBody[model.Page[model.ProbeRecipe]](t, first).NextCursor
	if cursor == "" {
		t.Fatal("first page lacked cursor")
	}
	bad := []string{"/admin/api/probe-recipes?limit=oops", "/admin/api/probe-recipes?limit=-1", "/admin/api/probe-recipes?upstream_id=bad", "/admin/api/probe-recipes?cursor=bad", "/admin/api/probe-recipes?endpoint=models&cursor=" + cursor, "/admin/api/client-probe-profiles?limit=nope", "/admin/api/client-probe-profiles?cursor=" + cursor, fmt.Sprintf("/admin/api/probe-recipes/%d/versions?limit=nope", version.RecipeID)}
	for _, path := range bad {
		response := do(t, h, "GET", path, "", true)
		if response.Code != 400 {
			t.Errorf("malformed/filter-crossed list accepted at %s: %d %s", path, response.Code, response.Body.String())
		}
	}
}

func TestRecipeHTTPForceRequiresAnActualFailedExplicitTest(t *testing.T) {
	s, h, _, _, calls, recipeID, version, route := recipeHTTPFixture(t)
	failedVersion, err := s.probeAdmin.AddVersion(context.Background(), recipeID, 2, probe.RecipeVersionMutation{Method: version.Method, Body: version.Body, BodyIsText: true, TimeoutProfile: version.TimeoutProfile, Headers: []model.HeaderTemplate{{Name: "X-Fixture-Outcome", Values: []string{"reject"}}}})
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/admin/api/probe-recipes/%d/versions/%d", recipeID, failedVersion.ID)
	versionPath := fmt.Sprintf("/admin/api/probe-recipe-versions/%d", failedVersion.ID)
	result := do(t, h, "POST", versionPath+"/test", fmt.Sprintf(`{"expected_revision":3,"route_id":%d}`, route.ID), true)
	if result.Code != 200 {
		t.Fatalf("failed explicit test=%d %s", result.Code, result.Body.String())
	}
	execution := decodeBody[model.ProbeExecution](t, result)
	if execution.Success || !execution.Final || execution.SentAtMS == 0 || calls.Load() != 1 {
		t.Fatalf("not an actual completed failed test: %+v", execution)
	}
	latestAudit(t, s, "recipe_test", "failed")
	ordinary := do(t, h, "POST", path+"/publish", fmt.Sprintf(`{"expected_revision":3,"test_execution_id":%q}`, execution.ID), true)
	if ordinary.Code != 400 {
		t.Fatalf("failed test published without Force: %d %s", ordinary.Code, ordinary.Body.String())
	}
	latestAudit(t, s, "recipe_publish", "failed")
	forced := do(t, h, "POST", path+"/publish", fmt.Sprintf(`{"expected_revision":3,"test_execution_id":%q,"force":true}`, execution.ID), true)
	if forced.Code != 200 {
		t.Fatalf("explicit failed-test Force=%d %s", forced.Code, forced.Body.String())
	}
	row := decodeBody[model.ProbeRecipe](t, forced)
	if !row.LastPublishForced || row.PublishedVersionID != failedVersion.ID || calls.Load() != 1 {
		t.Fatal("Force lost attribution or sent twice")
	}
	latestAudit(t, s, "recipe_force_publish", "succeeded")
}

func TestClientProfileHTTPFailureDoesNotEnableCandidate(t *testing.T) {
	s, h, source, _, calls, _, _, route := recipeHTTPFixture(t)
	profile := &model.ClientProbeProfile{UpstreamID: route.UpstreamID, Endpoint: model.EndpointChatCompletions, ClientFamily: "claude-cli/2", ShapeHash: "fixture-failing-profile", SeenCount: 1, SafeHeaders: []model.HeaderTemplate{{Name: "User-Agent", Values: []string{"claude-cli/2.1.0"}}}}
	if err := s.st.CreateClientProfileCandidate(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	source.Invalidate()
	if err := source.Refresh(); err != nil {
		t.Fatal(err)
	}
	result := do(t, h, "POST", fmt.Sprintf("/admin/api/client-probe-profiles/%d/test", profile.ID), fmt.Sprintf(`{"expected_revision":1,"route_id":%d}`, route.ID), true)
	if result.Code != 200 {
		t.Fatalf("failed profile test=%d %s", result.Code, result.Body.String())
	}
	execution := decodeBody[model.ProbeExecution](t, result)
	if execution.Success || calls.Load() != 1 {
		t.Fatal("failure fixture did not run exactly once")
	}
	current, err := s.st.GetClientProfile(context.Background(), profile.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Status != model.ProfileCandidate || current.Revision != profile.Revision {
		t.Fatal("failed test enabled or changed candidate")
	}
	latestAudit(t, s, "profile_test_activate", "failed")
}

func TestClientProfileHTTPRejectsSecretDeclarationsBeforeSanitizerDropsHeader(t *testing.T) {
	s, h, source, _, calls, _, _, route := recipeHTTPFixture(t)
	if _, err := s.st.CreateProbeSecret("profile-hidden-secret", []byte("fixture-only-profile-secret")); err != nil {
		t.Fatal(err)
	}
	profile := &model.ClientProbeProfile{UpstreamID: route.UpstreamID, Endpoint: model.EndpointChatCompletions, ClientFamily: "generic", ShapeHash: "fixture-profile-with-secret", SeenCount: 1, SafeHeaders: []model.HeaderTemplate{{Name: "X-Probe-Secret", Values: []string{"{{SECRET:profile-hidden-secret}}"}}}}
	if err := s.st.CreateClientProfileCandidate(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	source.Invalidate()
	if err := source.Refresh(); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/admin/api/client-probe-profiles/%d", profile.ID)
	for _, action := range []string{"preview", "test"} {
		body := fmt.Sprintf(`{"route_id":%d}`, route.ID)
		if action == "test" {
			body = fmt.Sprintf(`{"expected_revision":1,"route_id":%d}`, route.ID)
		}
		response := do(t, h, "POST", path+"/"+action, body, true)
		if response.Code != 400 {
			t.Errorf("raw Secret declaration bypassed automatic-profile validation during %s: %d %s", action, response.Code, response.Body.String())
		}
	}
	if calls.Load() != 0 {
		t.Fatal("unsafe candidate reached upstream")
	}
	current, err := s.st.GetClientProfile(context.Background(), profile.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Status != model.ProfileCandidate {
		t.Fatal("profile unusable by automatic resolver was enabled")
	}
}

func TestRecipeAndProfileHTTPRejectUnsafeDTOAndReturnOnlySanitizedShape(t *testing.T) {
	s, h, source, _, calls, recipeID, version, route := recipeHTTPFixture(t)
	for _, body := range []string{`{"expected_revision":2,"method":"POST","origin":"learned","timeout_profile":"l2_standard"}`, `{"expected_revision":2,"method":"POST","body_text":"x","body_base64":"eA==","timeout_profile":"l2_standard"}`, `{"expected_revision":2,"method":"POST","body_base64":"!bad","timeout_profile":"l2_standard"}`, `{"expected_revision":2,"method":"POST","headers":{"X":"wrong-shape"},"timeout_profile":"l2_standard"}`, `{"expected_revision":2,"method":"POST","timeout_profile":"l2_standard"}{"extra":true}`} {
		response := do(t, h, "POST", fmt.Sprintf("/admin/api/probe-recipes/%d/versions", recipeID), body, true)
		if response.Code != 400 {
			t.Errorf("unsafe version mutation accepted: %d %s", response.Code, response.Body.String())
		}
	}
	wrong := do(t, h, "POST", fmt.Sprintf("/admin/api/probe-recipes/%d/versions/%d/publish", recipeID+999, version.ID), `{"expected_revision":2}`, true)
	if wrong.Code != 400 || calls.Load() != 0 {
		t.Fatal("cross-parent version request reached network")
	}
	profile := &model.ClientProbeProfile{UpstreamID: route.UpstreamID, Endpoint: model.EndpointChatCompletions, ClientFamily: "generic", ShapeHash: "fixture-dirty-legacy", SeenCount: 1}
	if err := s.st.CreateClientProfileCandidate(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	const private = "fixture-private-body-never-export"
	if _, err := s.st.DB().Exec(`UPDATE client_probe_profile SET body_template=?,safe_headers_json=?,fixed_raw_query=? WHERE id=?`, []byte(private), `[{"name":"Authorization","values":["Bearer fixture-private-credential-never-export"]}]`, `api_key=fixture-private-query-never-export`, profile.ID); err != nil {
		t.Fatal(err)
	}
	source.Invalidate()
	if err := source.Refresh(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/admin/api/client-probe-profiles", fmt.Sprintf("/admin/api/client-probe-profiles/%d", profile.ID)} {
		response := do(t, h, "GET", path, "", true)
		if response.Code != 200 {
			t.Fatalf("safe read=%d %s", response.Code, response.Body.String())
		}
		for _, secret := range []string{private, "fixture-private-credential-never-export", "fixture-private-query-never-export"} {
			if strings.Contains(response.Body.String(), secret) {
				t.Fatalf("legacy profile leaked raw source at %s", path)
			}
		}
	}
}
