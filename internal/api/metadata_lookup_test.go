package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/configadmin"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/security"
)

func metadataUpstream(t *testing.T, s *Server, name, key string) model.Upstream {
	t.Helper()
	var initial []configadmin.EndpointMutation
	for _, kind := range []model.EndpointKind{model.EndpointModels, model.EndpointMessages, model.EndpointResponses, model.EndpointChatCompletions, model.EndpointCountTokens} {
		initial = append(initial, configadmin.EndpointMutation{Endpoint: kind, AuthProfile: model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: "upstream_api_key"}})
	}
	u, err := s.configAdmin.CreateUpstream(context.Background(), model.Upstream{Name: name, BaseURL: "https://metadata.example", APIKey: key, Enabled: true, ProbeMode: model.ProbeModeLazy}, initial)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestSecurityNamedLookupDoesNotScanOrDecryptUnrelatedSites(t *testing.T) {
	s, _ := newTestServer(t)
	var first int64
	for i := 0; i < 205; i++ {
		key := fmt.Sprintf("opaque-other-tenant-fixture-%03d", i)
		if i == 204 {
			key = "opaque-fixture-credential-value"
		}
		u := metadataUpstream(t, s, fmt.Sprintf("metadata-up-%03d", i), key)
		if i == 0 {
			first = u.ID
		}
	}
	if _, err := s.st.DB().Exec(`UPDATE upstream SET api_key_enc='broken-unrelated-envelope' WHERE id=?`, first); err != nil {
		t.Fatal(err)
	}
	h := s.WithSecurityCenter(security.NewCenter(50)).Routes(testAdminPW)
	body := `{"upstream":"metadata-up-204","text":"<script>x</script> opaque-fixture-credential-value"}`
	server := httptest.NewServer(h)
	defer server.Close()
	request, err := http.NewRequest(http.MethodPost, server.URL+"/admin/api/security/scan", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+testAdminPW)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	wire, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 {
		t.Fatalf("targeted scan status=%d", response.StatusCode)
	}
	if strings.Contains(string(wire), "opaque-fixture-credential-value") {
		t.Fatal("exact site lookup failed because an unrelated site's ciphertext was scanned; its key reached finding output")
	}
}

func TestConfigMetadataRealHTTPPagesOver200KeepCursorScopeAndPermission(t *testing.T) {
	s, _ := newTestServer(t)
	mn, err := s.configAdmin.CreateModelName(context.Background(), model.ModelName{Name: "page-model", Protocol: model.ProtoAnthropic, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 205; i++ {
		u := metadataUpstream(t, s, fmt.Sprintf("paged-%03d", i), "page-fixture-upstream-credential")
		if _, err := s.configAdmin.CreateRoute(context.Background(), model.Route{ModelNameID: mn.ID, UpstreamID: u.ID, Priority: 1, Weight: 100, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	server := httptest.NewServer(s.Routes(testAdminPW))
	defer server.Close()
	get := func(path string, authorized bool) (int, model.Page[model.Route]) {
		t.Helper()
		request, _ := http.NewRequest("GET", server.URL+"/admin/api/"+path, nil)
		if authorized {
			request.Header.Set("Authorization", "Bearer "+testAdminPW)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var page model.Page[model.Route]
		if response.StatusCode == 200 {
			if err := json.NewDecoder(response.Body).Decode(&page); err != nil {
				t.Fatal(err)
			}
		}
		return response.StatusCode, page
	}
	if status, _ := get("routes?limit=200", false); status != 401 {
		t.Fatalf("unprotected metadata-bearing config page: %d", status)
	}
	status, first := get("routes?limit=200", true)
	if status != 200 || len(first.Items) != 200 || first.NextCursor == "" {
		t.Fatalf("first route page status=%d count=%d", status, len(first.Items))
	}
	status, last := get("routes?limit=200&cursor="+url.QueryEscape(first.NextCursor), true)
	if status != 200 || len(last.Items) != 5 || last.NextCursor != "" {
		t.Fatalf("last route page status=%d count=%d", status, len(last.Items))
	}
	seen := map[int64]bool{}
	for _, item := range append(first.Items, last.Items...) {
		if seen[item.ID] {
			t.Fatal("real HTTP cursor repeated a route")
		}
		seen[item.ID] = true
	}
	for _, path := range []string{"routes?limit=201", "routes?cursor=" + url.QueryEscape(first.NextCursor) + "&upstream_id=1", "upstreams?cursor=" + url.QueryEscape(first.NextCursor)} {
		if status, _ := get(path, true); status != 400 {
			t.Fatalf("cursor/limit contract accepted %s status=%d", path, status)
		}
	}
	metadata, err := s.configAdmin.ListRouteMetadata(context.Background(), model.RouteFilter{PageRequest: model.PageRequest{Limit: 200}})
	if err != nil || len(metadata.Items) != 200 || metadata.NextCursor == "" {
		t.Fatalf("domain metadata page count=%d err=%v", len(metadata.Items), err)
	}
}

func TestSecuritySelectedCredentialReadFailureRecordsNoRawFinding(t *testing.T) {
	s, _ := newTestServer(t)
	u := metadataUpstream(t, s, "unreadable-site", "opaque-selected-fixture-key")
	if _, err := s.st.DB().Exec(`UPDATE upstream SET api_key_enc='broken-envelope' WHERE id=?`, u.ID); err != nil {
		t.Fatal(err)
	}
	center := security.NewCenter(50)
	h := s.WithSecurityCenter(center).Routes(testAdminPW)
	for _, ref := range []string{u.Name, fmt.Sprint(u.ID)} {
		rec := do(t, h, http.MethodPost, "/admin/api/security/scan", fmt.Sprintf(`{"upstream":%q,"text":"<script>x</script> opaque-selected-fixture-key"}`, ref), true)
		if rec.Code != 503 || center.Count() != 0 {
			t.Fatalf("unreadable selected credential was not closed safely: status=%d findings=%d", rec.Code, center.Count())
		}
		if strings.Contains(rec.Body.String(), "opaque-selected-fixture-key") {
			t.Fatal("failure response leaked selected key")
		}
	}
}
