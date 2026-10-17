package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

type pagedHealthResponse struct {
	Routes  []healthRow `json:"routes"`
	Next    string      `json:"next_cursor"`
	Summary struct {
		Total      int    `json:"total"`
		Selectable int    `json:"selectable"`
		Scope      string `json:"scope"`
	} `json:"summary"`
}

func TestHealthRealHTTPBoundedMetadataPagesAndModelVisibility(t *testing.T) {
	s, _ := newTestServer(t)
	up := metadataUpstream(t, s, "health-page-upstream", "health-page-credential-fixture")
	for i := 0; i < 205; i++ {
		mn, err := s.configAdmin.CreateModelName(context.Background(), model.ModelName{Name: fmt.Sprintf("health-model-%03d", i), Protocol: model.ProtoAnthropic, Enabled: i != 0})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.configAdmin.CreateRoute(context.Background(), model.Route{ModelNameID: mn.ID, UpstreamID: up.ID, Enabled: true, Priority: (i % 3) + 1, Weight: 100}); err != nil {
			t.Fatal(err)
		}
	}
	server := httptest.NewServer(withHealthView(t, s))
	defer server.Close()
	get := func(query string, authorized bool) (int, pagedHealthResponse) {
		t.Helper()
		request, _ := http.NewRequest("GET", server.URL+"/admin/api/health"+query, nil)
		if authorized {
			request.Header.Set("Authorization", "Bearer "+testAdminPW)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var body pagedHealthResponse
		if response.StatusCode == 200 {
			if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
		}
		return response.StatusCode, body
	}
	if status, _ := get("?limit=200", false); status != 401 {
		t.Fatalf("health page permission=%d", status)
	}
	status, first := get("?limit=200", true)
	if status != 200 || len(first.Routes) != 200 || first.Next == "" {
		t.Fatalf("health ignored bounded page: status=%d rows=%d next=%v", status, len(first.Routes), first.Next != "")
	}
	if first.Summary.Total != 200 || first.Summary.Scope != "page" || first.Summary.Selectable != 199 {
		t.Fatalf("page summary/model disable contract: %+v", first.Summary)
	}
	if first.Routes[0].Selectable || first.Routes[0].Reason == "" {
		t.Fatal("disabled model was presented as selectable")
	}
	if first.Routes[0].ProbeMode != model.ProbeModeLazy {
		t.Fatal("health page relied on a separate upstream page for ProbeMode")
	}
	status, last := get("?limit=200&cursor="+url.QueryEscape(first.Next), true)
	if status != 200 || len(last.Routes) != 5 || last.Next != "" {
		t.Fatalf("health last page status=%d rows=%d", status, len(last.Routes))
	}
	seen := map[int64]bool{}
	for _, row := range append(first.Routes, last.Routes...) {
		if seen[row.RouteID] {
			t.Fatal("health cursor duplicated row")
		}
		seen[row.RouteID] = true
	}
	for _, query := range []string{"?limit=201", "?cursor=" + url.QueryEscape(first.Next) + "&enabled=false", "?cursor=" + url.QueryEscape(first.Next) + "&upstream_id=" + fmt.Sprint(up.ID)} {
		if status, _ := get(query, true); status != 400 {
			t.Fatalf("health page accepted changed cursor scope/limit: %d", status)
		}
	}
	if status, page := get("", true); status != 200 || len(page.Routes) != 50 {
		t.Fatalf("health default page=%d/%d", status, len(page.Routes))
	}
}

func TestHealthMetadataDoesNotDecryptOrParseCredentialColumns(t *testing.T) {
	s, _ := newTestServer(t)
	up := metadataUpstream(t, s, "health-metadata", "health-metadata-private-fixture")
	mn, err := s.configAdmin.CreateModelName(context.Background(), model.ModelName{Name: "health-metadata-model", Protocol: model.ProtoAnthropic, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.configAdmin.CreateRoute(context.Background(), model.Route{ModelNameID: mn.ID, UpstreamID: up.ID, Enabled: true, Priority: 1, Weight: 100}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.DB().Exec(`UPDATE upstream SET api_key_enc='invalid-ciphertext',probe_headers='invalid-json' WHERE id=?`, up.ID); err != nil {
		t.Fatal(err)
	}
	rec := do(t, withHealthView(t, s), "GET", "/admin/api/health", "", true)
	if rec.Code != 200 {
		t.Fatalf("metadata decrypted credential/parsed legacy header column: %d", rec.Code)
	}
}

type endpointHealthCapabilities struct{}

func (endpointHealthCapabilities) Effective(_ model.RecipeScope, _ int64, endpoint model.EndpointKind, _ string) model.CapabilityState {
	switch endpoint {
	case model.EndpointMessages:
		return model.CapabilitySupported
	case model.EndpointResponses:
		return model.CapabilityUnsupported
	case model.EndpointChatCompletions:
		return model.CapabilityConfigError
	default:
		return model.CapabilityUnknown
	}
}

func TestHealthRowsUseActualProtocolEndpointFromTheSameCapabilityView(t *testing.T) {
	s, _ := newTestServer(t)
	up := metadataUpstream(t, s, "protocol-health", "protocol-health-credential")
	var routes []model.Route
	for _, protocol := range []model.Protocol{model.ProtoAnthropic, model.ProtoOpenAIResponses, model.ProtoOpenAIChat} {
		mn, err := s.configAdmin.CreateModelName(context.Background(), model.ModelName{Name: string(protocol), Protocol: protocol, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		route, err := s.configAdmin.CreateRoute(context.Background(), model.Route{ModelNameID: mn.ID, UpstreamID: up.ID, Priority: 1, Weight: 100, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		routes = append(routes, route)
	}
	h := s.WithHealth(stubHealth{}, nil).WithCapabilities(endpointHealthCapabilities{}).Routes(testAdminPW)
	rows := healthRowsByRoute(t, h)
	for i, endpoint := range []model.EndpointKind{model.EndpointMessages, model.EndpointResponses, model.EndpointChatCompletions} {
		row := rows[routes[i].ID]
		if row["endpoint"] != string(endpoint) || row["capability"] != string((endpointHealthCapabilities{}).Effective(model.RecipeScopeRoute, routes[i].ID, endpoint, "")) {
			t.Fatalf("health page used another endpoint's capability for route %d", routes[i].ID)
		}
		if row["count_tokens"] != string(model.CapabilityUnknown) || row["state"] != string(model.StateUnknown) {
			t.Fatal("capability display changed model/count_tokens health")
		}
	}
}
