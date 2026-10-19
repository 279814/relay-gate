package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestProbeStatisticsRealHTTPKeepsUnknownAndRequiresAdmin(t *testing.T) {
	s, _ := newTestServer(t)
	server := httptest.NewServer(s.Routes(testAdminPW))
	defer server.Close()
	get := func(authorized bool) (int, http.Header, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/admin/api/probe-statistics?day_from=2026-10-19&day_to=2026-10-19", nil)
		if authorized {
			req.Header.Set("Authorization", "Bearer "+testAdminPW)
		}
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		var data map[string]any
		if resp.StatusCode == http.StatusOK {
			if err := json.Unmarshal(raw, &data); err != nil {
				t.Fatal(err)
			}
		}
		return resp.StatusCode, resp.Header, data
	}
	code, header, data := get(true)
	if code != http.StatusOK {
		t.Fatalf("historical statistics endpoint status=%d want 200", code)
	}
	if !strings.Contains(header.Get("Cache-Control"), "no-store") {
		t.Fatal("statistics response is cacheable")
	}
	if data["total_rows"] != float64(0) || data["basis"] != "executions" {
		t.Fatalf("empty statistics contract=%+v", data)
	}
	coverage, ok := data["coverage"].(map[string]any)
	if !ok || coverage["canary_source"] != "unavailable" {
		t.Fatalf("missing source became false zero: %+v", data)
	}
	if code, _, _ := get(false); code != http.StatusUnauthorized {
		t.Fatalf("statistics bypassed admin permission: %d", code)
	}
}

func TestProbeStatisticsRealHTTPFiltersAndBoundedProjection(t *testing.T) {
	s, _ := newTestServer(t)
	up := metadataUpstream(t, s, "statistics-http", "opaque-public-synthetic-credential")
	for i, template := range []string{"builtin:one", "builtin:two"} {
		execution := model.ProbeExecution{ID: template, UpstreamID: up.ID, Endpoint: model.EndpointModels, Trigger: model.TriggerManual, RecipeBindingUse: model.BindingResolved, RecipeStorage: model.RecipeStorageEmbedded, RecipeOrigin: model.RecipeBasic, TemplateID: template, RecipeIdentityRevision: 1, ErrorClass: model.ErrorNone, Capability: model.CapabilityUnknown, Scope: model.ScopeUpstreamReachability, EvidenceHash: "synthetic", ObservationOrder: int64(i + 1), SentAtMS: 1792368000000, DoneAtMS: 1792368001000, Success: true, Final: true, RedactedDetail: "private-synthetic-not-statistics"}
		if err := s.st.InsertProbeExecution(context.Background(), &execution); err != nil {
			t.Fatal(err)
		}
	}
	h := s.Routes(testAdminPW)
	base := "/admin/api/probe-statistics?day_from=2026-10-19&day_to=2026-10-19"
	first := do(t, h, "GET", base+"&limit=1&scope=upstream", "", true)
	if first.Code != 200 || strings.Contains(first.Body.String(), "private-synthetic-not-statistics") || strings.Contains(first.Body.String(), "opaque-public-synthetic-credential") {
		t.Fatalf("bounded metadata projection failed: %d %s", first.Code, first.Body.String())
	}
	page := decodeBody[model.ProbeStatisticsPage](t, first)
	if page.TotalRows != 2 || len(page.Items) != 1 || page.NextCursor == "" || page.Items[0].ModelsRequests != 1 || page.Items[0].ObservedOutputTokens != nil {
		t.Fatalf("HTTP statistics=%+v", page)
	}
	for _, suffix := range []string{
		"&limit=201", "&limit=-1", "&limit=1&limit=2", "&scope=bogus", "&basis=unknown", "&endpoint=raw_sql", "&trigger=canary", "&origin=made_up", "&storage=unknown", "&route_id=-1", "&version_id=bad", "&include_body=true", "&sort=redacted_detail", "&basis=daily&recipe_id=1", "&basis=daily&trigger=real_traffic", "&day_from=2020-01-01", "&day_to=2026-10-18",
	} {
		// Duplicate time keys deliberately exercise the strict adapter too.
		rec := do(t, h, "GET", base+suffix, "", true)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("query %s status=%d body=%s", suffix, rec.Code, rec.Body.String())
		}
	}
}
