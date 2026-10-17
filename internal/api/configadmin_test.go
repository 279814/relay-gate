package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

func TestConfigAdminHTTP_ClientRevisionCannotBeReplacedByLatest(t *testing.T) {
	for _, kind := range []string{"upstreams", "model-names", "routes"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := newTestServer(t)
			seedConfig(t, s, 1, 1)
			pub := &recordingPublisher{}
			server := httptest.NewServer(s.WithConfigPublisher(pub).Routes(testAdminPW))
			defer server.Close()
			request := func(method, path, body string) (int, string) {
				req, _ := http.NewRequest(method, server.URL+"/admin/api/"+path, strings.NewReader(body))
				req.Header.Set("Authorization", "Bearer "+testAdminPW)
				response, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Error(err)
					return 0, ""
				}
				defer response.Body.Close()
				output, _ := io.ReadAll(response.Body)
				return response.StatusCode, string(output)
			}
			path := kind + "/1"
			for _, mutation := range []struct{ method, path, body string }{{"PUT", path, `{"enabled":false}`}, {"DELETE", path, ""}, {"PUT", path, `{"expected_revision":0,"enabled":false}`}} {
				if code, body := request(mutation.method, mutation.path, mutation.body); code != 400 {
					t.Fatalf("missing revision=%d %s", code, body)
				}
			}
			var wg sync.WaitGroup
			codes := make(chan int, 2)
			for _, body := range []string{`{"expected_revision":1,"enabled":false}`, `{"expected_revision":1,"enabled":false}`} {
				wg.Add(1)
				go func(body string) { defer wg.Done(); code, _ := request("PUT", path, body); codes <- code }(body)
			}
			wg.Wait()
			close(codes)
			counts := map[int]int{}
			for code := range codes {
				counts[code]++
			}
			if counts[200] != 1 || counts[409] != 1 {
				t.Fatalf("concurrent clients=%v", counts)
			}
			if code, body := request("DELETE", path+"?expected_revision=1", ""); code != 409 {
				t.Fatalf("old-page delete=%d %s", code, body)
			}
			if inv, ref := pub.counts(); inv != 1 || ref != 1 {
				t.Fatalf("rejected writes published: %d/%d", inv, ref)
			}
			code, body := request("GET", path, "")
			if code != 200 {
				t.Fatal(body)
			}
			var row struct {
				Revision int64 `json:"revision"`
				Enabled  bool  `json:"enabled"`
			}
			_ = json.Unmarshal([]byte(body), &row)
			if row.Revision != 2 || row.Enabled {
				t.Fatalf("stored revision=%+v", row)
			}
			if _, err := s.st.ListRoutesPage(context.Background(), model.RouteFilter{}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestConfigAdminHTTP_CreateRequiresExplicitCompleteEndpointBundle(t *testing.T) {
	s, h := newTestServer(t)
	for _, body := range []string{
		`{"name":"missing","base_url":"https://example.test","api_key":"fixture-secret-key"}`,
		`{"name":"empty","base_url":"https://example.test","api_key":"fixture-secret-key","initial_endpoints":[]}`,
	} {
		rec := do(t, h, "POST", "/admin/api/upstreams", body, true)
		if rec.Code != 400 {
			t.Fatalf("server guessed initial endpoints: %d %s", rec.Code, rec.Body.String())
		}
	}
	items, err := s.st.ListUpstreams()
	if err != nil || len(items) != 0 {
		t.Fatalf("invalid bundle persisted parent: %v %v", items, err)
	}
}

func TestConfigAdminHTTP_PagesAndFiltersAreBoundToCursor(t *testing.T) {
	s, h := newTestServer(t)
	seedConfig(t, s, 5, 3)
	for _, resource := range []string{"upstreams", "model-names", "routes"} {
		first := do(t, h, "GET", "/admin/api/"+resource+"?limit=2", "", true)
		page := decodeBody[model.Page[map[string]any]](t, first)
		if first.Code != 200 || len(page.Items) != 2 || page.NextCursor == "" {
			t.Fatalf("first page %s: %d %s", resource, first.Code, first.Body.String())
		}
		cursor := page.NextCursor
		seen := map[float64]bool{}
		for _, item := range page.Items {
			seen[item["id"].(float64)] = true
		}
		for cursor != "" {
			rec := do(t, h, "GET", "/admin/api/"+resource+"?limit=2&cursor="+url.QueryEscape(cursor), "", true)
			if rec.Code != 200 {
				t.Fatal(rec.Body.String())
			}
			page = decodeBody[model.Page[map[string]any]](t, rec)
			for _, item := range page.Items {
				id := item["id"].(float64)
				if seen[id] {
					t.Fatal("cursor repeated an item")
				}
				seen[id] = true
			}
			cursor = page.NextCursor
		}
		want := map[string]int{"upstreams": 5, "model-names": 3, "routes": 15}[resource]
		if len(seen) != want {
			t.Fatalf("%s items=%d want=%d", resource, len(seen), want)
		}
		for _, query := range []string{"limit=garbage", "limit=0", "limit=201", "enabled=garbage", "cursor=bad", "enabled=false&cursor=" + url.QueryEscape(decodeBody[model.Page[map[string]any]](t, first).NextCursor)} {
			if rec := do(t, h, "GET", "/admin/api/"+resource+"?"+query, "", true); rec.Code != 400 {
				t.Fatalf("%s query %s=%d", resource, query, rec.Code)
			}
		}
	}
	page := do(t, h, "GET", "/admin/api/upstreams?limit=1", "", true)
	cursor := decodeBody[model.Page[map[string]any]](t, page).NextCursor
	if rec := do(t, h, "GET", "/admin/api/routes?cursor="+url.QueryEscape(cursor), "", true); rec.Code != 400 {
		t.Fatal("cross-resource cursor was accepted")
	}
	if rec := do(t, h, "GET", "/admin/api/routes?upstream_id=2&model_name_id=2", "", true); len(decodeBody[model.Page[model.Route]](t, rec).Items) != 1 {
		t.Fatal("route SQL filter was not applied")
	}
}

func TestConfigAdminHTTP_RefreshFailureReportsCommittedRevision(t *testing.T) {
	s, h, _, pub := newLivecfgServer(t)
	seedConfig(t, s, 1, 1)
	pub.refreshErr = errors.New("sensitive backend detail")
	rec := do(t, h, "PUT", "/admin/api/routes/1", `{"expected_revision":1,"priority":8}`, true)
	var output struct {
		Code      string `json:"code"`
		Persisted bool   `json:"persisted"`
		ID        int64  `json:"resource_id"`
		Revision  int64  `json:"revision"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &output)
	if rec.Code != 503 || output.Code != "config_activation_pending" || !output.Persisted || output.ID != 1 || output.Revision != 2 || strings.Contains(rec.Body.String(), "sensitive") {
		t.Fatalf("activation result: %d %s", rec.Code, rec.Body.String())
	}
	row, err := s.st.GetRoute(1)
	if err != nil || row.Priority != 8 || row.Revision != 2 {
		t.Fatal("503 pretended write rollback")
	}
	if replay := do(t, h, "PUT", "/admin/api/routes/1", `{"expected_revision":1,"priority":8}`, true); replay.Code != 409 {
		t.Fatalf("old revision replay=%d", replay.Code)
	}
}

func TestConfigAdminHTTP_InitialBundleIsAtomicAndDoesNotInferAuth(t *testing.T) {
	s, h := newTestServer(t)
	valid := upstreamFixture(t, `{"name":"bundle","base_url":"https://example.test","api_key":"fixture-bundle-private-key"}`)
	for _, mutation := range []func(map[string]any){
		func(value map[string]any) { eps := value["initial_endpoints"].([]any); eps[1] = eps[0] },
		func(value map[string]any) {
			eps := value["initial_endpoints"].([]any)
			eps[0].(map[string]any)["auth_profile"] = map[string]any{"mode": "header_bearer"}
		},
		func(value map[string]any) {
			eps := value["initial_endpoints"].([]any)
			eps[2].(map[string]any)["auth_profile"] = map[string]any{"mode": "manual_headers", "secret_ref": "upstream_api_key", "manual_headers": []any{map[string]any{"name": "X-Key", "values": []string{"{{SECRET:missing}}"}}}}
		},
	} {
		var value map[string]any
		_ = json.Unmarshal([]byte(valid), &value)
		mutation(value)
		body, _ := json.Marshal(value)
		rec := do(t, h, "POST", "/admin/api/upstreams", string(body), true)
		if rec.Code != 400 {
			t.Fatalf("invalid bundle=%d %s", rec.Code, rec.Body.String())
		}
		rows, _ := s.st.ListUpstreams()
		eps, _ := s.st.ListEndpointsPage(context.Background(), model.EndpointFilter{})
		if len(rows) != 0 || len(eps.Items) != 0 {
			t.Fatal("invalid child left partial parent/endpoint rows")
		}
	}
	_, err := s.st.DB().Exec(`CREATE TEMP TRIGGER fail_bundle BEFORE INSERT ON upstream_endpoint WHEN NEW.endpoint='responses' BEGIN SELECT RAISE(ABORT,'bundle failure'); END`)
	if err != nil {
		t.Fatal(err)
	}
	if rec := do(t, h, "POST", "/admin/api/upstreams", valid, true); rec.Code != 500 {
		t.Fatalf("injected insert=%d %s", rec.Code, rec.Body.String())
	}
	rows, _ := s.st.ListUpstreams()
	eps, _ := s.st.ListEndpointsPage(context.Background(), model.EndpointFilter{})
	if len(rows) != 0 || len(eps.Items) != 0 {
		t.Fatal("SQL failure left partial bundle")
	}
}

func TestConfigAdminHTTP_ReEnableModelForgetsOnlyItsChildrenWithoutSynthetic(t *testing.T) {
	s, _ := newTestServer(t)
	seedConfig(t, s, 1, 2)
	settings := &fakeSettingsForInvalidate{s: model.DefaultSettings()}
	settings.s.FailThreshold = 1
	tracker := health.NewTracker(settings)
	inner := &recordingInvalidator{}
	h := s.WithInvalidator(&SemanticConfigInvalidator{Semantic: health.NewSemanticInvalidator(tracker, nil, nil, nil, nil), Inner: inner}).Routes(testAdminPW)
	if rec := do(t, h, "PUT", "/admin/api/model-names/1", `{"expected_revision":1,"enabled":false}`, true); rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	for _, id := range []int64{1, 2} {
		tracker.Report(health.Report{RouteID: id, Source: health.SourceL2, Verdict: health.VerdictUnavailable})
	}
	if rec := do(t, h, "PUT", "/admin/api/model-names/1", `{"expected_revision":2,"enabled":true}`, true); rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	if tracker.State(1) != model.StateUnknown || tracker.State(2) != model.StateDead {
		t.Fatalf("wrong re-enable scope: child=%s sibling=%s", tracker.State(1), tracker.State(2))
	}
	if routes, ups, names := inner.counts(); routes+ups+names != 0 {
		t.Fatalf("reenable scheduled synthetic: %d/%d/%d", routes, ups, names)
	}
}

func TestConfigAdminHTTP_InitialBundleValidationCannotEchoCredential(t *testing.T) {
	_, h := newTestServer(t)
	body := upstreamFixture(t, `{"name":"private","base_url":"https://example.test","api_key":"fixture-private-api-key"}`)
	var value map[string]any
	_ = json.Unmarshal([]byte(body), &value)
	ep := value["initial_endpoints"].([]any)[0].(map[string]any)
	ep["auth_profile"] = map[string]any{"mode": "manual_headers", "secret_ref": "upstream_api_key", "manual_headers": []any{map[string]any{"name": "X-Key", "values": []string{"{{SECRET:fixture-private-api-key}}"}}}}
	encoded, _ := json.Marshal(value)
	rec := do(t, h, "POST", "/admin/api/upstreams", string(encoded), true)
	if rec.Code != 400 || strings.Contains(rec.Body.String(), "fixture-private-api-key") {
		t.Fatalf("credential leaked from invalid Secret reference: %d %s", rec.Code, rec.Body.String())
	}
}

func TestConfigAdminHTTP_NoOpKeepsResourceAndSemanticVersions(t *testing.T) {
	s, h := newTestServer(t)
	seedConfig(t, s, 1, 1)
	for _, resource := range []string{"upstreams", "model-names", "routes"} {
		before := do(t, h, "GET", "/admin/api/"+resource+"/1", "", true)
		updated := do(t, h, "PUT", "/admin/api/"+resource+"/1", `{"expected_revision":1}`, true)
		if updated.Code != 200 || before.Body.String() != updated.Body.String() {
			t.Fatalf("no-op changed row/semantic fields for %s: %s => %s", resource, before.Body.String(), updated.Body.String())
		}
	}
}

func TestConfigAdminHTTP_DefaultAndMaximumPageSizesAndAllFilters(t *testing.T) {
	s, h := newTestServer(t)
	seedConfig(t, s, 205, 1)
	for _, page := range []struct {
		query string
		want  int
	}{{"", 50}, {"?limit=200", 200}} {
		rec := do(t, h, "GET", "/admin/api/upstreams"+page.query, "", true)
		result := decodeBody[model.Page[upstreamOut]](t, rec)
		if rec.Code != 200 || len(result.Items) != page.want || result.NextCursor == "" {
			t.Fatalf("page %s count=%d code=%d", page.query, len(result.Items), rec.Code)
		}
		if strings.Contains(rec.Body.String(), "sk-seed-key-abcdefgh") {
			t.Fatal("paged upstream response leaked credential")
		}
	}
	for _, mutation := range []struct{ path, body string }{{"upstreams/1", `{"expected_revision":1,"probe_mode":"lazy","enabled":false}`}, {"model-names/1", `{"expected_revision":1,"protocol":"openai-chat"}`}, {"routes/1", `{"expected_revision":1,"enabled":false}`}} {
		if rec := do(t, h, "PUT", "/admin/api/"+mutation.path, mutation.body, true); rec.Code != 200 {
			t.Fatal(rec.Body.String())
		}
	}
	for _, path := range []string{"upstreams?probe_mode=lazy&enabled=false", "model-names?protocol=openai-chat&enabled=true", "routes?upstream_id=1&model_name_id=1&enabled=false"} {
		rec := do(t, h, "GET", "/admin/api/"+path, "", true)
		if rec.Code != 200 || len(decodeBody[model.Page[map[string]any]](t, rec).Items) != 1 {
			t.Fatalf("server filter %s: %d %s", path, rec.Code, rec.Body.String())
		}
	}
}
