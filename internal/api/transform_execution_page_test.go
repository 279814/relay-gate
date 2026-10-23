package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/transform"
)

func TestTransformExecutionFilteredCursorAndRetention(t *testing.T) {
	registry := transform.NewRegistry(300)
	for i := 0; i < 250; i++ {
		registry.RecordExecution(transform.ExecutionRecord{RouteID: int64(i%2 + 1), EndpointID: 3, VersionID: 4, Mode: "published", Phase: "response", OK: false, At: time.UnixMilli(1000)})
	}
	h := New(nil, nil).WithTransformRegistry(registry).Routes(testAdminPW)
	type page struct {
		Executions []transform.ExecutionRecord `json:"executions"`
		Total      int                         `json:"total"`
		Next       string                      `json:"next_cursor"`
		Scope      string                      `json:"scope"`
	}
	base := "/admin/api/transform-executions?route_id=1&endpoint_id=3&version_id=4&mode=published&phase=response&ok=false&after_ms=999&before_ms=1001"
	read := func(path string) page {
		t.Helper()
		response := do(t, h, http.MethodGet, path, "", true)
		if response.Code != 200 {
			t.Fatalf("GET %s = %d %s", path, response.Code, response.Body.String())
		}
		var result page
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	first := read(base)
	if len(first.Executions) != 50 || first.Total != 125 || first.Scope != "current_run_retained" || first.Next == "" {
		t.Fatalf("unbounded or misleading filtered page: count=%d total=%d scope=%q next=%q", len(first.Executions), first.Total, first.Scope, first.Next)
	}
	// New arrivals must not duplicate or displace records in the next page.
	registry.RecordExecution(transform.ExecutionRecord{RouteID: 1, EndpointID: 3, VersionID: 4, Mode: "published", Phase: "response", At: time.UnixMilli(1000)})
	second := read(base + "&cursor=" + url.QueryEscape(first.Next))
	third := read(base + "&cursor=" + url.QueryEscape(second.Next))
	seen := map[string]bool{}
	for _, p := range []page{first, second, third} {
		for _, record := range p.Executions {
			if seen[record.ID] || record.RouteID != 1 || record.OK {
				t.Fatalf("duplicate/unfiltered record: %+v", record)
			}
			seen[record.ID] = true
		}
	}
	if len(second.Executions) != 50 || len(third.Executions) != 25 || third.Next != "" {
		t.Fatalf("bad tail: %d %d %q", len(second.Executions), len(third.Executions), third.Next)
	}
	for _, query := range []string{
		"?unknown=1", "?limit=0", "?limit=201", "?limit=1&limit=2", "?route_id=-1", "?route_id=", "?ok=1", "?phase=bogus", "?mode=bogus", "?after_ms=-1", "?after_ms=2&before_ms=1", "?cursor=bad",
		"?route_id=2&cursor=" + url.QueryEscape(first.Next),
	} {
		response := do(t, h, "GET", "/admin/api/transform-executions"+query, "", true)
		if response.Code != 400 {
			t.Errorf("query %s = %d want400", query, response.Code)
		}
	}
	for i := 0; i < 300; i++ {
		registry.RecordExecution(transform.ExecutionRecord{})
	}
	response := do(t, h, "GET", base+"&cursor="+url.QueryEscape(first.Next), "", true)
	if response.Code != 400 {
		t.Fatalf("evicted anchor must request reload, got%d", response.Code)
	}
}
