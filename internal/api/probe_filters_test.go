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

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probe"
)

func seedProbeListFilters(t *testing.T, s *Server) {
	t.Helper()
	ctx := context.Background()
	mn, err := s.configAdmin.CreateModelName(ctx, model.ModelName{Name: "filter-model", Protocol: model.ProtoAnthropic, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 206; i++ {
		up := metadataUpstream(t, s, fmt.Sprintf("filter-up-%03d", i), "opaque-filter-fixture-credential")
		route, err := s.configAdmin.CreateRoute(ctx, model.Route{UpstreamID: up.ID, ModelNameID: mn.ID, Enabled: true, Priority: 1, Weight: 100})
		if err != nil {
			t.Fatal(err)
		}
		endpoint, err := s.st.Endpoint(ctx, up.ID, model.EndpointMessages)
		if err != nil {
			t.Fatal(err)
		}
		name, trigger, kind, capState, reachState, runState, day, origin, network, expires := fmt.Sprintf("main-%03d", i), model.TriggerRealTraffic, model.EndpointMessages, model.CapabilitySupported, model.ReachabilityReachable, model.CalibrationPlanned, "2099-01-01", model.RecipeManual, int64(1), int64(0)
		if i == 205 {
			name, trigger, kind, capState, reachState, runState, day, origin, network, expires = "other", model.TriggerManual, model.EndpointCountTokens, model.CapabilityUnsupported, model.ReachabilityUnreachable, model.CalibrationCanceled, "2099-02-01", model.RecipeCalibration, 0, 1
			endpoint, err = s.st.Endpoint(ctx, up.ID, kind)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.st.DB().Exec(`UPDATE upstream_endpoint SET needs_review=1 WHERE upstream_id=?`, up.ID); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.st.CreateProbeSecret(name, []byte("opaque-probe-secret-fixture-value")); err != nil {
			t.Fatal(err)
		}
		execution := model.ProbeExecution{ID: fmt.Sprintf("filter-exec-%03d", i), UpstreamID: up.ID, RouteID: route.ID, EndpointID: endpoint.ID, Endpoint: kind,
			Trigger: trigger, RecipeBindingUse: model.BindingRealTrafficContext, RecipeStorage: model.RecipeStorageEmbedded, RecipeOrigin: model.RecipeBasic,
			TemplateID: "basic-anthropic-messages", RecipeIdentityRevision: 1,
			ErrorClass: model.ErrorNone, Capability: capState, Scope: model.ScopeRouteEndpoint, EvidenceHash: fmt.Sprintf("filter-evidence-%03d", i),
			RedactedDetail: "opaque-filter-fixture-credential", SentAtMS: 0, DoneAtMS: 1000, ObservationOrder: int64(i + 1), Final: true, Success: true}
		if trigger == model.TriggerRealTraffic {
			execution.RealRequestShapeUnavailableReason = model.ShapeUnsupported
		} else {
			execution.RecipeBindingUse = model.BindingResolved
		}
		if err := s.st.InsertProbeExecution(ctx, &execution); err != nil {
			t.Fatal(err)
		}
		if _, err := s.st.DB().Exec(`INSERT INTO endpoint_capability(scope_route_id,endpoint,endpoint_id,evidence_kind,state,observation_token,
			upstream_network_revision,upstream_credential_revision,endpoint_revision,auth_profile_revision,recipe_binding_revision,
			probe_settings_fingerprint,probe_secret_revisions_hash,expires_at) VALUES(?,?,?,'real',?,'fixture',1,1,1,1,1,'fixture','',?)`, route.ID, kind, endpoint.ID, capState, expires); err != nil {
			t.Fatal(err)
		}
		if _, err := s.st.DB().Exec(`INSERT INTO upstream_reachability(upstream_id,evidence_kind,endpoint,state,observed_network_revision,settings_fingerprint,observation_token)
			VALUES(?,'real','models',?,?,'fixture','fixture')`, up.ID, reachState, network); err != nil {
			t.Fatal(err)
		}
		if _, err := s.st.DB().Exec(`INSERT INTO calibration_run(id,route_id,endpoint,state,created_at) VALUES(?,?,?,?,1000)`, fmt.Sprintf("filter-run-%03d", i), route.ID, kind, runState); err != nil {
			t.Fatal(err)
		}
		if _, err := s.st.DB().Exec(`INSERT INTO probe_cost_daily(day_utc,trigger,origin,endpoint,route_id,upstream_id,requests) VALUES(?,'manual',?,?,?,?,1)`, day, origin, kind, route.ID, up.ID); err != nil {
			t.Fatal(err)
		}
	}
}

type probeListWire struct {
	Items []map[string]any `json:"items"`
	Next  string           `json:"next_cursor"`
}

func TestProbeListsRealHTTPFilterScopeAndBoundedPages(t *testing.T) {
	s, _ := newTestServer(t)
	seedProbeListFilters(t, s)
	server := httptest.NewServer(s.WithProbeAdmin(probe.NewService(s.st, nil, nil, nil, nil, nil)).Routes(testAdminPW))
	defer server.Close()
	get := func(path, query string, authorized bool) (int, probeListWire) {
		t.Helper()
		request, _ := http.NewRequest("GET", server.URL+"/admin/api/"+path+"?"+query, nil)
		if authorized {
			request.Header.Set("Authorization", "Bearer "+testAdminPW)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		wire, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(wire), "opaque-filter-fixture-credential") || strings.Contains(string(wire), "opaque-probe-secret-fixture-value") {
			t.Fatal("list leaked fixture credential")
		}
		var page probeListWire
		if response.StatusCode == 200 {
			if err := json.Unmarshal(wire, &page); err != nil {
				t.Fatal(err)
			}
		}
		return response.StatusCode, page
	}
	for _, test := range []struct{ path, query, changed string }{
		{"upstream-endpoints", "endpoint=messages&needs_review=false", "endpoint=count_tokens&needs_review=false"},
		{"probe-secrets", "name_prefix=main-", "name_prefix=other"},
		{"probe-executions", "trigger=real_traffic", "trigger=manual"},
		{"capabilities", "state=supported", "state=unsupported"},
		{"reachability", "state=reachable", "state=unreachable"},
		{"calibrations", "state=planned", "state=canceled"},
		{"probe-costs", "day_from=2099-01-01&day_to=2099-01-01", "day_from=2099-01-01&day_to=2099-02-01"},
	} {
		t.Run(test.path, func(t *testing.T) {
			if status, _ := get(test.path, test.query, false); status != 401 {
				t.Fatalf("permission=%d", status)
			}
			if status, page := get(test.path, test.query, true); status != 200 || len(page.Items) != 50 || page.Next == "" {
				t.Fatalf("default page=%d/%d", status, len(page.Items))
			}
			status, first := get(test.path, test.query+"&limit=200", true)
			if status != 200 || len(first.Items) != 200 || first.Next == "" {
				t.Fatalf("first page=%d/%d", status, len(first.Items))
			}
			status, last := get(test.path, test.query+"&limit=200&cursor="+url.QueryEscape(first.Next), true)
			if status != 200 || len(last.Items) != 5 || last.Next != "" {
				t.Errorf("filtered 205 rows must end at 200+5: status=%d last=%d", status, len(last.Items))
			}
			seen := map[string]bool{}
			for _, item := range append(first.Items, last.Items...) {
				identity, err := json.Marshal(item)
				if err != nil {
					t.Fatal(err)
				}
				if seen[string(identity)] {
					t.Fatal("stable-tie cursor duplicated a record")
				}
				seen[string(identity)] = true
			}
			if status, _ := get(test.path, test.changed+"&limit=200&cursor="+url.QueryEscape(first.Next), true); status != 400 {
				t.Errorf("changed filter cursor accepted: status=%d", status)
			}
			for _, limit := range []string{"invalid", "0", "-1", "201", "999999999999999999999999999", "1&limit=2"} {
				if status, _ := get(test.path, "limit="+limit, true); status != 400 {
					t.Errorf("invalid limit %q accepted: %d", limit, status)
				}
			}
		})
	}
	for _, test := range []struct {
		path, query string
		count       int
	}{
		{"upstream-endpoints", "upstream_id=206", 5}, {"upstream-endpoints", "needs_review=true", 5},
		{"probe-secrets", "name_prefix=other", 1}, {"probe-executions", "upstream_id=206", 1}, {"probe-executions", "route_id=206", 1},
		{"probe-executions", "endpoint=count_tokens", 1}, {"probe-executions", "capability_state=unsupported", 1}, {"probe-executions", "error_class=rate_limited", 0},
		{"capabilities", "route_id=206", 1}, {"capabilities", "upstream_id=206", 0}, {"capabilities", "endpoint=count_tokens", 1}, {"capabilities", "expired=true", 1},
		{"reachability", "upstream_id=206", 1}, {"reachability", "current=false", 1},
		{"calibrations", "route_id=206", 1}, {"calibrations", "endpoint=count_tokens", 1},
		{"probe-costs", "origin=calibration_native", 1}, {"probe-costs", "endpoint=count_tokens&day_from=2099-01-01", 1}, {"probe-costs", "day_from=2099-02-01", 1}, {"probe-costs", "trigger=recovery", 0},
		{"probe-costs", "upstream_id=1", 1}, {"probe-costs", "route_id=1", 1},
	} {
		status, page := get(test.path, test.query, true)
		if status != 200 || len(page.Items) != test.count {
			t.Errorf("filter %s?%s status=%d count=%d want=%d", test.path, test.query, status, len(page.Items), test.count)
		}
	}
	for _, test := range []struct{ path, query string }{
		{"upstream-endpoints", "upstream_id=bad"}, {"upstream-endpoints", "endpoint=bogus"}, {"upstream-endpoints", "needs_review=1"},
		{"probe-executions", "route_id=0"}, {"probe-executions", "upstream_id=-1"}, {"probe-executions", "error_class=bogus"}, {"probe-executions", "capability_state=expired"}, {"probe-executions", "trigger=bogus"},
		{"capabilities", "state=expired"}, {"capabilities", "expired=1"}, {"reachability", "current=1"}, {"reachability", "state=bogus"},
		{"calibrations", "state=bogus"}, {"calibrations", "route_id=bad"}, {"probe-costs", "day_from=bad"}, {"probe-costs", "day_from=2099-02-01&day_to=2099-01-01"}, {"probe-costs", "origin=bogus"},
		{"probe-recipes", "limit=0"}, {"probe-recipes", "upstream_id=1&upstream_id=2"},
		{"client-probe-profiles", "limit=invalid"}, {"client-probe-profiles", "status=bogus"}, {"client-probe-profiles", "upstream_id=1&upstream_id=2"},
		{"probe-recipes/1/versions", "limit=1&limit=2"}, {"probe-recipes/1/versions", "origin=manual&origin=learned"},
	} {
		if status, _ := get(test.path, test.query, true); status != 400 {
			t.Errorf("invalid filter %s?%s accepted: %d", test.path, test.query, status)
		}
	}
}
