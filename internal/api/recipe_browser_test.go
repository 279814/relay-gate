package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/runstate"
	"github.com/279814/relay-gate/internal/web"
)

// Opt-in real-browser fixture. Only loopback listeners, temporary SQLite and
// synthetic credentials are used. This endpoint is never built into the app.
func TestRecipeAdminBrowserFixture(t *testing.T) {
	if os.Getenv("RELAY_RECIPE_BROWSER_FIXTURE") != "1" {
		t.Skip("opt-in browser fixture")
	}
	s, _, source, coordinator, _, _, _, route := recipeHTTPFixture(t)
	controller, err := runstate.NewController(s.st)
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	if err := controller.BindSyntheticController(coordinator); err != nil {
		t.Fatal(err)
	}
	s.WithRunState(controller).WithHealth(health.NewTracker(source), health.NewReachabilityTracker(source))
	now := time.Now().UnixMilli()
	sample := &model.Sample{UpstreamID: route.UpstreamID, RouteID: route.ID, ModelNameID: route.ModelNameID, ModelIn: "test-model", ModelOut: "test-model",
		Endpoint: "/v1/chat/completions", InMethod: "POST", InPath: "/v1/chat/completions", InHeaders: http.Header{"Content-Type": {"application/json"}, "User-Agent": {"OpenAI/Python/1.1.0"}, "Authorization": {"Bearer fixture-private-value"}},
		InBody: []byte(`{"model":"test-model","messages":[{"role":"user","content":"fixture business text"}],"stream":false,"max_tokens":2}`),
		TSRecv: now, TSSent: now, TSFirstByte: now + 1, TSDone: now + 2, RespStatus: 200, Outcome: model.OutcomeOK}
	if err := s.st.InsertSample(sample); err != nil {
		t.Fatal(err)
	}
	profile := &model.ClientProbeProfile{UpstreamID: route.UpstreamID, Endpoint: model.EndpointChatCompletions, ClientFamily: "generic", ShapeHash: "browser-fixture-shape", SeenCount: 1}
	if err := s.st.CreateClientProfileCandidate(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	source.Invalidate()
	if err := source.Refresh(); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.Handle("/admin/api/", s.Routes(testAdminPW))
	mux.Handle("/admin/", web.Handler())
	server := httptest.NewServer(mux)
	defer server.Close()
	fmt.Printf("RECIPE_BROWSER_URL=%s/admin/\nRECIPE_BROWSER_FIXTURE_PASSWORD=%s\nRECIPE_BROWSER_ROUTE_ID=%d\n", server.URL, testAdminPW, route.ID)
	done := os.Getenv("RELAY_RECIPE_BROWSER_DONE_FILE")
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(15 * time.Minute)
	defer timeout.Stop()
	for {
		select {
		case <-timeout.C:
			t.Fatal("browser fixture timed out")
		case <-ticker.C:
			if done != "" {
				if _, err := os.Stat(done); err == nil {
					return
				}
			}
		}
	}
}
