package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/router"
)

// perUpstreamEndpoints gives each Upstream its own FixedQueryTemplate so one
// Route can carry a broken URL while its sibling stays healthy.
type perUpstreamEndpoints struct {
	base    testEndpoints
	queries map[int64]string
}

func (source perUpstreamEndpoints) Endpoint(ctx context.Context, upstreamID int64,
	kind model.EndpointKind) (*model.UpstreamEndpoint, error) {

	endpoint, err := source.base.Endpoint(ctx, upstreamID, kind)
	if err != nil {
		return nil, err
	}
	endpoint.FixedQueryTemplate = source.queries[upstreamID]
	return endpoint, nil
}

const (
	badURLKey  = "sk-broken-url-upstream-key"
	goodURLKey = "sk-healthy-upstream-key"
)

// urlConfigCase is one §6.5 "this Route's URL / Auth Secret configuration
// error" on Upstream 10. None of them may reach the wire.
type urlConfigCase struct {
	name    string
	baseURL string // empty = the harness upstream
	query   string
}

func urlConfigCases() []urlConfigCase {
	return []urlConfigCase{
		{name: "malformed template", query: "key={{UPSTREAM_API_KEY"},
		{name: "unknown placeholder", query: "key={{UPSTREAM_API_KE}}"},
		{name: "bad base URL", baseURL: "not-a-url"},
		{name: "missing Secret source", query: "key={{SECRET:site-token}}"},
		{name: "unsupported placeholder", query: "model={{UPSTREAM_MODEL}}"},
	}
}

func (tc urlConfigCase) setup(t *testing.T, hs *harness, twoRoutes bool) *routeConfigCaps {
	t.Helper()
	baseURL := hs.up.URL
	if tc.baseURL != "" {
		baseURL = tc.baseURL
	}
	mn := &model.ModelName{ID: 1, Name: "claude-opus-5",
		Protocol: model.ProtoAnthropic, MatchMode: model.MatchExact, Enabled: true}
	bad := &model.Upstream{ID: 10, Name: "broken-url", BaseURL: baseURL,
		APIKey: badURLKey, AuthStyle: model.AuthBearer, Enabled: true}
	ups := []*model.Upstream{bad}
	routes := []*model.Route{
		{ID: 100, ModelNameID: 1, UpstreamID: 10, Priority: 1, Weight: 100, Enabled: true},
	}
	if twoRoutes {
		ups = append(ups, &model.Upstream{ID: 11, Name: "healthy", BaseURL: hs.up.URL,
			APIKey: goodURLKey, AuthStyle: model.AuthBearer, Enabled: true})
		routes = append(routes,
			&model.Route{ID: 101, ModelNameID: 1, UpstreamID: 11, Priority: 2, Weight: 100, Enabled: true})
	}
	hs.cfg.snap = router.BuildSnapshot([]*model.ModelName{mn}, ups, routes)
	// Route-local skips must not consume network attempts (§6.5).
	hs.cfg.settings.RetryMaxAttempts = 1
	provider := outbound.NewProvider(perUpstreamEndpoints{
		base:    testEndpoints{cfg: hs.cfg},
		queries: map[int64]string{10: tc.query},
	}, nil, outbound.NewResolver(testHasher{}))
	hs.h = hs.h.WithTargets(provider, nil)
	caps := &routeConfigCaps{}
	hs.h.WithCountTokensCapability(caps)
	return caps
}

func countByKey(bad, good *atomic.Int32) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer "+goodURLKey {
			good.Add(1)
		} else {
			bad.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"msg_1","type":"message"}`))
	}
}

// §6.5: a Route whose URL or Auth Secret configuration is broken is
// route-local — skip it without contacting that upstream, mark config_error,
// and serve the request from the next Route.
func TestURLConfigError_SkipsRouteAndServesNext(t *testing.T) {
	for _, tc := range urlConfigCases() {
		t.Run(tc.name, func(t *testing.T) {
			var badHits, goodHits atomic.Int32
			hs := newHarness(t, countByKey(&badHits, &goodHits))
			caps := tc.setup(t, hs, true)

			rec := hs.serve(hs.anthropicRequest(emptyKeyReqBody))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 from the healthy Route; body=%s", rec.Code, rec.Body.String())
			}
			if n := goodHits.Load(); n != 1 {
				t.Fatalf("healthy upstream hits = %d, want 1", n)
			}
			if n := badHits.Load(); n != 0 {
				t.Fatalf("broken-URL Route must not reach the wire, hits = %d", n)
			}
			if got := caps.Effective(model.RecipeScopeRoute, 100, model.EndpointMessages, ""); got != model.CapabilityConfigError {
				t.Fatalf("broken-URL Route capability = %s, want config_error", got)
			}
			if got := caps.Effective(model.RecipeScopeRoute, 101, model.EndpointMessages, ""); got != model.CapabilityUnknown {
				t.Fatalf("healthy Route capability = %s, want unknown", got)
			}
			if _, open, _ := hs.health.stats(); open != 0 {
				t.Fatalf("concurrency slots leaked: open = %d", open)
			}
		})
	}
}

// Only the broken Route: documented no-route 503 with no template, secret
// name or URL text in the body or X-Relay-Reason.
func TestURLConfigError_OnlyRouteReturnsNoRoute(t *testing.T) {
	for _, tc := range urlConfigCases() {
		t.Run(tc.name, func(t *testing.T) {
			var badHits, goodHits atomic.Int32
			hs := newHarness(t, countByKey(&badHits, &goodHits))
			caps := tc.setup(t, hs, false)

			rec := hs.serve(hs.anthropicRequest(emptyKeyReqBody))
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503 no-route; body=%s", rec.Code, rec.Body.String())
			}
			if n := badHits.Load() + goodHits.Load(); n != 0 {
				t.Fatalf("upstream hits = %d, want 0", n)
			}
			body := rec.Body.String()
			reason := rec.Header().Get("X-Relay-Reason")
			for _, leak := range []string{"{{", "}}", "SECRET", "site-token", "UPSTREAM", "key=",
				"not-a-url", "base_url", "占位符", "模板", "配置错误", badURLKey} {
				if strings.Contains(body, leak) || strings.Contains(reason, leak) {
					t.Fatalf("response leaks config text %q: header=%q body=%s", leak, reason, body)
				}
			}
			if got := caps.Effective(model.RecipeScopeRoute, 100, model.EndpointMessages, ""); got != model.CapabilityConfigError {
				t.Fatalf("capability = %s, want config_error", got)
			}
		})
	}
}

// A client that already went away does not continue to the next Route.
func TestURLConfigError_DisconnectedClientDoesNotContinue(t *testing.T) {
	var badHits, goodHits atomic.Int32
	hs := newHarness(t, countByKey(&badHits, &goodHits))
	urlConfigCases()[0].setup(t, hs, true)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	hs.serve(hs.anthropicRequest(emptyKeyReqBody).WithContext(ctx))
	if n := badHits.Load() + goodHits.Load(); n != 0 {
		t.Fatalf("upstream hits = %d after client disconnect, want 0", n)
	}
}

// A transport failure is a network Attempt, not a URL configuration error:
// it is not skipped locally (so retry_max_attempts=1 stops here) and the
// Route is not marked config_error.
func TestURLConfigError_TransportErrorIsNotConfigSkip(t *testing.T) {
	var badHits, goodHits atomic.Int32
	hs := newHarness(t, countByKey(&badHits, &goodHits))
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	caps := urlConfigCase{name: "connection refused", baseURL: deadURL}.setup(t, hs, true)

	rec := hs.serve(hs.anthropicRequest(emptyKeyReqBody))
	if rec.Code == http.StatusOK {
		t.Fatalf("status = 200; a transport error must not be skipped like a config error")
	}
	if n := goodHits.Load(); n != 0 {
		t.Fatalf("healthy upstream hits = %d, want 0 (retry_max_attempts=1)", n)
	}
	if caps.marks != 0 {
		t.Fatalf("config_error marks = %d, want 0 for a transport error", caps.marks)
	}
}
