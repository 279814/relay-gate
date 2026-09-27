package proxy

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/router"
)

// routeConfigCaps records §6.5 route-local config_error marks per endpoint.
type routeConfigCaps struct {
	mu     sync.Mutex
	states map[int64]map[model.EndpointKind]model.CapabilityState
	marks  int
}

func (c *routeConfigCaps) Effective(_ model.RecipeScope, scopeID int64,
	endpoint model.EndpointKind, _ string) model.CapabilityState {
	c.mu.Lock()
	defer c.mu.Unlock()
	if st, ok := c.states[scopeID][endpoint]; ok {
		return st
	}
	return model.CapabilityUnknown
}

func (c *routeConfigCaps) MarkCountTokensUnsupported(int64, uint64, int) {}
func (c *routeConfigCaps) MarkCountTokensConfigError(int64, uint64, int) {}

func (c *routeConfigCaps) MarkRouteConfigError(routeID int64, _ uint64, endpoint model.EndpointKind) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.states == nil {
		c.states = map[int64]map[model.EndpointKind]model.CapabilityState{}
	}
	if c.states[routeID] == nil {
		c.states[routeID] = map[model.EndpointKind]model.CapabilityState{}
	}
	c.states[routeID][endpoint] = model.CapabilityConfigError
	c.marks++
}

const emptyKeyReqBody = `{"model":"claude-opus-5","max_tokens":1,"messages":[{"role":"user","content":"x"}]}`

// §6.5 / §7.2: an empty upstream credential is a route-local config_error.
// The Route is skipped (nothing sent), its Capability becomes config_error,
// and the request is served by the next Route instead of failing with 500.
func TestEmptyUpstreamKey_SkipsRouteAndServesNext(t *testing.T) {
	var emptyHits, goodHits atomic.Int32
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer sk-healthy-upstream-key" {
			goodHits.Add(1)
		} else {
			emptyHits.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"msg_1","type":"message"}`))
	})
	mn := &model.ModelName{ID: 1, Name: "claude-opus-5",
		Protocol: model.ProtoAnthropic, MatchMode: model.MatchExact, Enabled: true}
	empty := &model.Upstream{ID: 10, Name: "empty-key", BaseURL: hs.up.URL,
		APIKey: "", AuthStyle: model.AuthBearer, Enabled: true}
	good := &model.Upstream{ID: 11, Name: "healthy", BaseURL: hs.up.URL,
		APIKey: "sk-healthy-upstream-key", AuthStyle: model.AuthBearer, Enabled: true}
	hs.cfg.snap = router.BuildSnapshot([]*model.ModelName{mn},
		[]*model.Upstream{empty, good}, []*model.Route{
			{ID: 100, ModelNameID: 1, UpstreamID: 10, Priority: 1, Weight: 100, Enabled: true},
			{ID: 101, ModelNameID: 1, UpstreamID: 11, Priority: 2, Weight: 100, Enabled: true},
		})
	caps := &routeConfigCaps{}
	hs.h.WithCountTokensCapability(caps)

	rec := hs.serve(hs.anthropicRequest(emptyKeyReqBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 from the healthy Route; body=%s", rec.Code, rec.Body.String())
	}
	if n := goodHits.Load(); n != 1 {
		t.Fatalf("healthy upstream hits = %d, want 1", n)
	}
	if n := emptyHits.Load(); n != 0 {
		t.Fatalf("empty-key Route must not reach the wire, hits = %d", n)
	}
	if got := caps.Effective(model.RecipeScopeRoute, 100, model.EndpointMessages, ""); got != model.CapabilityConfigError {
		t.Fatalf("empty-key Route messages capability = %s, want config_error", got)
	}
	if got := caps.Effective(model.RecipeScopeRoute, 101, model.EndpointMessages, ""); got != model.CapabilityUnknown {
		t.Fatalf("healthy Route capability = %s, want unknown", got)
	}
	_, open, _ := hs.health.stats()
	if open != 0 {
		t.Fatalf("concurrency slots leaked: open = %d", open)
	}

	// Next request excludes the config_error Route at selection.
	rec2 := hs.serve(hs.anthropicRequest(emptyKeyReqBody))
	if rec2.Code != http.StatusOK {
		t.Fatalf("second status = %d, want 200", rec2.Code)
	}
	if caps.marks != 1 {
		t.Fatalf("config_error marks = %d, want 1 (second request should skip at selection)", caps.marks)
	}
	if n := goodHits.Load(); n != 2 {
		t.Fatalf("healthy upstream hits = %d, want 2", n)
	}
}

// Single empty-key Route: the client gets the documented no-route response,
// not a 500 and not the credential error text.
func TestEmptyUpstreamKey_OnlyRouteReturnsNoRoute(t *testing.T) {
	var hits atomic.Int32
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"msg_1","type":"message"}`))
	})
	hs.cfg.snap.Upstreams[10].APIKey = ""
	caps := &routeConfigCaps{}
	hs.h.WithCountTokensCapability(caps)

	rec := hs.serve(hs.anthropicRequest(emptyKeyReqBody))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 no-route; body=%s", rec.Code, rec.Body.String())
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("upstream hits = %d, want 0", n)
	}
	body := rec.Body.String()
	for _, leak := range []string{"api_key", "认证", "配置错误"} {
		if strings.Contains(body, leak) || strings.Contains(rec.Header().Get("X-Relay-Reason"), leak) {
			t.Fatalf("response leaks auth error text %q: header=%q body=%s",
				leak, rec.Header().Get("X-Relay-Reason"), body)
		}
	}
	if got := caps.Effective(model.RecipeScopeRoute, 100, model.EndpointMessages, ""); got != model.CapabilityConfigError {
		t.Fatalf("capability = %s, want config_error", got)
	}
}

// Without a Capability marker the Route is still skipped for this request.
func TestEmptyUpstreamKey_SkipsWithoutMarker(t *testing.T) {
	hs := newHarness(t, nil)
	hs.cfg.snap.Upstreams[10].APIKey = ""

	rec := hs.serve(hs.anthropicRequest(emptyKeyReqBody))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 no-route; body=%s", rec.Code, rec.Body.String())
	}
}
