package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
)

// Stored proxy URLs the transport refuses to build a pool for. Rows saved
// before save-time validation required a host can still carry these.
func badProxyURLs() map[string]string {
	return map[string]string{
		"no host with credentials": "http://proxyuser:proxysecret@",
		"no host":                  "http://",
		"malformed":                "http://proxyuser:proxysecret@[::1",
	}
}

func setupProxyRoutes(t *testing.T, hs *harness, proxyURL string, twoRoutes bool) *routeConfigCaps {
	t.Helper()
	caps := urlConfigCase{name: "proxy"}.setup(t, hs, twoRoutes)
	hs.cfg.snap.Upstreams[10].ProxyURL = proxyURL
	return caps
}

func closedAddr(t *testing.T) string {
	t.Helper()
	dead := httptest.NewServer(http.NotFoundHandler())
	addr := dead.Listener.Addr().String()
	dead.Close()
	return addr
}

// §6.5: an Upstream whose proxy_url cannot build a connection pool is a
// route-local network configuration error — skip it without contacting that
// upstream, mark config_error, and serve the request from the next Route.
func TestProxyPoolConfigError_SkipsRouteAndServesNext(t *testing.T) {
	for name, proxyURL := range badProxyURLs() {
		t.Run(name, func(t *testing.T) {
			var badHits, goodHits atomic.Int32
			hs := newHarness(t, countByKey(&badHits, &goodHits))
			caps := setupProxyRoutes(t, hs, proxyURL, true)

			rec := hs.serve(hs.anthropicRequest(emptyKeyReqBody))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 from the healthy Route; body=%s", rec.Code, rec.Body.String())
			}
			if n := goodHits.Load(); n != 1 {
				t.Fatalf("healthy upstream hits = %d, want 1", n)
			}
			if n := badHits.Load(); n != 0 {
				t.Fatalf("bad-proxy Route must not reach the wire, hits = %d", n)
			}
			if got := caps.Effective(model.RecipeScopeRoute, 100, model.EndpointMessages, ""); got != model.CapabilityConfigError {
				t.Fatalf("bad-proxy Route capability = %s, want config_error", got)
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

// Only the bad-proxy Route: documented no-route 503 with no proxy URL or
// credential text in the body or X-Relay-Reason.
func TestProxyPoolConfigError_OnlyRouteReturnsNoRoute(t *testing.T) {
	for name, proxyURL := range badProxyURLs() {
		t.Run(name, func(t *testing.T) {
			var badHits, goodHits atomic.Int32
			hs := newHarness(t, countByKey(&badHits, &goodHits))
			caps := setupProxyRoutes(t, hs, proxyURL, false)

			rec := hs.serve(hs.anthropicRequest(emptyKeyReqBody))
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503 no-route; body=%s", rec.Code, rec.Body.String())
			}
			if n := badHits.Load() + goodHits.Load(); n != 0 {
				t.Fatalf("upstream hits = %d, want 0", n)
			}
			body := rec.Body.String()
			reason := rec.Header().Get("X-Relay-Reason")
			for _, leak := range []string{"proxyuser", "proxysecret", "proxy_url", "http://",
				"scheme://", "[::1", "配置错误", badURLKey} {
				if strings.Contains(body, leak) || strings.Contains(reason, leak) {
					t.Fatalf("response leaks proxy text %q: header=%q body=%s", leak, reason, body)
				}
			}
			if got := caps.Effective(model.RecipeScopeRoute, 100, model.EndpointMessages, ""); got != model.CapabilityConfigError {
				t.Fatalf("capability = %s, want config_error", got)
			}
		})
	}
}

// A well-formed proxy that refuses the connection builds a pool fine; the
// failure happens in RoundTrip and is a connect failure, not config_error.
func TestProxyPoolConfigError_RefusedProxyIsConnectError(t *testing.T) {
	proxyURL := "http://proxyuser:proxysecret@" + closedAddr(t)

	manager := outbound.NewManager()
	t.Cleanup(manager.CloseIdleConnections)
	tr, err := manager.Transport(outbound.NetworkConfig{
		UpstreamID: 1, ProxyURL: proxyURL, NetworkRevision: 1, ConnectTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("well-formed proxy must build a pool: %v", err)
	}
	f := &Forwarder{Transport: tr, Timeouts: fastTimeouts()}
	res := f.Forward(context.Background(), httptest.NewRecorder(), "POST",
		"http://upstream.invalid/v1/messages", http.Header{}, []byte("{}"))
	if !errors.Is(res.Err, ErrConnect) {
		t.Fatalf("refused proxy: want ErrConnect, got %v", res.Err)
	}

	var badHits, goodHits atomic.Int32
	hs := newHarness(t, countByKey(&badHits, &goodHits))
	caps := setupProxyRoutes(t, hs, proxyURL, true)
	rec := hs.serve(hs.anthropicRequest(emptyKeyReqBody))
	if rec.Code == http.StatusOK {
		t.Fatalf("status = 200; a refused proxy is a network Attempt, not a config skip")
	}
	if n := goodHits.Load(); n != 0 {
		t.Fatalf("healthy upstream hits = %d, want 0 (retry_max_attempts=1)", n)
	}
	if caps.marks != 0 {
		t.Fatalf("config_error marks = %d, want 0 for a refused proxy", caps.marks)
	}
}

// A missing transport manager is not this Upstream's configuration: it stays
// a request-global 500 and is not recorded as config_error.
func TestProxyPoolConfigError_MissingManagerIsNotRouteSkip(t *testing.T) {
	var badHits, goodHits atomic.Int32
	hs := newHarness(t, countByKey(&badHits, &goodHits))
	caps := setupProxyRoutes(t, hs, "", true)
	hs.h.transports = nil

	rec := hs.serve(hs.anthropicRequest(emptyKeyReqBody))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	if n := badHits.Load() + goodHits.Load(); n != 0 {
		t.Fatalf("upstream hits = %d, want 0", n)
	}
	if caps.marks != 0 {
		t.Fatalf("config_error marks = %d, want 0", caps.marks)
	}
}
