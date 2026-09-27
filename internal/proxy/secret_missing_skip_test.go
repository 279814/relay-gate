package proxy

import (
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/store"
)

const (
	missingSecretName = "deleted-site-token"
	presentSecretName = "present-site-token"
	presentSecretVal  = "tok-present-secret-value"
)

// secretStore opens a real Store holding presentSecretName, plus a Secret
// named missingSecretName that is created and then deleted.
func secretStore(t *testing.T) *store.Store {
	t.Helper()
	cipher, err := store.NewCipher("test-encryption-key-32-bytes-long")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "secrets.db"), cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.CreateProbeSecret(presentSecretName, []byte(presentSecretVal)); err != nil {
		t.Fatal(err)
	}
	gone, err := st.CreateProbeSecret(missingSecretName, []byte("tok-deleted-secret-value"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteProbeSecret(gone.ID, gone.Revision); err != nil {
		t.Fatal(err)
	}
	return st
}

// setupSecretRoutes: Route 100 (Upstream 10) references missingSecretName in
// its fixed query; Route 101 (Upstream 11) references presentSecretName.
func setupSecretRoutes(t *testing.T, hs *harness, secrets outbound.SecretSource, twoRoutes bool) *routeConfigCaps {
	t.Helper()
	mn := &model.ModelName{ID: 1, Name: "claude-opus-5",
		Protocol: model.ProtoAnthropic, MatchMode: model.MatchExact, Enabled: true}
	ups := []*model.Upstream{{ID: 10, Name: "missing-secret", BaseURL: hs.up.URL,
		APIKey: badURLKey, AuthStyle: model.AuthBearer, Enabled: true}}
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
	hs.cfg.settings.RetryMaxAttempts = 1
	provider := outbound.NewProvider(perUpstreamEndpoints{
		base: testEndpoints{cfg: hs.cfg},
		queries: map[int64]string{
			10: "token={{SECRET:" + missingSecretName + "}}",
			11: "token={{SECRET:" + presentSecretName + "}}",
		},
	}, nil, outbound.NewResolver(testHasher{}))
	hs.h = hs.h.WithTargets(provider, secrets)
	caps := &routeConfigCaps{}
	hs.h.WithCountTokensCapability(caps)
	return caps
}

// §6.5: a named Secret this Route's URL references that is not in the store
// is route-local config_error — skip without contacting that upstream and
// serve from the next Route, whose existing Secret still resolves.
func TestMissingSecret_SkipsRouteAndServesNext(t *testing.T) {
	var badHits, goodHits atomic.Int32
	var goodQuery atomic.Value
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer "+goodURLKey {
			goodHits.Add(1)
			goodQuery.Store(r.URL.RawQuery)
		} else {
			badHits.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"msg_1","type":"message"}`))
	})
	caps := setupSecretRoutes(t, hs, secretStore(t), true)

	rec := hs.serve(hs.anthropicRequest(emptyKeyReqBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 from the healthy Route; body=%s", rec.Code, rec.Body.String())
	}
	if n := badHits.Load(); n != 0 {
		t.Fatalf("missing-Secret Route must not reach the wire, hits = %d", n)
	}
	if n := goodHits.Load(); n != 1 {
		t.Fatalf("healthy upstream hits = %d, want 1", n)
	}
	if q, _ := goodQuery.Load().(string); !strings.HasPrefix(q, "token="+presentSecretVal) {
		t.Fatalf("existing Secret must still resolve, query = %q", q)
	}
	if got := caps.Effective(model.RecipeScopeRoute, 100, model.EndpointMessages, ""); got != model.CapabilityConfigError {
		t.Fatalf("missing-Secret Route capability = %s, want config_error", got)
	}
	if got := caps.Effective(model.RecipeScopeRoute, 101, model.EndpointMessages, ""); got != model.CapabilityUnknown {
		t.Fatalf("healthy Route capability = %s, want unknown", got)
	}
}

// Only the missing-Secret Route: 503 no-route, nothing sent, and neither the
// body nor X-Relay-Reason names the Secret.
func TestMissingSecret_OnlyRouteReturnsNoRoute(t *testing.T) {
	var badHits, goodHits atomic.Int32
	hs := newHarness(t, countByKey(&badHits, &goodHits))
	caps := setupSecretRoutes(t, hs, secretStore(t), false)

	rec := hs.serve(hs.anthropicRequest(emptyKeyReqBody))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 no-route; body=%s", rec.Code, rec.Body.String())
	}
	if n := badHits.Load() + goodHits.Load(); n != 0 {
		t.Fatalf("upstream hits = %d, want 0", n)
	}
	body := rec.Body.String()
	reason := rec.Header().Get("X-Relay-Reason")
	for _, leak := range []string{missingSecretName, "SECRET", "{{", "tok-", "Probe Secret", badURLKey} {
		if strings.Contains(body, leak) || strings.Contains(reason, leak) {
			t.Fatalf("response leaks %q: header=%q body=%s", leak, reason, body)
		}
	}
	if got := caps.Effective(model.RecipeScopeRoute, 100, model.EndpointMessages, ""); got != model.CapabilityConfigError {
		t.Fatalf("capability = %s, want config_error", got)
	}
}

// A Secret store read failure is not "this name does not exist": the request
// fails as a whole, does not skip to the next Route, and marks nothing.
func TestSecretStoreReadError_FailsRequestWithoutSkip(t *testing.T) {
	var badHits, goodHits atomic.Int32
	hs := newHarness(t, countByKey(&badHits, &goodHits))
	st := secretStore(t)
	caps := setupSecretRoutes(t, hs, st, true)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	rec := hs.serve(hs.anthropicRequest(emptyKeyReqBody))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for a store read failure; body=%s", rec.Code, rec.Body.String())
	}
	if n := badHits.Load() + goodHits.Load(); n != 0 {
		t.Fatalf("upstream hits = %d, want 0 (no skip to the next Route)", n)
	}
	if caps.marks != 0 {
		t.Fatalf("config_error marks = %d, want 0 for a store read failure", caps.marks)
	}
	if strings.Contains(rec.Body.String(), missingSecretName) {
		t.Fatalf("body leaks Secret name: %s", rec.Body.String())
	}
}
