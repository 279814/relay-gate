package probe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/observationseq"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/probetemplate"
	"github.com/279814/relay-gate/internal/proxy"
	"github.com/279814/relay-gate/internal/sample"
	"github.com/279814/relay-gate/internal/store"
)

type countedAuthSecretStore struct {
	*store.Store
	reads atomic.Int64
}

func (s *countedAuthSecretStore) ResolveProbeSecret(ctx context.Context, name string) (probetemplate.ResolvedSecret, error) {
	s.reads.Add(1)
	return s.Store.ResolveProbeSecret(ctx, name)
}

func TestDeclaredAuthSecretRealHTTPAndCountTokensKeepUsedValuesPrivate(t *testing.T) {
	for _, kind := range []model.EndpointKind{model.EndpointMessages, model.EndpointCountTokens} {
		t.Run(string(kind), func(t *testing.T) {
			const credential = "fixture-declared-auth-secret-must-stay-private"
			var received atomic.Int64
			h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") == "Bearer "+credential && r.URL.Query().Get("api_key") == credential && r.Header.Get("X-Api-Key") == "" {
					received.Add(1)
				}
				w.Header().Set("Location", "https://example.test/next?opaque="+credential)
				if kind == model.EndpointCountTokens {
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"input_tokens":13}`)
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, anthropicSemanticBody())
			})
			if _, err := h.store.CreateProbeSecret("selected-auth", []byte(credential)); err != nil {
				t.Fatal(err)
			}
			endpoint, err := h.store.Endpoint(context.Background(), h.up.ID, kind)
			if err != nil {
				t.Fatal(err)
			}
			endpoint.LegacyCompatRealOnly = false
			endpoint.AuthProfile = model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: "probe:selected-auth"}
			endpoint.FixedQueryTemplate = "api_key={{SECRET:selected-auth}}"
			if err := h.store.UpdateEndpoint(endpoint, endpoint.Revision); err != nil {
				t.Fatal(err)
			}
			cfg := h.manager.cfg.(*livecfg.Source)
			cfg.Invalidate()
			if err := cfg.Refresh(); err != nil {
				t.Fatal(err)
			}
			settings, err := cfg.Settings()
			if err != nil {
				t.Fatal(err)
			}
			recorder := sample.NewRecorder(h.store, settings, cfg, discardLogger())
			defer recorder.Close()
			secrets := &countedAuthSecretStore{Store: h.store}
			targets := outbound.NewProvider(cfg, h.store, outbound.NewResolver(testHasher{}))
			handler := proxy.NewHandler(cfg, h.tracker, recorder, []string{"test-relay-key"}, discardLogger()).
				WithTargets(targets, secrets).WithObservers(h.manager).WithCountTokensCapability(h.caps)
			mux := http.NewServeMux()
			handler.Routes(mux)
			gate := httptest.NewServer(mux)
			defer gate.Close()
			request, err := http.NewRequest(http.MethodPost, gate.URL+kind.CanonicalPath(), strings.NewReader(`{"model":"claude-cal","messages":[],"stream":true}`))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("X-Api-Key", "test-relay-key")
			request.Header.Set("Content-Type", "application/json")
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != 200 || received.Load() != 1 {
				t.Fatalf("declared credential did not reach the native endpoint: status=%d received=%d err=%v", response.StatusCode, received.Load(), err)
			}
			if kind == model.EndpointMessages && string(body) != anthropicSemanticBody() {
				t.Fatal("credential tracing changed native SSE bytes")
			}
			if strings.Contains(response.Header.Get("Location"), credential) {
				t.Fatal("a Probe Secret escaped through an upstream URL header")
			}
			if secrets.reads.Load() != 1 {
				t.Fatalf("same query/Auth Secret was resolved more than once: %d", secrets.reads.Load())
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			release, err := handler.Quiesce(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			if err := recorder.Flush(ctx); err != nil {
				t.Fatal(err)
			}
			if err := h.manager.Flush(ctx); err != nil {
				t.Fatal(err)
			}
			rows, err := h.store.DB().Query(`SELECT out_url,out_headers,resp_headers,error FROM sample_attempt`)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			rowCount := 0
			for rows.Next() {
				rowCount++
				var url, requestHeaders, responseHeaders, failure string
				if err := rows.Scan(&url, &requestHeaders, &responseHeaders, &failure); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(fmt.Sprint(url, requestHeaders, responseHeaders, failure), credential) {
					t.Fatal("a Probe Secret escaped into sample metadata")
				}
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			if kind == model.EndpointMessages && rowCount == 0 {
				t.Fatal("native forwarding did not produce sample metadata")
			}
		})
	}
}

func TestManualProbeUsesDeclaredCredentialOnceAndRedactsReflectedFailure(t *testing.T) {
	const credential = "fixture-manual-auth-secret-must-stay-private"
	var received atomic.Int64
	h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer "+credential && r.URL.Query().Get("api_key") == credential {
			received.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintf(w, `{"error":{"type":"authentication_error","code":"%s"}}`, credential)
	})
	if _, err := h.store.CreateProbeSecret("manual-auth", []byte(credential)); err != nil {
		t.Fatal(err)
	}
	ep, err := h.store.Endpoint(context.Background(), h.up.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	ep.LegacyCompatRealOnly = false
	ep.AuthProfile = model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: "probe:manual-auth"}
	ep.FixedQueryTemplate = "api_key={{SECRET:manual-auth}}"
	if err := h.store.UpdateEndpoint(ep, ep.Revision); err != nil {
		t.Fatal(err)
	}
	secrets := &countedAuthSecretStore{Store: h.store}
	service := manualAuthProbeService(t, h, secrets)
	execution, err := service.RunManual(context.Background(), h.route.ID)
	if err != nil {
		t.Fatal(err)
	}
	if received.Load() != 1 || execution.StatusCode != http.StatusUnauthorized || execution.ErrorClass != model.ErrorAuthRejected {
		t.Fatalf("manual request did not use its declared credential: received=%d status=%d class=%s", received.Load(), execution.StatusCode, execution.ErrorClass)
	}
	if secrets.reads.Load() != 1 {
		t.Fatalf("manual query/Auth resolved the same credential %d times", secrets.reads.Load())
	}
	stored, err := h.store.GetProbeExecution(context.Background(), execution.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(execution.RedactedDetail, credential) || strings.Contains(stored.RedactedDetail, credential) {
		t.Fatal("reflected Probe Secret escaped into manual execution evidence")
	}
}

func manualAuthProbeService(t *testing.T, h *trafficHTTPHarness, secrets outbound.SecretSource) *Service {
	t.Helper()
	cfg, recipes := restoreTestDeps(h.store)
	if _, err := cfg.Bundle(); err != nil {
		t.Fatal(err)
	}
	transports := outbound.NewManager()
	t.Cleanup(transports.CloseIdleConnections)
	executor := NewExecutor(outbound.NewProvider(cfg, h.store, outbound.NewResolver(testHasher{})), secrets, recipes,
		ManagerTransports{Manager: transports}, NewExecutionOnlyRecorder(h.store), AlwaysOpenAdmission(), WallClock(), discardLogger())
	seq, err := observationseq.Open(context.Background(), h.store)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(seq.Close)
	scheduler := NewScheduler(cfg, nil, health.NewTracker(cfg), nil, discardLogger()).WithRecipes(recipes).WithExecutor(executor).WithSequencer(seq)
	return NewService(h.store, executor, nil, cfg, nil, nil).WithManualPreparer(scheduler)
}

func TestShortDeclaredCredentialsNeverReachHTTPUpstream(t *testing.T) {
	for _, path := range []string{"messages", "count_tokens", "manual"} {
		t.Run(path, func(t *testing.T) {
			var received atomic.Int64
			h := newTrafficHTTPHarness(t, func(http.ResponseWriter, *http.Request) { received.Add(1) })
			if _, err := h.store.CreateProbeSecret("short-auth", []byte("short-value")); err != nil {
				t.Fatal(err)
			}
			kind := model.EndpointMessages
			if path == "count_tokens" {
				kind = model.EndpointCountTokens
			}
			ep, err := h.store.Endpoint(context.Background(), h.up.ID, kind)
			if err != nil {
				t.Fatal(err)
			}
			ep.LegacyCompatRealOnly = false
			ep.AuthProfile = model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: "probe:short-auth"}
			if err := h.store.UpdateEndpoint(ep, ep.Revision); err != nil {
				t.Fatal(err)
			}
			cfg := h.manager.cfg.(*livecfg.Source)
			cfg.Invalidate()
			if err := cfg.Refresh(); err != nil {
				t.Fatal(err)
			}
			if path == "manual" {
				execution, err := manualAuthProbeService(t, h, h.store).RunManual(context.Background(), h.route.ID)
				if err != nil || execution.ErrorClass != model.ErrorConfig || execution.SentAtMS != 0 {
					t.Fatalf("short credential must produce an unsent config error: class=%s sent=%d err=%v", execution.ErrorClass, execution.SentAtMS, err)
				}
			} else {
				request, err := http.NewRequest(http.MethodPost, h.url+kind.CanonicalPath(), strings.NewReader(`{"model":"claude-cal","messages":[]}`))
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("X-Api-Key", "test-relay-key")
				response, err := http.DefaultClient.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, response.Body)
				response.Body.Close()
				want := http.StatusServiceUnavailable
				if kind == model.EndpointCountTokens {
					want = http.StatusOK
					if response.Header.Get("X-Relay-Count-Tokens") != "estimated" {
						t.Fatal("short credential did not use the local token estimate")
					}
				}
				if response.StatusCode != want {
					t.Fatalf("status=%d want=%d", response.StatusCode, want)
				}
			}
			if received.Load() != 0 {
				t.Fatal("short credential was sent to the HTTP upstream")
			}
		})
	}
}
