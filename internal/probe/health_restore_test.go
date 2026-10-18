package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/proxy"
	"github.com/279814/relay-gate/internal/store"
	"github.com/279814/relay-gate/internal/transform"
)

func TestColdStartLegacyNegativeRequiresRecoveryWithoutInventingEvidence(t *testing.T) {
	for _, state := range []model.HealthState{model.StateDead, model.StateRecovering} {
		t.Run(string(state), func(t *testing.T) {
			st := calibrationTestStore(t)
			_, _, route := seedCalibrationRoute(t, st)
			if err := st.SaveRouteHealth([]*store.RouteHealth{{RouteID: route.ID, State: state, ConsecutiveOK: 1, ConsecutiveFail: 8, LastErrAt: route.CreatedAt, LastError: "legacy unverified failure"}}); err != nil {
				t.Fatal(err)
			}
			path := st.DatabasePath()
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			cipher, _ := store.NewCipher("calibration-test-passphrase-16")
			reopened, err := store.Open(path, cipher)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			cfg, _ := restoreTestDeps(reopened)
			tracker := health.NewTracker(cfg)
			if _, err := RestoreRouteHealth(context.Background(), tracker, reopened, cfg); err != nil {
				t.Fatal(err)
			}
			got := tracker.Status(route.ID)
			if got.State != model.StateRecovering || got.ConsecutiveOK != 0 || got.ConsecutiveFail != 0 || got.CooldownUntil != 0 || got.LastError != "" {
				t.Fatalf("legacy negative bypassed recovery or invented current evidence: %+v", got)
			}
		})
	}
}

func TestRestoredNegativeRequiresOneRealRecoveryAndOldAliveIsDemoted(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy=%t", legacy), func(t *testing.T) {
			var healthy atomic.Bool
			var recoveryHits atomic.Int32
			entered, release := make(chan struct{}, 2), make(chan struct{})
			resume := func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}
			defer resume()
			h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, r *http.Request) {
				drainBody(r)
				if !healthy.Load() {
					w.WriteHeader(503)
					io.WriteString(w, `{"error":{"type":"server_error"}}`)
					return
				}
				recoveryHits.Add(1)
				entered <- struct{}{}
				<-release
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"type":"message","content":[{"type":"text","text":"recovered"}]}`)
			})
			settings, revision, err := h.store.GetSettingsWithRevision()
			if err != nil {
				t.Fatal(err)
			}
			settings.FailThreshold = 1
			if _, err := h.store.SaveSettingsWithRevision(settings, revision); err != nil {
				t.Fatal(err)
			}
			source := h.manager.cfg.(*livecfg.Source)
			if err := source.Refresh(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if !legacy {
				if status, _ := h.requestProtocol(t, model.ProtoAnthropic); status != 503 {
					t.Fatalf("initial negative status=%d", status)
				}
				flushRestorationTraffic(t, ctx, h.handler, h.manager)
				flushHealthSnapshot(h.tracker, h.store)
			} else {
				if err := h.store.SaveRouteHealth([]*store.RouteHealth{{RouteID: h.route.ID, State: model.StateDead, LastErrAt: time.Now().UnixMilli(), ConsecutiveFail: 99, LastError: "old unverified"}}); err != nil {
					t.Fatal(err)
				}
			}
			cfg, _ := restoreTestDeps(h.store)
			fresh := health.NewTracker(cfg)
			if n, err := RestoreRouteHealth(ctx, fresh, h.store, cfg); err != nil || n != 1 {
				t.Fatalf("restore=%d %v", n, err)
			}
			if legacy && fresh.Status(h.route.ID).RecoverySource != "legacy_unverified" {
				t.Fatal("legacy provenance was not visible")
			}
			healthy.Store(true)
			h.manager.Close()
			caps := NewCapabilityRegistry(cfg).WithRouteGeneration(fresh)
			reach := health.NewReachabilityTracker(cfg)
			manager := NewTrafficObserverManager(cfg, h.manager.seq, NewResultRecorder(h.store, health.NewObservationReducer(nil), reach, caps), discardLogger()).WithHealthTracker(fresh)
			workerCtx, stopWorkers := context.WithCancel(context.Background())
			workersDone := make(chan struct{})
			go func() { manager.Run(workerCtx); close(workersDone) }()
			t.Cleanup(func() { stopWorkers(); <-workersDone })
			gate := health.NewRecoveryGate()
			handler := proxy.NewHandler(cfg, fresh, nil, []string{"test-relay-key"}, discardLogger()).WithRunState(fixtureController(t, h.store)).WithTargets(outbound.NewProvider(cfg, h.store, outbound.NewResolver(testHasher{})), h.store).WithObservers(manager).WithRecoveryGate(gate)
			mux := http.NewServeMux()
			handler.Routes(mux)
			front := httptest.NewServer(mux)
			defer front.Close()
			defer resume()
			defer handler.CloseIdleConnections()
			send := func() (int, string, error) {
				request, _ := http.NewRequest(http.MethodPost, front.URL+"/v1/messages", strings.NewReader(`{"model":"claude-cal","messages":[]}`))
				request.Header.Set("X-Api-Key", "test-relay-key")
				response, err := (&http.Client{Timeout: 3 * time.Second}).Do(request)
				if err != nil {
					return 0, "", err
				}
				defer response.Body.Close()
				_, err = io.Copy(io.Discard, response.Body)
				return response.StatusCode, response.Header.Get("Retry-After"), err
			}
			done := make(chan error, 1)
			go func() {
				status, _, err := send()
				if err == nil && status != 200 {
					err = fmt.Errorf("recovery status=%d", status)
				}
				done <- err
			}()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("restored route never entered a real recovery")
			}
			if status, retry, err := send(); err != nil || status != 503 || retry == "" || recoveryHits.Load() != 1 {
				t.Fatalf("cold negative bypassed single-flight: status=%d retry=%s hits=%d err=%v", status, retry, recoveryHits.Load(), err)
			}
			resume()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			flushRestorationTraffic(t, ctx, handler, manager)
			if fresh.State(h.route.ID) != model.StateAlive || gate.InFlight(h.route.ID) || len(fresh.Snapshot()) != 0 {
				t.Fatalf("real recovery did not restore/release: %+v gate=%t", fresh.Status(h.route.ID), gate.InFlight(h.route.ID))
			}
			flushHealthSnapshot(fresh, h.store)
			nextCfg, _ := restoreTestDeps(h.store)
			next := health.NewTracker(nextCfg)
			if n, err := RestoreRouteHealth(ctx, next, h.store, nextCfg); err != nil || n != 0 || next.State(h.route.ID) != model.StateUnknown {
				t.Fatalf("old alive survived: n=%d state=%s err=%v", n, next.State(h.route.ID), err)
			}
		})
	}
}

func flushHealthSnapshot(tracker *health.Tracker, st *store.Store) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	health.NewPersister(tracker, st, discardLogger()).Run(ctx)
}

func TestOldTransformHealthCannotReturnAcrossPublishOrRollbackAndColdStart(t *testing.T) {
	for _, window := range []string{"before SQL", "after SQL"} {
		for _, action := range []string{"publish", "rollback"} {
			t.Run(window+"/"+action, func(t *testing.T) {
				ctx := context.Background()
				entered, release := make(chan struct{}), make(chan struct{})
				resume := func() {
					select {
					case <-release:
					default:
						close(release)
					}
				}
				defer resume()
				h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, r *http.Request) {
					drainBody(r)
					if window == "before SQL" {
						close(entered)
						<-release
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(503)
					io.WriteString(w, `{"error":{"type":"server_error"}}`)
				})
				source := h.manager.cfg.(*livecfg.Source)
				settings, revision, err := h.store.GetSettingsWithRevision()
				if err != nil {
					t.Fatal(err)
				}
				settings.FailThreshold = 1
				if _, err := h.store.SaveSettingsWithRevision(settings, revision); err != nil {
					t.Fatal(err)
				}
				registry := transform.NewRegistry(8).WithPersist(h.store)
				set, err := registry.CreateSet("late-transform")
				if err != nil {
					t.Fatal(err)
				}
				ep, err := h.store.Endpoint(ctx, h.up.ID, model.EndpointMessages)
				if err != nil {
					t.Fatal(err)
				}
				publish := func(value string) int64 {
					t.Helper()
					if _, err := registry.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindSetHeader, Name: "X-Started-Transform", Value: value}}, transform.FailClosed, transform.FailOpen, ""); err != nil {
						t.Fatal(err)
					}
					_, v, err := registry.PublishSnapshot(set.ID, h.route.ID, ep.ID)
					if err != nil {
						t.Fatal(err)
					}
					return v.ID
				}
				old := publish("A")
				started := "A"
				if action == "rollback" {
					publish("B")
					started = "B"
				}
				if err := source.Refresh(); err != nil {
					t.Fatal(err)
				}
				h.handler.WithTransforms(registry)
				generation := h.tracker.EnsureGeneration(h.route.ID)
				before := h.tracker.Status(h.route.ID)
				if window == "after SQL" {
					h.manager.record = NewResultRecorder(delayedCommittedObservation{h.store, entered, release}, health.NewObservationReducer(nil), h.reach, h.caps)
				}
				req, _ := http.NewRequest(http.MethodPost, h.url+"/v1/messages", strings.NewReader(`{"model":"claude-cal","messages":[]}`))
				req.Header.Set("X-Api-Key", "test-relay-key")
				type clientResult struct {
					status int
					marker string
					err    error
				}
				client := make(chan clientResult, 1)
				go func() {
					response, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
					if err != nil {
						client <- clientResult{err: err}
						return
					}
					_, err = io.ReadAll(response.Body)
					response.Body.Close()
					client <- clientResult{response.StatusCode, response.Header.Get("X-Started-Transform"), err}
				}()
				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					t.Fatal("observation did not reach the delayed boundary")
				}
				if action == "publish" {
					publish("C")
				} else {
					if _, err := registry.Rollback(h.route.ID, ep.ID, old); err != nil {
						t.Fatal(err)
					}
				}
				source.Invalidate()
				if err := source.Refresh(); err != nil {
					t.Fatal(err)
				}
				if h.tracker.GenerationOf(h.route.ID) != generation {
					t.Fatal("test must independently cover config identity without a Forget")
				}
				resume()
				got := <-client
				if got.err != nil || got.status != 503 || got.marker != started {
					t.Fatalf("request did not retain its started transform: %+v want=%s", got, started)
				}
				wait, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				flushRestorationTraffic(t, wait, h.handler, h.manager)
				if after := h.tracker.Status(h.route.ID); !reflect.DeepEqual(before, after) {
					t.Fatalf("old transform negative poisoned current health: before=%+v after=%+v", before, after)
				}
				flush, cancelFlush := context.WithCancel(ctx)
				cancelFlush()
				health.NewPersister(h.tracker, h.store, discardLogger()).Run(flush)
				h.manager.Close()
				path := h.store.DatabasePath()
				if err := h.store.Close(); err != nil {
					t.Fatal(err)
				}
				cipher, _ := store.NewCipher("calibration-test-passphrase-16")
				reopened, err := store.Open(path, cipher)
				if err != nil {
					t.Fatal(err)
				}
				defer reopened.Close()
				cfg, _ := restoreTestDeps(reopened)
				fresh := health.NewTracker(cfg)
				if n, err := RestoreRouteHealth(ctx, fresh, reopened, cfg); err != nil || n != 0 || fresh.State(h.route.ID) != model.StateUnknown {
					t.Fatalf("cold start revived old transform negative: n=%d state=%s err=%v", n, fresh.State(h.route.ID), err)
				}
			})
		}
	}
}

func boundNegativeSnapshot(t *testing.T, setup ...func(*store.Store, *model.Upstream, *model.ModelName, *model.Route)) (*store.Store, *model.Upstream, *model.ModelName, *model.Route, *store.RouteHealth) {
	t.Helper()
	st := calibrationTestStore(t)
	up, mn, route := seedCalibrationRoute(t, st)
	for _, prepare := range setup {
		prepare(st, up, mn, route)
	}
	cfg, recipes := restoreTestDeps(st)
	pub, err := cfg.Bundle()
	if err != nil {
		t.Fatal(err)
	}
	recipe, err := recipes.Resolve(context.Background(), RecipeQuery{UpstreamID: up.ID, RouteID: route.ID, Endpoint: model.EndpointMessages})
	if err != nil {
		t.Fatal(err)
	}
	recipe.Facts.Use = model.BindingRealTrafficContext
	reach, _, cap, _, err := buildRealExpectations(pub.Probe, up, route, model.EndpointMessages, recipe)
	if err != nil {
		t.Fatal(err)
	}
	identity := capturedRouteHealthIdentity(pub.Probe, cap, reach, nil)
	tracker := health.NewTracker(cfg)
	for n := 0; n < pub.Settings.FailThreshold; n++ {
		tracker.Report(health.Report{RouteID: route.ID, Verdict: health.VerdictUnavailable, Source: health.SourceReal, Err: errors.New("upstream_transient"), Identity: identity})
	}
	status := tracker.Status(route.ID)
	if status.State != model.StateDead || status.Identity == nil {
		t.Fatalf("bound negative fixture=%+v", status)
	}
	return st, up, mn, route, &store.RouteHealth{RouteID: route.ID, State: status.State, ConsecutiveFail: status.ConsecutiveFail, LastErrAt: status.LastErrAt, LastError: status.LastError, DeadSince: status.DeadSince, RecoveryRequired: true, Identity: status.Identity}
}

func TestRouteHealthSnapshotRejectsIdentityChangesBeforeOrAfterPersistence(t *testing.T) {
	type mutation struct {
		name  string
		keeps bool
		apply func(*testing.T, *store.Store, *model.Upstream, *model.ModelName, *model.Route)
	}
	mutations := []mutation{
		{"model mapping", false, func(t *testing.T, st *store.Store, up *model.Upstream, mn *model.ModelName, rt *model.Route) {
			rt.UpstreamModel = "new-model"
			if err := st.UpdateRouteWithRevision(context.Background(), rt, rt.Revision); err != nil {
				t.Fatal(err)
			}
		}},
		{"route reenable", false, func(t *testing.T, st *store.Store, up *model.Upstream, mn *model.ModelName, rt *model.Route) {
			for _, v := range []bool{false, true} {
				rt.Enabled = v
				if err := st.UpdateRouteWithRevision(context.Background(), rt, rt.Revision); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{"upstream reenable", false, func(t *testing.T, st *store.Store, up *model.Upstream, mn *model.ModelName, rt *model.Route) {
			for _, v := range []bool{false, true} {
				up.Enabled = v
				if err := st.UpdateUpstreamWithRevision(context.Background(), up, up.Revision); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{"model reenable", false, func(t *testing.T, st *store.Store, up *model.Upstream, mn *model.ModelName, rt *model.Route) {
			for _, v := range []bool{false, true} {
				mn.Enabled = v
				if err := st.UpdateModelNameWithRevision(context.Background(), mn, mn.Revision); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{"disabled route", false, func(t *testing.T, st *store.Store, up *model.Upstream, mn *model.ModelName, rt *model.Route) {
			rt.Enabled = false
			if err := st.UpdateRouteWithRevision(context.Background(), rt, rt.Revision); err != nil {
				t.Fatal(err)
			}
		}},
		{"disabled upstream", false, func(t *testing.T, st *store.Store, up *model.Upstream, mn *model.ModelName, rt *model.Route) {
			up.Enabled = false
			if err := st.UpdateUpstreamWithRevision(context.Background(), up, up.Revision); err != nil {
				t.Fatal(err)
			}
		}},
		{"disabled model", false, func(t *testing.T, st *store.Store, up *model.Upstream, mn *model.ModelName, rt *model.Route) {
			mn.Enabled = false
			if err := st.UpdateModelNameWithRevision(context.Background(), mn, mn.Revision); err != nil {
				t.Fatal(err)
			}
		}},
		{"credential", false, func(t *testing.T, st *store.Store, up *model.Upstream, mn *model.ModelName, rt *model.Route) {
			up.APIKey = "replacement-upstream-private-key"
			if err := st.UpdateUpstreamWithRevision(context.Background(), up, up.Revision); err != nil {
				t.Fatal(err)
			}
		}},
		{"network origin", false, func(t *testing.T, st *store.Store, up *model.Upstream, mn *model.ModelName, rt *model.Route) {
			up.BaseURL = "https://replacement.example.test"
			if err := st.UpdateUpstreamWithRevision(context.Background(), up, up.Revision); err != nil {
				t.Fatal(err)
			}
		}},
		{"endpoint auth", false, func(t *testing.T, st *store.Store, up *model.Upstream, mn *model.ModelName, rt *model.Route) {
			ep, err := st.Endpoint(context.Background(), up.ID, model.EndpointMessages)
			if err != nil {
				t.Fatal(err)
			}
			ep.AuthProfile = model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: "upstream_api_key"}
			ep.LegacyCompatRealOnly = false
			if err := st.UpdateEndpoint(ep, ep.Revision); err != nil {
				t.Fatal(err)
			}
		}},
		{"real stage", false, func(t *testing.T, st *store.Store, up *model.Upstream, mn *model.ModelName, rt *model.Route) {
			s, r, err := st.GetSettingsWithRevision()
			if err != nil {
				t.Fatal(err)
			}
			s.RealFirstSemanticSec++
			if _, err := st.SaveSettingsWithRevision(s, r); err != nil {
				t.Fatal(err)
			}
		}},
		{"failure threshold", false, func(t *testing.T, st *store.Store, up *model.Upstream, mn *model.ModelName, rt *model.Route) {
			s, r, err := st.GetSettingsWithRevision()
			if err != nil {
				t.Fatal(err)
			}
			s.FailThreshold++
			if _, err := st.SaveSettingsWithRevision(s, r); err != nil {
				t.Fatal(err)
			}
		}},
		{"recovery threshold", false, func(t *testing.T, st *store.Store, up *model.Upstream, mn *model.ModelName, rt *model.Route) {
			s, r, err := st.GetSettingsWithRevision()
			if err != nil {
				t.Fatal(err)
			}
			s.OKThreshold++
			if _, err := st.SaveSettingsWithRevision(s, r); err != nil {
				t.Fatal(err)
			}
		}},
		{"cooldown policy", false, func(t *testing.T, st *store.Store, up *model.Upstream, mn *model.ModelName, rt *model.Route) {
			s, r, err := st.GetSettingsWithRevision()
			if err != nil {
				t.Fatal(err)
			}
			s.CooldownSec++
			if _, err := st.SaveSettingsWithRevision(s, r); err != nil {
				t.Fatal(err)
			}
		}},
		{"priority weight concurrency", true, func(t *testing.T, st *store.Store, up *model.Upstream, mn *model.ModelName, rt *model.Route) {
			rt.Priority++
			rt.Weight++
			rt.MaxConcurrency++
			if err := st.UpdateRouteWithRevision(context.Background(), rt, rt.Revision); err != nil {
				t.Fatal(err)
			}
		}},
		{"display name", true, func(t *testing.T, st *store.Store, up *model.Upstream, mn *model.ModelName, rt *model.Route) {
			up.Name = "new display"
			if err := st.UpdateUpstreamWithRevision(context.Background(), up, up.Revision); err != nil {
				t.Fatal(err)
			}
		}},
		{"sample policy", true, func(t *testing.T, st *store.Store, up *model.Upstream, mn *model.ModelName, rt *model.Route) {
			s, r, err := st.GetSettingsWithRevision()
			if err != nil {
				t.Fatal(err)
			}
			s.SampleKeepCount++
			if _, err := st.SaveSettingsWithRevision(s, r); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, before := range []bool{true, false} {
		for _, change := range mutations {
			t.Run(fmt.Sprintf("persist_before=%t/%s", before, change.name), func(t *testing.T) {
				st, up, mn, route, row := boundNegativeSnapshot(t)
				if before {
					if err := st.SaveRouteHealth([]*store.RouteHealth{row}); err != nil {
						t.Fatal(err)
					}
				}
				change.apply(t, st, up, mn, route)
				if !before {
					if err := st.SaveRouteHealth([]*store.RouteHealth{row}); err != nil {
						t.Fatal(err)
					}
				}
				cfg, _ := restoreTestDeps(st)
				tracker := health.NewTracker(cfg)
				count, err := RestoreRouteHealth(context.Background(), tracker, st, cfg)
				if err != nil {
					t.Fatal(err)
				}
				want := model.StateUnknown
				if change.keeps {
					want = model.StateDead
				}
				if got := tracker.State(route.ID); got != want || (count == 1) != change.keeps {
					t.Fatalf("restored=%d state=%s want=%s", count, got, want)
				}
			})
		}
	}
}

func TestRealHTTPNegativeHealthRetainsCurrentIdentityAndCooldownAcrossColdRestart(t *testing.T) {
	for _, kind := range []string{"dead", "recovering", "cooldown"} {
		t.Run(kind, func(t *testing.T) {
			h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, r *http.Request) {
				drainBody(r)
				w.Header().Set("Content-Type", "application/json")
				status := 503
				if kind == "cooldown" {
					status = 429
					w.Header().Set("Retry-After", "60")
				}
				w.WriteHeader(status)
				io.WriteString(w, `{"error":{"type":"server_error"}}`)
			})
			settings, revision, err := h.store.GetSettingsWithRevision()
			if err != nil {
				t.Fatal(err)
			}
			settings.FailThreshold = 1
			if _, err := h.store.SaveSettingsWithRevision(settings, revision); err != nil {
				t.Fatal(err)
			}
			cfg := h.manager.cfg.(*livecfg.Source)
			if err := cfg.Refresh(); err != nil {
				t.Fatal(err)
			}
			status, _ := h.requestProtocol(t, model.ProtoAnthropic)
			if status != 503 && status != 429 {
				t.Fatalf("upstream failure not delivered: %d", status)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			flushRestorationTraffic(t, ctx, h.handler, h.manager)
			before := h.tracker.Status(h.route.ID)
			if before.Identity == nil {
				t.Fatal("real observation lost its captured health identity")
			}
			if kind == "recovering" {
				h.tracker.Report(health.Report{RouteID: h.route.ID, Verdict: health.VerdictOK, Source: health.SourceL2, HalfOpen: true, Identity: before.Identity})
				before = h.tracker.Status(h.route.ID)
			}
			flush, cancelFlush := context.WithCancel(context.Background())
			cancelFlush()
			health.NewPersister(h.tracker, h.store, discardLogger()).Run(flush)
			h.manager.Close()
			path := h.store.DatabasePath()
			if err := h.store.Close(); err != nil {
				t.Fatal(err)
			}
			cipher, _ := store.NewCipher("calibration-test-passphrase-16")
			reopened, err := store.Open(path, cipher)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			freshCfg, _ := restoreTestDeps(reopened)
			fresh := health.NewTracker(freshCfg)
			count, err := RestoreRouteHealth(ctx, fresh, reopened, freshCfg)
			if err != nil {
				t.Fatal(err)
			}
			after := fresh.Status(h.route.ID)
			if count != 1 || after.State != before.State || after.CooldownUntil != before.CooldownUntil || after.ConsecutiveFail != before.ConsecutiveFail || after.ConsecutiveOK != before.ConsecutiveOK || after.LastError != before.LastError {
				t.Fatalf("cold state changed: restored=%d before=%+v after=%+v", count, before, after)
			}
		})
	}
}

func flushRestorationTraffic(t *testing.T, ctx context.Context, handler *proxy.Handler, manager *TrafficObserverManager) {
	t.Helper()
	release, err := handler.Quiesce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := manager.Flush(ctx); err != nil {
		t.Fatal(err)
	}
}
