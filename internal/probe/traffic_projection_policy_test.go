package probe

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/revisioncodec"
	"github.com/279814/relay-gate/internal/store"
)

func TestTrafficCommittedReturnChecksCapturedPolicyBeforeHealthProjection(t *testing.T) {
	for _, tc := range []struct {
		name                                                     string
		success, networkFailure, project, expireTTL, unpublished bool
		change                                                   func(*model.Settings)
	}{
		{name: "old success related semantic", success: true, expireTTL: true, change: func(s *model.Settings) { s.RealFirstSemanticSec++ }},
		{name: "old failure related header", change: func(s *model.Settings) { s.RealResponseHeaderSec++ }},
		{name: "success unrelated synthetic L2", success: true, project: true, change: func(s *model.Settings) { s.L2FirstSemanticSec++ }},
		{name: "failure unrelated sample", project: true, change: func(s *model.Settings) { s.SampleKeepCount++ }},
		{name: "network failure related connect", networkFailure: true, change: func(s *model.Settings) { s.RealConnectSec++ }},
		{name: "network failure related threshold", networkFailure: true, change: func(s *model.Settings) { s.FailThreshold++ }},
		{name: "network failure unrelated semantic-only stage", networkFailure: true, project: true, change: func(s *model.Settings) { s.RealFirstSemanticSec++ }},
		{name: "success requires a ready published view", success: true, unpublished: true, change: func(s *model.Settings) { s.SampleKeepCount++ }},
		{name: "failure requires a ready published view", unpublished: true, change: func(s *model.Settings) { s.SampleKeepCount++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, r *http.Request) {
				drainBody(r)
				w.Header().Set("Content-Type", "application/json")
				if !tc.success {
					w.WriteHeader(503)
					_, _ = io.WriteString(w, `{"error":{"type":"server_error"}}`)
					return
				}
				_, _ = io.WriteString(w, `{"type":"message","content":[{"type":"text","text":"complete real response"}]}`)
			})
			source := h.manager.cfg.(*livecfg.Source)
			if tc.networkFailure {
				// The real HTTP client still enters the proxy; only its actual
				// upstream TCP connection fails, before any response headers.
				remote := httptest.NewServer(http.NotFoundHandler())
				h.up.BaseURL = remote.URL
				remote.Close()
				if err := h.store.UpdateUpstreamWithRevision(ctx, h.up, h.up.Revision); err != nil {
					t.Fatal(err)
				}
			}
			settings, revision, err := h.store.GetSettingsWithRevision()
			if err != nil {
				t.Fatal(err)
			}
			settings.FailThreshold, settings.OKThreshold = 1, 1
			settings.RealConnectSec = 1
			if _, err := h.store.SaveSettingsWithRevision(settings, revision); err != nil {
				t.Fatal(err)
			}
			if err := source.Refresh(); err != nil {
				t.Fatal(err)
			}
			generation := h.tracker.EnsureGeneration(h.route.ID)
			h.tracker.Report(health.Report{RouteID: h.route.ID, Generation: generation, Verdict: health.VerdictOK, Source: health.SourceReal})
			h.tracker.CompleteL2(h.route.ID, time.Now(), 0)
			before := h.tracker.Status(h.route.ID)
			delayed := delayedCommittedObservation{store: h.store, committed: make(chan struct{}), release: make(chan struct{})}
			resume := func() {
				select {
				case <-delayed.release:
				default:
					close(delayed.release)
				}
			}
			t.Cleanup(resume)
			h.manager.record = NewResultRecorder(delayed, health.NewObservationReducer(nil), h.reach, h.caps)
			// Candidate learning has its own DB writer and contract. Keep this
			// regression's held-connection assertion on health projection alone.
			h.manager.WithLearner(nil)
			schedule := &recordingSched{}
			h.manager.WithScheduler(schedule)
			status, _ := h.requestProtocol(t, model.ProtoAnthropic)
			if (tc.success && status != 200) || (tc.networkFailure && status != 502) || (!tc.success && !tc.networkFailure && status != 503) {
				t.Fatalf("real HTTP fixture response=%d", status)
			}
			select {
			case <-delayed.committed:
			case <-time.After(2 * time.Second):
				t.Fatal("real observation did not commit before the return delay")
			}
			page, err := h.store.ListProbeExecutions(ctx, model.ProbeExecutionFilter{Trigger: model.TriggerRealTraffic})
			if err != nil {
				t.Fatal(err)
			}
			if len(page.Items) != 1 {
				t.Fatalf("durable execution count=%d", len(page.Items))
			}
			captured := page.Items[0]
			if captured.Success != tc.success || captured.RecipeBindingUse != model.BindingRealTrafficContext || captured.CapabilityPolicySelector.Kind != model.EvidenceRealTraffic || captured.ReachabilityDisposition != model.ApplyCurrent || (!tc.networkFailure && captured.CapabilityDisposition != model.ApplyCurrent) {
				t.Fatalf("fixture did not commit the actual real-traffic context: %+v", captured)
			}
			updated, currentRevision, err := h.store.GetSettingsWithRevision()
			if err != nil {
				t.Fatal(err)
			}
			tc.change(&updated)
			if _, err := h.store.SaveSettingsWithRevision(updated, currentRevision); err != nil {
				t.Fatal(err)
			}
			source.Invalidate()
			if !tc.unpublished {
				if err := source.Refresh(); err != nil {
					t.Fatal(err)
				}
			}
			if h.tracker.GenerationOf(h.route.ID) != generation {
				t.Fatal("policy update must not hide the race with a lifecycle reset")
			}
			if tc.networkFailure {
				policy, err := revisioncodec.BuildReachabilityEvidencePolicy(updated, captured.ReachabilityPolicySelector)
				if err != nil {
					t.Fatal(err)
				}
				if (revisioncodec.ReachabilitySettingsFingerprint(policy) == captured.ReachabilitySettingsFingerprint) != (tc.project || tc.unpublished) {
					t.Fatal("fixture changed the wrong reachability policy side")
				}
			} else {
				policy, err := revisioncodec.BuildCapabilityEvidencePolicy(updated, captured.CapabilityPolicySelector)
				if err != nil {
					t.Fatal(err)
				}
				if (revisioncodec.ProbeSettingsFingerprint(policy) == captured.ProbeSettingsFingerprint) != (tc.project || tc.unpublished) {
					t.Fatal("fixture changed the wrong capability policy side")
				}
			}
			if tc.expireTTL {
				time.Sleep(livecfg.DefaultTTL + 20*time.Millisecond)
			}
			connection, err := h.store.DB().Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = connection.Close() })
			resume()
			flushContext, cancel := context.WithTimeout(ctx, time.Second)
			flushErr := h.manager.Flush(flushContext)
			cancel()
			_ = connection.Close()
			if flushErr != nil {
				t.Fatalf("health projection waited for SQLite instead of cached facts: %v", flushErr)
			}
			after := h.tracker.Status(h.route.ID)
			if !tc.project {
				if !reflect.DeepEqual(before, after) || schedule.n != 0 {
					t.Fatalf("old committed policy projected health/synthetic savings:\nbefore=%+v\nafter=%+v savings=%d", before, after, schedule.n)
				}
			} else if tc.success {
				if after.ConsecutiveOK <= before.ConsecutiveOK || schedule.n != 1 {
					t.Fatalf("unrelated setting suppressed real success: health=%+v savings=%d", after, schedule.n)
				}
			} else if after.ConsecutiveFail != before.ConsecutiveFail+1 || after.NextL2At != 0 {
				t.Fatalf("unrelated setting suppressed real failure: before=%+v after=%+v", before, after)
			}
		})
	}
}

func TestTrafficCommittedReturnCannotProjectAfterPublishedBindingChanges(t *testing.T) {
	ctx := context.Background()
	h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, r *http.Request) {
		drainBody(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"type":"message","content":[{"type":"text","text":"complete"}]}`)
	})
	source := h.manager.cfg.(*livecfg.Source)
	ep, err := h.store.Endpoint(ctx, h.up.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	ep.LegacyCompatRealOnly = false
	ep.AuthProfile = model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: "upstream_api_key"}
	if err := h.store.UpdateEndpoint(ep, ep.Revision); err != nil {
		t.Fatal(err)
	}
	if err := source.Refresh(); err != nil {
		t.Fatal(err)
	}
	generation := h.tracker.EnsureGeneration(h.route.ID)
	h.tracker.Report(health.Report{RouteID: h.route.ID, Generation: generation, Verdict: health.VerdictOK, Source: health.SourceReal})
	before := h.tracker.Status(h.route.ID)
	delayed := delayedCommittedObservation{store: h.store, committed: make(chan struct{}), release: make(chan struct{})}
	resume := func() {
		select {
		case <-delayed.release:
		default:
			close(delayed.release)
		}
	}
	t.Cleanup(resume)
	h.manager.record = NewResultRecorder(delayed, health.NewObservationReducer(nil), h.reach, h.caps)
	h.manager.WithLearner(nil)
	schedule := &recordingSched{}
	h.manager.WithScheduler(schedule)
	h.request(t)
	select {
	case <-delayed.committed:
	case <-time.After(2 * time.Second):
		t.Fatal("real response never committed")
	}
	rows, err := h.store.ListProbeExecutions(ctx, model.ProbeExecutionFilter{Trigger: model.TriggerRealTraffic})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows.Items) != 1 || !rows.Items[0].Success || rows.Items[0].RecipeBindingFacts.ResolvedLayer != model.ResolvedEmbedded || rows.Items[0].CapabilityDisposition != model.ApplyCurrent {
		t.Fatalf("fixture did not commit its initial embedded real context: %+v", rows.Items)
	}
	// Publish a genuine immutable version using its own actual HTTP test and
	// transaction CAS. Deliberately omit the separate runtime invalidator, so
	// only the guard's current binding proof can reject the delayed return.
	recipes := NewRecipeResolver(h.store).WithNotFound(func(err error) bool { return errors.Is(err, store.ErrNotFound) })
	transports := outbound.NewManager()
	t.Cleanup(transports.CloseIdleConnections)
	executor := NewExecutor(outbound.NewProvider(source, h.store, outbound.NewResolver(testHasher{})), h.store, recipes, ManagerTransports{Manager: transports}, NewResultRecorder(h.store, health.NewObservationReducer(nil), nil, nil), AlwaysOpenAdmission(), WallClock(), discardLogger())
	manual := NewScheduler(source, h.tracker, h.reach, discardLogger()).WithRecipes(recipes).WithExecutor(executor).WithSequencer(h.manager.seq)
	admin := NewService(h.store, executor, nil, source, nil, nil).WithManualPreparer(manual)
	recipe, err := admin.CreateRecipe(ctx, model.RecipeScopeRoute, h.route.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	version, err := admin.AddVersion(ctx, recipe.ID, recipe.Revision, RecipeVersionMutation{Method: http.MethodPost, Body: []byte(`{"model":"{{UPSTREAM_MODEL}}","max_tokens":1,"messages":[{"role":"user","content":"probe"}]}`), BodyIsText: true, TimeoutProfile: model.TimeoutL2Standard})
	if err != nil {
		t.Fatal(err)
	}
	recipe, err = admin.GetRecipe(ctx, recipe.ID)
	if err != nil {
		t.Fatal(err)
	}
	tested, err := admin.Test(ctx, version.ID, ManualTestInput{RouteID: h.route.ID, ExpectedRevision: recipe.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if !tested.Success {
		t.Fatalf("new binding was not actually tested: %+v", tested)
	}
	published, err := admin.Publish(ctx, recipe.ID, version.ID, tested.ID, recipe.Revision, false)
	if err != nil {
		t.Fatal(err)
	}
	if published.Status != model.RecipePublished || published.PublishedVersionID != version.ID || h.tracker.GenerationOf(h.route.ID) != generation {
		t.Fatal("fixture needs a new published binding without Forget/generation reset")
	}
	if !reflect.DeepEqual(before, h.tracker.Status(h.route.ID)) {
		t.Fatal("setup changed health instead of independently testing the delayed projection")
	}
	connection, err := h.store.DB().Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	resume()
	flushContext, cancel := context.WithTimeout(ctx, time.Second)
	flushErr := h.manager.Flush(flushContext)
	cancel()
	_ = connection.Close()
	if flushErr != nil {
		t.Fatalf("published binding validation waited for SQL: %v", flushErr)
	}
	after := h.tracker.Status(h.route.ID)
	if !reflect.DeepEqual(before, after) || schedule.n != 0 {
		t.Fatalf("old binding was accepted under a newly published recipe:\nbefore=%+v\nafter=%+v savings=%d", before, after, schedule.n)
	}
}
