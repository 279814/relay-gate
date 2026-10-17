package probe

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/observationseq"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

func TestSchedulerL1CommittedFailureCannotDamageReenabledRouteHealth(t *testing.T) {
	ctx := context.Background()
	st := calibrationTestStore(t)
	up, _, route := seedCalibrationRoute(t, st)
	refused := httptest.NewServer(http.NotFoundHandler())
	up.BaseURL = refused.URL
	refused.Close()
	if err := st.UpdateUpstreamWithRevision(ctx, up, up.Revision); err != nil {
		t.Fatal(err)
	}
	ep, err := st.Endpoint(ctx, up.ID, model.EndpointModels)
	if err != nil {
		t.Fatal(err)
	}
	ep.LegacyCompatRealOnly = false
	ep.AuthProfile = model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: "upstream_api_key"}
	if err := st.UpdateEndpoint(ep, ep.Revision); err != nil {
		t.Fatal(err)
	}
	cfg, recipes := restoreTestDeps(st)
	if _, err := cfg.Bundle(); err != nil {
		t.Fatal(err)
	}
	track := health.NewTracker(cfg)
	oldGeneration := track.EnsureGeneration(route.ID)
	track.Report(health.Report{RouteID: route.ID, Generation: oldGeneration, Verdict: health.VerdictOK, Source: health.SourceReal})
	reach := health.NewReachabilityTracker(cfg)
	delayed := delayedCommittedObservation{store: st, committed: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() {
		select {
		case <-delayed.release:
		default:
			close(delayed.release)
		}
	})
	recorder := NewResultRecorder(delayed, health.NewObservationReducer(nil), reach, nil)
	manager := outbound.NewManager()
	t.Cleanup(manager.CloseIdleConnections)
	executor := NewExecutor(outbound.NewProvider(cfg, st, outbound.NewResolver(testHasher{})), st, recipes, ManagerTransports{Manager: manager}, recorder, AlwaysOpenAdmission(), WallClock(), discardLogger())
	seq, err := observationseq.Open(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(seq.Close)
	scheduler := NewScheduler(cfg, track, reach, discardLogger()).WithRecipes(recipes).WithExecutor(executor).WithSequencer(seq)
	done := make(chan struct{})
	go func() { scheduler.runL1(ctx, up, model.DefaultSettings()); close(done) }()
	select {
	case <-delayed.committed:
	case <-time.After(2 * time.Second):
		t.Fatal("L1 did not commit its failure")
	}
	page, err := st.ListProbeExecutions(ctx, model.ProbeExecutionFilter{UpstreamID: up.ID, Endpoint: model.EndpointModels})
	if err != nil || len(page.Items) != 1 || page.Items[0].ErrorClass != model.ErrorUnreachable || page.Items[0].ReachabilityDisposition != model.ApplyCurrent {
		if len(page.Items) > 0 {
			t.Fatalf("fixture must commit real L1 network failure: %+v err=%v", *page.Items[0], err)
		}
		t.Fatalf("fixture must commit a real L1 network failure: rows=%+v err=%v", page.Items, err)
	}
	updated := *up
	updated.Enabled = false
	if err := st.UpdateUpstreamWithRevision(ctx, &updated, updated.Revision); err != nil {
		t.Fatal(err)
	}
	updated.Enabled = true
	if err := st.UpdateUpstreamWithRevision(ctx, &updated, updated.Revision); err != nil {
		t.Fatal(err)
	}
	track.Forget(route.ID)
	if generation := track.EnsureGeneration(route.ID); generation == oldGeneration {
		t.Fatal("re-enable did not reset health generation")
	}
	reach.Invalidate(up.ID)
	if err := cfg.Refresh(); err != nil {
		t.Fatal(err)
	}
	close(delayed.release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("L1 did not finish")
	}
	status := track.Status(route.ID)
	if status.State != model.StateUnknown || status.ConsecutiveFail != 0 || status.LastError != "" {
		t.Fatalf("late L1 poisoned reset RouteHealth: %+v", status)
	}
	if got := reach.Effective(up.ID, updated.NetworkRevision); got != model.ReachabilityUnknown {
		t.Fatalf("late L1 revived old reachability: %s", got)
	}
}

func TestSchedulerCommittedReturnRechecksOnlyItsCurrentEvidencePolicy(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		endpoint                    model.EndpointKind
		success, project, expireTTL bool
		change                      func(*model.Settings)
	}{
		{"L1 failure related connect", model.EndpointModels, false, false, false, func(s *model.Settings) { s.L1ConnectSec++ }},
		{"L1 failure related threshold", model.EndpointModels, false, false, false, func(s *model.Settings) { s.FailThreshold++ }},
		{"L1 failure unrelated L2", model.EndpointModels, false, true, false, func(s *model.Settings) { s.L2FirstSemanticSec++ }},
		{"L1 failure unrelated sample", model.EndpointModels, false, true, false, func(s *model.Settings) { s.SampleKeepCount++ }},
		{"L1 recovery related connect", model.EndpointModels, true, false, false, func(s *model.Settings) { s.L1ConnectSec++ }},
		{"L1 recovery unrelated L2", model.EndpointModels, true, true, false, func(s *model.Settings) { s.L2FirstSemanticSec++ }},
		{"L2 failure related semantic", model.EndpointMessages, false, false, true, func(s *model.Settings) { s.L2FirstSemanticSec++ }},
		{"L2 success related header", model.EndpointMessages, true, false, false, func(s *model.Settings) { s.L2ResponseHeaderSec++ }},
		{"L2 failure reachability-only threshold", model.EndpointMessages, false, true, false, func(s *model.Settings) { s.FailThreshold++ }},
		{"L2 failure unrelated L1", model.EndpointMessages, false, true, false, func(s *model.Settings) { s.L1ConnectSec++ }},
		{"L2 success unrelated sample", model.EndpointMessages, true, true, false, func(s *model.Settings) { s.SampleKeepCount++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			st := calibrationTestStore(t)
			up, mn, route := seedCalibrationRoute(t, st)
			remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				drainBody(r)
				if tc.endpoint == model.EndpointModels {
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"data":[]}`)
					return
				}
				if tc.success {
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = io.WriteString(w, anthropicSemanticBody())
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(503)
				_, _ = io.WriteString(w, `{"error":{"type":"server_error"}}`)
			}))
			t.Cleanup(remote.Close)
			up.BaseURL = remote.URL
			if tc.endpoint == model.EndpointModels && !tc.success {
				remote.Close()
			}
			if err := st.UpdateUpstreamWithRevision(ctx, up, up.Revision); err != nil {
				t.Fatal(err)
			}
			ep, err := st.Endpoint(ctx, up.ID, tc.endpoint)
			if err != nil {
				t.Fatal(err)
			}
			ep.LegacyCompatRealOnly = false
			ep.AuthProfile = model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: "upstream_api_key"}
			if err := st.UpdateEndpoint(ep, ep.Revision); err != nil {
				t.Fatal(err)
			}
			settings, revision, err := st.GetSettingsWithRevision()
			if err != nil {
				t.Fatal(err)
			}
			settings.OKThreshold, settings.FailThreshold = 1, 1
			settings.L1ConnectSec, settings.L1TotalSec = 1, 5
			settings.L2ConnectSec, settings.L2TotalSec, settings.L2IdleSec = 1, 5, 1
			settings.L2FirstTokenSec, settings.L2ResponseHeaderSec, settings.L2FirstByteSec, settings.L2FirstEventSec, settings.L2FirstSemanticSec = 2, 1, 1, 1, 2
			if _, err := st.SaveSettingsWithRevision(settings, revision); err != nil {
				t.Fatal(err)
			}
			cfg, recipes := restoreTestDeps(st)
			if _, err := cfg.Bundle(); err != nil {
				t.Fatal(err)
			}
			track := health.NewTracker(cfg)
			generation := track.EnsureGeneration(route.ID)
			track.Report(health.Report{RouteID: route.ID, Generation: generation, Verdict: health.VerdictOK, Source: health.SourceReal})
			reach := health.NewReachabilityTracker(cfg)
			caps := NewCapabilityRegistry(cfg).WithRouteGeneration(track)
			if tc.endpoint == model.EndpointModels && tc.success {
				track.Report(health.Report{RouteID: route.ID, Generation: generation, Verdict: health.VerdictFatal, Source: health.SourceL2})
				track.CompleteL2(route.ID, time.Now(), 0)
				snapshot, err := cfg.CachedProbeSnapshot()
				if err != nil {
					t.Fatal(err)
				}
				selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
				expectation, err := snapshot.ReachabilityExpectation(up.ID, selector)
				if err != nil {
					t.Fatal(err)
				}
				reach.ApplyCommitted(&model.UpstreamReachability{UpstreamID: up.ID, State: model.ReachabilityUnreachable, PolicySelector: selector,
					ObservedCreatedAt: up.CreatedAt, ObservedNetworkRevision: up.NetworkRevision, SettingsFingerprint: expectation.Revision.SettingsFingerprint, ObservationToken: expectation.ObservationToken})
			}
			before := track.Status(route.ID)
			delayed := delayedCommittedObservation{store: st, committed: make(chan struct{}), release: make(chan struct{})}
			resume := func() {
				select {
				case <-delayed.release:
				default:
					close(delayed.release)
				}
			}
			t.Cleanup(resume)
			recorder := NewResultRecorder(delayed, health.NewObservationReducer(nil), reach, caps)
			manager := outbound.NewManager()
			t.Cleanup(manager.CloseIdleConnections)
			executor := NewExecutor(outbound.NewProvider(cfg, st, outbound.NewResolver(testHasher{})), st, recipes, ManagerTransports{Manager: manager}, recorder, AlwaysOpenAdmission(), WallClock(), discardLogger())
			seq, err := observationseq.Open(ctx, st)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(seq.Close)
			scheduler := NewScheduler(cfg, track, reach, discardLogger()).WithRecipes(recipes).WithExecutor(executor).WithSequencer(seq)
			done := make(chan struct{})
			go func() {
				defer close(done)
				if tc.endpoint == model.EndpointModels {
					scheduler.runL1(ctx, up, settings)
				} else {
					scheduler.runL2(ctx, up, mn, route, settings, generation)
				}
			}()
			select {
			case <-delayed.committed:
			case <-time.After(2 * time.Second):
				t.Fatal("probe never committed before the injected return delay")
			}
			page, err := st.ListProbeExecutions(ctx, model.ProbeExecutionFilter{UpstreamID: up.ID, Endpoint: tc.endpoint})
			if err != nil {
				t.Fatal(err)
			}
			if len(page.Items) != 1 || page.Items[0].Success != tc.success || page.Items[0].ReachabilityDisposition != model.ApplyCurrent || (tc.endpoint != model.EndpointModels && page.Items[0].CapabilityDisposition != model.ApplyCurrent) {
				t.Fatalf("fixture did not commit the original current observation: %+v", page.Items)
			}
			captured := page.Items[0]
			updated, currentRevision, err := st.GetSettingsWithRevision()
			if err != nil {
				t.Fatal(err)
			}
			tc.change(&updated)
			if _, err := st.SaveSettingsWithRevision(updated, currentRevision); err != nil {
				t.Fatal(err)
			}
			cfg.Invalidate()
			if err := cfg.Refresh(); err != nil {
				t.Fatal(err)
			}
			if track.GenerationOf(route.ID) != generation {
				t.Fatal("pure settings change must not use a lifecycle generation reset to hide the race")
			}
			// Independently confirm whether this side's policy actually changed.
			var currentFingerprint string
			if tc.endpoint == model.EndpointModels {
				policy, err := revisioncodec.BuildReachabilityEvidencePolicy(updated, captured.ReachabilityPolicySelector)
				if err != nil {
					t.Fatal(err)
				}
				currentFingerprint = revisioncodec.ReachabilitySettingsFingerprint(policy)
				if (currentFingerprint == captured.ReachabilitySettingsFingerprint) != tc.project {
					t.Fatal("test changed the wrong policy side")
				}
			} else {
				policy, err := revisioncodec.BuildCapabilityEvidencePolicy(updated, captured.CapabilityPolicySelector)
				if err != nil {
					t.Fatal(err)
				}
				currentFingerprint = revisioncodec.ProbeSettingsFingerprint(policy)
				if (currentFingerprint == captured.ProbeSettingsFingerprint) != tc.project {
					t.Fatal("test changed the wrong policy side")
				}
			}
			if tc.expireTTL {
				time.Sleep(livecfg.DefaultTTL + 20*time.Millisecond)
			}
			// Hold the only SQL connection: completion must use the published
			// immutable view, even after its routing refresh TTL has elapsed.
			connection, err := st.DB().Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			resume()
			select {
			case <-done:
			case <-time.After(time.Second):
				_ = connection.Close()
				<-done
				t.Fatal("health projection waited for SQLite instead of checking published policy")
			}
			_ = connection.Close()
			after := track.Status(route.ID)
			if !tc.project {
				if !reflect.DeepEqual(before, after) {
					t.Fatalf("SQL-current return projected stale policy into RouteHealth:\nbefore=%+v\nafter=%+v", before, after)
				}
			} else if tc.endpoint == model.EndpointModels && tc.success {
				if before.NextL2At == 0 || after.NextL2At != 0 {
					t.Fatalf("unrelated settings suppressed legitimate L1 recovery scheduling: before=%+v after=%+v", before, after)
				}
			} else if tc.success {
				if after.ConsecutiveOK <= before.ConsecutiveOK {
					t.Fatalf("unrelated settings suppressed legitimate L2 success: before=%+v after=%+v", before, after)
				}
			} else if after.ConsecutiveFail != before.ConsecutiveFail+1 {
				t.Fatalf("unrelated settings suppressed legitimate failure: before=%+v after=%+v", before, after)
			}
		})
	}
}
