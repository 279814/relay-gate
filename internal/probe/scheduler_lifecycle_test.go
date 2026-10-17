package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/observationseq"
	"github.com/279814/relay-gate/internal/outbound"
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
