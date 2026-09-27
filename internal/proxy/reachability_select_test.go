package proxy

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
	"github.com/279814/relay-gate/internal/router"
)

// §6.4：正常候选要求「Upstream Reachability 不是 unreachable」，与 RouteHealth
// 是否 dead 无关。harness 的主站（Upstream 10 / Route 100，priority 1）在这里
// 加一个 priority 2 的备站（Upstream 20 / Route 200）。
func reachabilityHarness(t *testing.T, primaryState model.ReachabilityState) (*harness, *int32, *int32) {
	t.Helper()
	var primaryHits, backupHits int32
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&primaryHits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"msg_primary","type":"message"}`))
	})
	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&backupHits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"msg_backup","type":"message"}`))
	}))
	t.Cleanup(backup.Close)

	snap := hs.cfg.snap
	up2 := &model.Upstream{ID: 20, Name: "backup", BaseURL: backup.URL,
		APIKey: "sk-upstream-backup", AuthStyle: model.AuthAuto, Enabled: true}
	rt2 := &model.Route{ID: 200, ModelNameID: 1, UpstreamID: 20,
		Priority: 2, Weight: 100, Enabled: true}
	ups := []*model.Upstream{snap.Upstreams[10], up2}
	routes := append(append([]*model.Route(nil), snap.RoutesByModelName[1]...), rt2)
	hs.cfg.snap = router.BuildSnapshot(snap.ModelNames, ups, routes)

	reach := health.NewReachabilityTracker(hs.cfg)
	primary := hs.cfg.snap.Upstreams[10]
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	policy, err := revisioncodec.BuildReachabilityEvidencePolicy(hs.cfg.settings, selector)
	if err != nil {
		t.Fatal(err)
	}
	fp := revisioncodec.ReachabilitySettingsFingerprint(policy)
	reach.ApplyCommitted(&model.UpstreamReachability{
		UpstreamID: primary.ID, PolicySelector: selector, State: primaryState,
		ObservedNetworkRevision: primary.NetworkRevision, SettingsFingerprint: fp,
		ObservationToken: revisioncodec.NewReachabilityToken(model.ReachabilityRevision{
			NetworkRevision: primary.NetworkRevision, SettingsFingerprint: fp,
		}),
		LastObservationOrder: 1,
	})
	if primaryState == model.ReachabilityUnreachable && reach.OK(primary.ID, primary.NetworkRevision) {
		t.Fatal("setup: committed unreachable row must be effective")
	}
	hs.h.WithReachability(reach)
	return hs, &primaryHits, &backupHits
}

func TestHandler_UnreachableUpstreamSkippedBeforeRouteDead(t *testing.T) {
	hs, primaryHits, backupHits := reachabilityHarness(t, model.ReachabilityUnreachable)
	if hs.health.State(100) == model.StateDead {
		t.Fatal("setup: primary Route must not be dead")
	}

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))
	if rec.Code != 200 {
		t.Fatalf("backup should serve, got %d: %s", rec.Code, rec.Body.String())
	}
	if n := atomic.LoadInt32(primaryHits); n != 0 {
		t.Errorf("unreachable Upstream must not receive a new request, got %d", n)
	}
	if n := atomic.LoadInt32(backupHits); n != 1 {
		t.Errorf("reachable backup should receive the request, got %d", n)
	}
}

func TestHandler_ReachableUpstreamStillSelected(t *testing.T) {
	hs, primaryHits, backupHits := reachabilityHarness(t, model.ReachabilityReachable)

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))
	if rec.Code != 200 {
		t.Fatalf("primary should serve, got %d: %s", rec.Code, rec.Body.String())
	}
	if n := atomic.LoadInt32(primaryHits); n != 1 {
		t.Errorf("reachable priority-1 Upstream must be selected, got %d", n)
	}
	if n := atomic.LoadInt32(backupHits); n != 0 {
		t.Errorf("backup must not be used while primary is reachable, got %d", n)
	}
}
