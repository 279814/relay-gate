package health

import (
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

type staticSettings struct{ s model.Settings }

func (s staticSettings) Settings() (model.Settings, error) { return s.s, nil }

func TestReachabilityTracker_CASAndEffectiveUnknown(t *testing.T) {
	settings := model.DefaultSettings()
	tracker := NewReachabilityTracker(staticSettings{settings})
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	policy, err := revisioncodec.BuildReachabilityEvidencePolicy(settings, selector)
	if err != nil {
		t.Fatal(err)
	}
	fp := revisioncodec.ReachabilitySettingsFingerprint(policy)
	token := revisioncodec.NewReachabilityToken(model.ReachabilityRevision{
		NetworkRevision: 1, SettingsFingerprint: fp,
	})

	newer := &model.UpstreamReachability{
		UpstreamID: 7, PolicySelector: selector, State: model.ReachabilityReachable,
		ObservedNetworkRevision: 1, SettingsFingerprint: fp,
		ObservationToken: token, LastObservationOrder: 10,
	}
	older := &model.UpstreamReachability{
		UpstreamID: 7, PolicySelector: selector, State: model.ReachabilityUnreachable,
		ObservedNetworkRevision: 1, SettingsFingerprint: fp,
		ObservationToken: token, LastObservationOrder: 5,
	}
	tracker.ApplyCommitted(newer)
	tracker.ApplyCommitted(older) // 反转返回顺序：旧行不得覆盖
	if got := tracker.Snapshot(7); got == nil || got.State != model.ReachabilityReachable || got.LastObservationOrder != 10 {
		t.Fatalf("CAS kept wrong row: %+v", got)
	}
	if !tracker.OK(7, 1) {
		t.Fatal("reachable must be OK")
	}
	if tracker.Effective(7, 2) != model.ReachabilityUnknown {
		t.Fatal("network revision change must effective-unknown")
	}
	gate := NewUpstreamGate().WithTracker(tracker)
	if !gate.OK(7) {
		t.Fatal("gate facade should read tracker")
	}
	gate.Forget(7)
	if !gate.OK(7) {
		t.Fatal("forget returns optimistic OK")
	}
}

func TestReachabilityTracker_DNSFailureThenHTTPRecovery(t *testing.T) {
	settings := model.DefaultSettings()
	tracker := NewReachabilityTracker(staticSettings{settings})
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	policy, err := revisioncodec.BuildReachabilityEvidencePolicy(settings, selector)
	if err != nil {
		t.Fatal(err)
	}
	fp := revisioncodec.ReachabilitySettingsFingerprint(policy)
	token := revisioncodec.NewReachabilityToken(model.ReachabilityRevision{
		NetworkRevision: 3, SettingsFingerprint: fp,
	})
	tracker.ApplyCommitted(&model.UpstreamReachability{
		UpstreamID: 3, PolicySelector: selector, State: model.ReachabilityUnreachable,
		ObservedNetworkRevision: 3, SettingsFingerprint: fp,
		ObservationToken: token, LastObservationOrder: 1, LastErrorAt: time.Now().UnixMilli(),
	})
	if tracker.OK(3, 3) {
		t.Fatal("unreachable must block")
	}
	tracker.ApplyCommitted(&model.UpstreamReachability{
		UpstreamID: 3, PolicySelector: selector, State: model.ReachabilityReachable,
		ObservedNetworkRevision: 3, SettingsFingerprint: fp,
		ObservationToken: token, LastObservationOrder: 2,
	})
	if !tracker.OK(3, 3) {
		t.Fatal("http recovery must reopen")
	}
}

func TestUpstreamGateOKAtDoesNotTrustTheRowsOwnRevision(t *testing.T) {
	settings := model.DefaultSettings()
	tracker := NewReachabilityTracker(staticSettings{settings})
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	policy, err := revisioncodec.BuildReachabilityEvidencePolicy(settings, selector)
	if err != nil {
		t.Fatal(err)
	}
	fp := revisioncodec.ReachabilitySettingsFingerprint(policy)
	token := revisioncodec.NewReachabilityToken(model.ReachabilityRevision{
		NetworkRevision: 1, SettingsFingerprint: fp,
	})
	tracker.ApplyCommitted(&model.UpstreamReachability{
		UpstreamID: 4, PolicySelector: selector, State: model.ReachabilityUnreachable,
		ObservedNetworkRevision: 1, SettingsFingerprint: fp,
		ObservationToken: token, LastObservationOrder: 1, LastError: "dial",
	})
	gate := NewUpstreamGate().WithTracker(tracker)
	if gate.OKAt(4, 1) {
		t.Fatal("matching network revision must keep unreachable")
	}
	if !gate.OKAt(4, 2) {
		t.Fatal("a newer network revision must not keep the old unreachable verdict")
	}
	status := gate.StatusAt(4, 2)
	if !status.OK || status.Probed {
		t.Fatalf("stale row was still presented as the current L1 status: %+v", status)
	}
}
