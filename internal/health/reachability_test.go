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

// Different ObservationToken is a new incarnation: it must replace a prior
// registry row even when its LastObservationOrder is lower (e.g. after a
// placeholder high order from another writer).
func TestReachabilityTracker_DifferentTokenLowerOrderReplaces(t *testing.T) {
	settings := model.DefaultSettings()
	tracker := NewReachabilityTracker(staticSettings{settings})
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	policy, err := revisioncodec.BuildReachabilityEvidencePolicy(settings, selector)
	if err != nil {
		t.Fatal(err)
	}
	fp := revisioncodec.ReachabilitySettingsFingerprint(policy)
	tracker.ApplyCommitted(&model.UpstreamReachability{
		UpstreamID: 7, PolicySelector: selector, State: model.ReachabilityUnreachable,
		ObservedNetworkRevision: 1, SettingsFingerprint: fp,
		ObservationToken: "old-incarnation", LastObservationOrder: 1_700_000_000_000,
	})
	tracker.ApplyCommitted(&model.UpstreamReachability{
		UpstreamID: 7, PolicySelector: selector, State: model.ReachabilityReachable,
		ObservedNetworkRevision: 1, SettingsFingerprint: fp,
		ObservationToken: "new-incarnation", LastObservationOrder: 42,
	})
	got := tracker.Snapshot(7)
	if got == nil || got.ObservationToken != "new-incarnation" || got.LastObservationOrder != 42 ||
		got.State != model.ReachabilityReachable {
		t.Fatalf("new token with lower order must replace: %+v", got)
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

// Forget 后迟到的 L1 Report 不得按 id 写回：否则同 id 新站会被旧
// unreachable/reachable 污染（与 Tracker.Report-after-Forget 同类）。
func TestUpstreamGate_ReportAfterForgetDoesNotPoisonReusedID(t *testing.T) {
	gate := NewUpstreamGate()
	const id int64 = 7
	gen := gate.EnsureGeneration(id)
	_ = gate.Report(id, gen, false, errString("dial"))
	if gate.OK(id) {
		t.Fatal("setup: gate should be down")
	}

	gate.Forget(id)
	if !gate.OK(id) {
		t.Fatal("Forget must return optimistic OK")
	}

	// Late probe from the deleted incarnation.
	if gate.Report(id, gen, false, errString("dial")) {
		t.Fatal("stale report must not claim recovery")
	}
	if !gate.OK(id) {
		t.Fatal("stale generation report must not mark reused id down")
	}

	newGen := gate.EnsureGeneration(id)
	if newGen == gen {
		t.Fatal("reused id must receive a new generation")
	}
	if gate.Report(id, newGen, false, errString("dial")) {
		t.Fatal("fresh failure is not recovery")
	}
	if gate.OK(id) {
		t.Fatal("current generation failure should apply")
	}
	// Stale success must not clear the new down state.
	if gate.Report(id, gen, true, nil) {
		t.Fatal("stale success must not recover reused id")
	}
	if gate.OK(id) {
		t.Fatal("stale success poisoned reused id")
	}
}

type errString string

func (e errString) Error() string { return string(e) }
