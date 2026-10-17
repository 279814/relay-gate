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
	tracker.Invalidate(7)
	if tracker.Snapshot(7) != nil || !tracker.OK(7, 1) {
		t.Fatal("invalidated evidence must return optimistic unknown")
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

// Empty ObservationToken must not clobber a non-empty revision token even
// with a higher UnixMilli order. Non-empty still replaces an empty placeholder.
func TestReachabilityTracker_EmptyTokenDoesNotClobberNonEmpty(t *testing.T) {
	settings := model.DefaultSettings()
	tracker := NewReachabilityTracker(staticSettings{settings})
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	policy, err := revisioncodec.BuildReachabilityEvidencePolicy(settings, selector)
	if err != nil {
		t.Fatal(err)
	}
	fp := revisioncodec.ReachabilitySettingsFingerprint(policy)
	tracker.ApplyCommitted(&model.UpstreamReachability{
		UpstreamID: 7, PolicySelector: selector, State: model.ReachabilityReachable,
		ObservedNetworkRevision: 1, SettingsFingerprint: fp,
		ObservationToken: "revision-token", LastObservationOrder: 42,
	})
	tracker.ApplyCommitted(&model.UpstreamReachability{
		UpstreamID: 7, PolicySelector: selector, State: model.ReachabilityUnreachable,
		ObservedNetworkRevision: 1, SettingsFingerprint: fp,
		ObservationToken: "", LastObservationOrder: 1_700_000_000_000,
	})
	got := tracker.Snapshot(7)
	if got == nil || got.ObservationToken != "revision-token" || got.LastObservationOrder != 42 ||
		got.State != model.ReachabilityReachable {
		t.Fatalf("empty token must not clobber non-empty: %+v", got)
	}

	tracker.ApplyCommitted(&model.UpstreamReachability{
		UpstreamID: 8, PolicySelector: selector, State: model.ReachabilityUnreachable,
		ObservedNetworkRevision: 1, SettingsFingerprint: fp,
		ObservationToken: "", LastObservationOrder: 1_700_000_000_000,
	})
	tracker.ApplyCommitted(&model.UpstreamReachability{
		UpstreamID: 8, PolicySelector: selector, State: model.ReachabilityReachable,
		ObservedNetworkRevision: 1, SettingsFingerprint: fp,
		ObservationToken: "revision-token", LastObservationOrder: 42,
	})
	got = tracker.Snapshot(8)
	if got == nil || got.ObservationToken != "revision-token" || got.LastObservationOrder != 42 ||
		got.State != model.ReachabilityReachable {
		t.Fatalf("non-empty must still replace empty placeholder: %+v", got)
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

func TestReachabilityTrackerDoesNotTrustTheRowsOwnNetworkRevision(t *testing.T) {
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
	if tracker.OK(4, 1) {
		t.Fatal("matching network revision must keep unreachable")
	}
	if !tracker.OK(4, 2) {
		t.Fatal("a newer network revision must not keep the old unreachable verdict")
	}
	if state := tracker.Effective(4, 2); state != model.ReachabilityUnknown {
		t.Fatalf("stale evidence was still presented as current: %s", state)
	}
}

type migratedReachabilityIdentitySource struct {
	staticSettings
	revision model.ReachabilityRevision
}

func (s *migratedReachabilityIdentitySource) CurrentReachabilityRevision(int64, model.EvidencePolicySelector) (model.ReachabilityRevision, bool) {
	return s.revision, true
}

// A reused numeric ID must reject committed evidence from the deleted lifetime,
// even when both lifetimes start with the same network revision and token.
func TestReachabilityTracker_LateCommittedLifetimeCannotPoisonReusedID(t *testing.T) {
	settings := model.DefaultSettings()
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	policy, err := revisioncodec.BuildReachabilityEvidencePolicy(settings, selector)
	if err != nil {
		t.Fatal(err)
	}
	revision := model.ReachabilityRevision{NetworkRevision: 1, CreatedAt: 100, SettingsFingerprint: revisioncodec.ReachabilitySettingsFingerprint(policy)}
	source := &migratedReachabilityIdentitySource{staticSettings: staticSettings{settings}, revision: revision}
	tracker := NewReachabilityTracker(source)
	const id int64 = 7
	old := &model.UpstreamReachability{UpstreamID: id, State: model.ReachabilityUnreachable, PolicySelector: selector, ObservedNetworkRevision: 1, ObservedCreatedAt: revision.CreatedAt, SettingsFingerprint: revision.SettingsFingerprint, ObservationToken: revisioncodec.NewReachabilityToken(revision), LastObservationOrder: 10}
	tracker.ApplyCommitted(old)
	if tracker.OK(id, 1) {
		t.Fatal("setup: unreachable evidence must block")
	}

	tracker.Invalidate(id)
	source.revision.CreatedAt = 200
	if !tracker.OK(id, 1) {
		t.Fatal("deleted lifetime must return optimistic unknown")
	}

	tracker.ApplyCommitted(old)
	if !tracker.OK(id, 1) || tracker.Snapshot(id) != nil {
		t.Fatal("old committed failure resurrected deleted lifetime")
	}

	current := *old
	current.ObservedCreatedAt = source.revision.CreatedAt
	current.LastObservationOrder = 1
	tracker.ApplyCommitted(&current)
	if tracker.OK(id, 1) {
		t.Fatal("current lifetime's committed failure was ignored")
	}
	oldSuccess := *old
	oldSuccess.State = model.ReachabilityReachable
	oldSuccess.LastObservationOrder = 100
	tracker.ApplyCommitted(&oldSuccess)
	if tracker.OK(id, 1) {
		t.Fatal("old lifetime's late success poisoned current failure")
	}
}
