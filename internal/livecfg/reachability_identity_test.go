package livecfg

import (
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

func TestReachabilityUsesPublishedIncarnationTokenWithoutWaitingForRefresh(t *testing.T) {
	st := testStore(t)
	up := &model.Upstream{Name: "incarnation", BaseURL: "https://example.test", APIKey: "fixture-reachability-private-key", Enabled: true}
	if err := st.CreateUpstream(up); err != nil {
		t.Fatal(err)
	}
	source, _ := newSource(t, st)
	if _, err := source.Bundle(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := source.ProbeSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	expected, err := snapshot.ReachabilityExpectation(up.ID, selector)
	if err != nil {
		t.Fatal(err)
	}
	if expected.Revision.CreatedAt == 0 {
		t.Fatal("fixture must be a real persisted incarnation")
	}
	row := &model.UpstreamReachability{UpstreamID: up.ID, ObservedCreatedAt: expected.Revision.CreatedAt, State: model.ReachabilityUnreachable, PolicySelector: selector, ObservedNetworkRevision: expected.Revision.NetworkRevision, SettingsFingerprint: expected.Revision.SettingsFingerprint, ObservationToken: expected.ObservationToken, LastObservationOrder: 1}
	tracker := health.NewReachabilityTracker(source)
	tracker.ApplyCommitted(row)
	if got := tracker.Effective(up.ID, up.NetworkRevision); got != model.ReachabilityUnreachable {
		t.Fatalf("real committed row was not effective: %s", got)
	}

	// A refresh can hold Source's write lock while reading SQLite. Routing's
	// optional reachability evidence must skip, never wait on that database I/O.
	source.mu.Lock()
	done := make(chan model.ReachabilityState, 1)
	go func() { done <- tracker.Effective(up.ID, up.NetworkRevision) }()
	select {
	case got := <-done:
		if got != model.ReachabilityUnknown {
			t.Errorf("busy published view=%s", got)
		}
	case <-time.After(100 * time.Millisecond):
		source.mu.Unlock()
		<-done
		t.Fatal("reachability waited for refresh")
	}
	source.mu.Unlock()

	// Model the state after delete/recreate reused a numeric id and reset its
	// revisions, while an old SQL commit's return is still delayed.
	if _, err := st.DB().Exec(`UPDATE upstream SET created_at=created_at+1000 WHERE id=?`, up.ID); err != nil {
		t.Fatal(err)
	}
	if err := source.Refresh(); err != nil {
		t.Fatal(err)
	}
	tracker.Invalidate(up.ID)
	tracker.ApplyCommitted(row)
	if got := tracker.Effective(up.ID, up.NetworkRevision); got != model.ReachabilityUnknown {
		t.Fatalf("old incarnation was revived: %s", got)
	}
	newSnapshot, err := source.ProbeSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	newExpected, err := newSnapshot.ReachabilityExpectation(up.ID, selector)
	if err != nil {
		t.Fatal(err)
	}
	current := *row
	current.ObservedCreatedAt = newExpected.Revision.CreatedAt
	current.ObservationToken = newExpected.ObservationToken
	current.LastObservationOrder = 2
	tracker.ApplyCommitted(&current)
	tracker.ApplyCommitted(row)
	if got := tracker.Effective(up.ID, up.NetworkRevision); got != model.ReachabilityUnreachable {
		t.Fatalf("late old token replaced the current committed row: %s", got)
	}
}
