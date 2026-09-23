package store

import (
	"context"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

// Delete + recreate can reuse a SQLite rowid (especially if the sequence is
// reset). NetworkRevision alone restarts at 1, so a late L1 that started on
// the old row must not ApplyCurrent on the new incarnation.
func TestCommitProbeObservation_ReusedIDSameNetworkRevisionIsConfigStale(t *testing.T) {
	st := testStore(t)
	upstream := mkUpstream(t, st, "reuse-a")
	oldID := upstream.ID
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	policy, err := revisioncodec.BuildReachabilityEvidencePolicy(model.DefaultSettings(), selector)
	if err != nil {
		t.Fatal(err)
	}
	revision := model.ReachabilityRevision{
		NetworkRevision:     upstream.NetworkRevision,
		CreatedAt:           upstream.CreatedAt,
		SettingsFingerprint: revisioncodec.ReachabilitySettingsFingerprint(policy),
	}
	expectation := &model.ReachabilityExpectation{UpstreamID: oldID, PolicySelector: selector, Revision: revision}
	expectation.ObservationToken = revisioncodec.NewReachabilityToken(revision)
	late := minimalReachabilityExecution(t, st, upstream, expectation, "late-reuse", "ev-reuse", 5)
	late.Reachable = false
	late.Success = false
	late.ErrorClass = model.ErrorUnreachable
	late.StatusCode = 0

	if err := st.DeleteUpstream(oldID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := st.db.Exec(`DELETE FROM sqlite_sequence WHERE name='upstream'`); err != nil {
		t.Fatalf("reset sequence: %v", err)
	}
	if _, err := st.db.Exec(`DELETE FROM sqlite_sequence WHERE name='upstream_endpoint'`); err != nil {
		t.Fatalf("reset endpoint sequence: %v", err)
	}
	// Distinct created_at from the deleted row (same ms would still be a bug
	// if CreatedAt were omitted from the revision check).
	time.Sleep(2 * time.Millisecond)
	neu := &model.Upstream{Name: "reuse-b", BaseURL: "https://b.example", APIKey: "sk-bbbbbbbbbbbb", Enabled: true}
	if err := st.CreateUpstream(neu); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	if neu.ID != oldID {
		t.Fatalf("forced reuse failed: new id=%d old=%d", neu.ID, oldID)
	}
	if neu.NetworkRevision != revision.NetworkRevision {
		t.Fatalf("NetworkRevision=%d want %d (incarnation must not rely on a bump)", neu.NetworkRevision, revision.NetworkRevision)
	}
	if neu.CreatedAt == revision.CreatedAt {
		t.Fatal("recreated upstream must have a distinct created_at")
	}
	page, err := st.ListEndpointsPage(context.Background(), model.EndpointFilter{
		UpstreamID: neu.ID, Endpoint: model.EndpointModels,
	})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("new models endpoint=%+v err=%v", page, err)
	}
	late.EndpointID = page.Items[0].ID
	late.EndpointRevision = page.Items[0].Revision

	reducer := &fakeStateReducer{}
	result, err := st.CommitProbeObservation(context.Background(), &model.ProbeObservation{
		Execution: late, ReachabilityExpectation: expectation, ReachabilityPolicy: &policy.State,
	}, reducer)
	if err != nil {
		t.Fatal(err)
	}
	if result.Reachability != model.ApplyConfigStale {
		t.Fatalf("disposition=%s want config_stale (CreatedAt incarnation mismatch)", result.Reachability)
	}
	if reducer.reachCalls != 0 {
		t.Fatalf("reducer must not run for stale incarnation, calls=%d", reducer.reachCalls)
	}
}
