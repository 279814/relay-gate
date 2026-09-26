package store

import (
	"context"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

// Cost write failure after a successful probe must not undo capability/health.
func TestCommitProbeObservation_CostWriteErrorKeepsObservation(t *testing.T) {
	store := testStore(t)
	upstream := mkUpstream(t, store, "observation-cost-order")
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
	expectation := &model.ReachabilityExpectation{
		UpstreamID: upstream.ID, PolicySelector: selector, Revision: revision,
		ObservationToken: revisioncodec.NewReachabilityToken(revision),
	}
	execution := minimalReachabilityExecution(t, store, upstream, expectation, "exec-cost-fail", "evidence-cost-fail", 1)

	if _, err := store.db.Exec(`CREATE TRIGGER deny_probe_cost_event
		BEFORE INSERT ON probe_cost_event
		BEGIN SELECT RAISE(ABORT, 'simulated cost write failure'); END`); err != nil {
		t.Fatal(err)
	}

	result, err := store.CommitProbeObservation(context.Background(), &model.ProbeObservation{
		Execution: execution, ReachabilityExpectation: expectation, ReachabilityPolicy: &policy.State,
	}, &fakeStateReducer{})
	if err != nil {
		t.Fatalf("observation must commit despite cost failure: %v", err)
	}
	if !result.ExecutionStored || result.Reachability != model.ApplyCurrent {
		t.Fatalf("result=%+v", result)
	}
	if result.CommittedReachability == nil || result.CommittedReachability.LastObservationOrder != 1 {
		t.Fatalf("reachability must persist: %+v", result.CommittedReachability)
	}

	var executions, reachRows, costEvents int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM probe_execution WHERE id=?`, execution.ID).Scan(&executions); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM upstream_reachability WHERE upstream_id=?`, upstream.ID).Scan(&reachRows); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM probe_cost_event WHERE event_id=?`, "execution:"+execution.ID).Scan(&costEvents); err != nil {
		t.Fatal(err)
	}
	if executions != 1 || reachRows != 1 {
		t.Fatalf("observation rolled back: executions=%d reachability=%d", executions, reachRows)
	}
	if costEvents != 0 {
		t.Fatalf("cost event should not exist after simulated failure, got %d", costEvents)
	}
}

func TestCommitProbeObservation_RecordsCostAfterObservationCommit(t *testing.T) {
	store := testStore(t)
	upstream := mkUpstream(t, store, "observation-cost-ok")
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
	expectation := &model.ReachabilityExpectation{
		UpstreamID: upstream.ID, PolicySelector: selector, Revision: revision,
		ObservationToken: revisioncodec.NewReachabilityToken(revision),
	}
	execution := minimalReachabilityExecution(t, store, upstream, expectation, "exec-cost-ok", "evidence-cost-ok", 1)

	result, err := store.CommitProbeObservation(context.Background(), &model.ProbeObservation{
		Execution: execution, ReachabilityExpectation: expectation, ReachabilityPolicy: &policy.State,
	}, &fakeStateReducer{})
	if err != nil {
		t.Fatal(err)
	}
	if !result.ExecutionStored || result.Reachability != model.ApplyCurrent {
		t.Fatalf("result=%+v", result)
	}

	var costEvents int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM probe_cost_event WHERE event_id=?`, "execution:"+execution.ID).Scan(&costEvents); err != nil {
		t.Fatal(err)
	}
	if costEvents != 1 {
		t.Fatalf("expected one cost event after successful observation, got %d", costEvents)
	}
}

// A mismatched revision is ApplyConfigStale: execution may still be stored, but
// probe_cost_event / probe_cost_daily must not be charged.
func TestCommitProbeObservation_ConfigStaleSkipsCost(t *testing.T) {
	store := testStore(t)
	upstream := mkUpstream(t, store, "observation-cost-stale")
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
	expectation := &model.ReachabilityExpectation{
		UpstreamID: upstream.ID, PolicySelector: selector, Revision: revision,
		ObservationToken: revisioncodec.NewReachabilityToken(revision),
	}
	execution := minimalReachabilityExecution(t, store, upstream, expectation, "exec-cost-stale", "evidence-cost-stale", 1)

	// Bump network revision so the expectation no longer matches current config.
	if _, err := store.db.Exec(`UPDATE upstream SET network_revision=network_revision+1 WHERE id=?`, upstream.ID); err != nil {
		t.Fatal(err)
	}

	result, err := store.CommitProbeObservation(context.Background(), &model.ProbeObservation{
		Execution: execution, ReachabilityExpectation: expectation, ReachabilityPolicy: &policy.State,
	}, &fakeStateReducer{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Reachability != model.ApplyConfigStale {
		t.Fatalf("disposition=%s want config_stale", result.Reachability)
	}

	var costEvents, costDaily int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM probe_cost_event WHERE event_id=?`, "execution:"+execution.ID).Scan(&costEvents); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM probe_cost_daily WHERE upstream_id=?`, upstream.ID).Scan(&costDaily); err != nil {
		t.Fatal(err)
	}
	if costEvents != 0 || costDaily != 0 {
		t.Fatalf("stale probe must not charge cost: events=%d daily=%d", costEvents, costDaily)
	}
}
