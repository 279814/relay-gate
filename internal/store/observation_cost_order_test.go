package store

import (
	"context"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

// Execution, state and cost share one transaction; a failed cost write cannot leave a partial observation.
func TestCommitProbeObservation_CostWriteErrorRollsBackObservation(t *testing.T) {
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
	if err == nil {
		t.Fatal("cost write failure must reject the observation transaction")
	}
	if result.ExecutionStored || result.CostCharged {
		t.Fatalf("rolled back transaction reported committed data: %+v", result)
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
	if executions != 0 || reachRows != 0 {
		t.Fatalf("partial observation survived cost failure: executions=%d reachability=%d", executions, reachRows)
	}
	if costEvents != 0 {
		t.Fatalf("cost event should not exist after simulated failure, got %d", costEvents)
	}
}

func TestCommitProbeObservation_RecordsCostWithObservation(t *testing.T) {
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
	if !result.CostCharged {
		t.Fatal("CostCharged must be true after successful probe_cost_* commit")
	}

	var costEvents int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM probe_cost_event WHERE event_id=?`, "execution:"+execution.ID).Scan(&costEvents); err != nil {
		t.Fatal(err)
	}
	if costEvents != 1 {
		t.Fatalf("expected one cost event after successful observation, got %d", costEvents)
	}
}

func TestCommitProbeObservation_ReplayRepairsLegacyCostFromStoredExecution(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "legacy-cost-repair")
	now := time.Now().UnixMilli()
	execution := model.ProbeExecution{
		ID: "legacy-cost-gap", Trigger: model.TriggerManual, UpstreamID: up.ID,
		Endpoint: model.EndpointMessages, RecipeStorage: model.RecipeStorageEmbedded,
		RecipeOrigin: model.RecipeBasic, TemplateID: "builtin:cost-fixture", RecipeIdentityRevision: 1,
		RecipeBindingUse: model.BindingResolved, RecipeBindingFacts: model.RecipeBindingFacts{Use: model.BindingResolved, ResolvedLayer: model.ResolvedEmbedded},
		EvidenceHash: "immutable-cost-fixture", ObservationOrder: 1,
		SentAtMS: now, DoneAtMS: now + 1, EstimatedInputTokens: 7, ObservedOutputTokens: 2,
		Final: true, Success: true, ErrorClass: model.ErrorNone, Capability: model.CapabilityUnknown,
	}
	if err := st.InsertProbeExecution(context.Background(), &execution); err != nil {
		t.Fatal(err)
	}
	// Reproduce the old writer's committed execution with a missing cost event.
	if _, err := st.db.Exec(`DELETE FROM probe_cost_event`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`DELETE FROM probe_cost_daily`); err != nil {
		t.Fatal(err)
	}
	execution.EstimatedInputTokens = 999 // A replay must not replace immutable stored evidence.
	for repeated := 0; repeated < 2; repeated++ {
		result, err := st.CommitProbeObservation(context.Background(), &model.ProbeObservation{Execution: execution}, &fakeStateReducer{})
		if err != nil || !result.CostCharged {
			t.Fatalf("legacy cost repair failed: charged=%v err=%v", result.CostCharged, err)
		}
	}
	var requests, tokens int64
	if err := st.db.QueryRow(`SELECT SUM(requests),SUM(estimated_input_tokens+observed_output_tokens) FROM probe_cost_daily`).Scan(&requests, &tokens); err != nil {
		t.Fatal(err)
	}
	if requests != 1 || tokens != 9 {
		t.Fatalf("replay changed or duplicated immutable cost: requests=%d tokens=%d", requests, tokens)
	}
}

// A stale state result still costs money when its synthetic request was sent.
func TestCommitProbeObservation_ConfigStaleRecordsActualSentCost(t *testing.T) {
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
	if !result.CostCharged {
		t.Fatal("sent synthetic cost disappeared because its state result was stale")
	}

	var costEvents, costDaily int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM probe_cost_event WHERE event_id=?`, "execution:"+execution.ID).Scan(&costEvents); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM probe_cost_daily WHERE upstream_id=?`, upstream.ID).Scan(&costDaily); err != nil {
		t.Fatal(err)
	}
	if costEvents != 1 || costDaily != 1 {
		t.Fatalf("sent stale synthetic cost must persist exactly once: events=%d daily=%d", costEvents, costDaily)
	}
}
