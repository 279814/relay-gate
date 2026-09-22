package probe

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/observation"
	"github.com/279814/relay-gate/internal/revisioncodec"
	"github.com/279814/relay-gate/internal/store"
)

type recordingCommitter struct {
	mu      sync.Mutex
	calls   []*model.ProbeObservation
	results []model.ProbeApplyResult
	err     error
}

func (c *recordingCommitter) CommitProbeObservation(_ context.Context, value *model.ProbeObservation, _ observation.StateReducer) (model.ProbeApplyResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, value)
	if c.err != nil {
		return model.ProbeApplyResult{}, c.err
	}
	if len(c.results) == 0 {
		return model.ProbeApplyResult{ExecutionStored: true, Reachability: model.ApplyNotApplicable, Capability: model.ApplyNotApplicable}, nil
	}
	result := c.results[0]
	c.results = c.results[1:]
	return result, nil
}

func TestResultRecorder_AppliesRegistriesOnlyOnApplyCurrent(t *testing.T) {
	settings := model.DefaultSettings()
	reach := health.NewReachabilityTracker(capSettings{settings})
	caps := NewCapabilityRegistry(capSettings{settings})
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	policy, err := revisioncodec.BuildReachabilityEvidencePolicy(settings, selector)
	if err != nil {
		t.Fatal(err)
	}
	fp := revisioncodec.ReachabilitySettingsFingerprint(policy)
	token := revisioncodec.NewReachabilityToken(model.ReachabilityRevision{NetworkRevision: 1, SettingsFingerprint: fp})

	newer := &model.UpstreamReachability{
		UpstreamID: 1, PolicySelector: selector, State: model.ReachabilityReachable,
		ObservedNetworkRevision: 1, SettingsFingerprint: fp, ObservationToken: token,
		LastObservationOrder: 20,
	}
	older := &model.UpstreamReachability{
		UpstreamID: 1, PolicySelector: selector, State: model.ReachabilityUnreachable,
		ObservedNetworkRevision: 1, SettingsFingerprint: fp, ObservationToken: token,
		LastObservationOrder: 10,
	}
	committer := &recordingCommitter{results: []model.ProbeApplyResult{
		{ExecutionStored: true, Reachability: model.ApplyCurrent, CommittedReachability: newer},
		{ExecutionStored: true, Reachability: model.ApplyCurrent, CommittedReachability: older},
	}}
	recorder := NewResultRecorder(committer, health.NewObservationReducer(nil), reach, caps)

	if _, err := recorder.Record(context.Background(), &model.ProbeObservation{Execution: model.ProbeExecution{ID: "a"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := recorder.Record(context.Background(), &model.ProbeObservation{Execution: model.ProbeExecution{ID: "b"}}); err != nil {
		t.Fatal(err)
	}
	if got := reach.Snapshot(1); got == nil || got.LastObservationOrder != 20 || got.State != model.ReachabilityReachable {
		t.Fatalf("CAS must keep higher order after reversed returns: %+v", got)
	}
}

func TestResultRecorder_RealStoreRoundTrip(t *testing.T) {
	cipher, err := store.NewCipher("test-encryption-key-32-bytes-long")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "rr.db"), cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	upstream := &model.Upstream{Name: "rr", BaseURL: "https://rr.example", APIKey: "sk-rr", Enabled: true}
	if err := st.CreateUpstream(upstream); err != nil {
		t.Fatal(err)
	}
	settings := model.DefaultSettings()
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	policy, err := revisioncodec.BuildReachabilityEvidencePolicy(settings, selector)
	if err != nil {
		t.Fatal(err)
	}
	revision := model.ReachabilityRevision{
		NetworkRevision: upstream.NetworkRevision, SettingsFingerprint: revisioncodec.ReachabilitySettingsFingerprint(policy),
	}
	expectation := &model.ReachabilityExpectation{
		UpstreamID: upstream.ID, PolicySelector: selector, Revision: revision,
		ObservationToken: revisioncodec.NewReachabilityToken(revision),
	}
	execution := model.ProbeExecution{
		ID: "rr-1", Trigger: model.TriggerScheduled, UpstreamID: upstream.ID,
		UpstreamNetworkRevision:    upstream.NetworkRevision,
		ReachabilityPolicySelector: selector, ReachabilitySettingsFingerprint: revision.SettingsFingerprint,
		ReachabilityToken: expectation.ObservationToken, Endpoint: model.EndpointModels,
		RecipeStorage: model.RecipeStorageEmbedded, RecipeOrigin: model.RecipeBasic,
		TemplateID: "builtin:models", RecipeIdentityRevision: 1,
		RecipeBindingUse: model.BindingResolved, RecipeBindingFacts: model.RecipeBindingFacts{
			Use: model.BindingResolved, ResolvedLayer: model.ResolvedEmbedded,
		},
		EvidenceHash: "rr-evidence", ErrorClass: model.ErrorNone, Capability: model.CapabilityUnknown,
		Reachable: true, Final: true, Success: true, ObservationOrder: 1, SentAtMS: 1, DoneAtMS: 2,
		StatusCode: 200,
	}
	hash, err := revisioncodec.NewProbeEvidenceHash(model.ProbeObservation{
		Execution: execution, ReachabilityExpectation: expectation, ReachabilityPolicy: &policy.State,
	})
	if err != nil {
		t.Fatal(err)
	}
	execution.EvidenceHash = hash

	reach := health.NewReachabilityTracker(capSettings{settings})
	caps := NewCapabilityRegistry(capSettings{settings})
	recorder := NewResultRecorder(st, health.NewObservationReducer(nil), reach, caps)
	result, err := recorder.Record(context.Background(), &model.ProbeObservation{
		Execution: execution, ReachabilityExpectation: expectation, ReachabilityPolicy: &policy.State,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Reachability != model.ApplyCurrent || result.CommittedReachability == nil {
		t.Fatalf("result=%+v", result)
	}
	if snap := reach.Snapshot(upstream.ID); snap == nil || snap.LastObservationOrder != 1 || snap.ConsecutiveOK != 1 {
		t.Fatalf("registry not updated: %+v", snap)
	}
	// 默认 OKThreshold>1 时首次成功保持 unknown；Registry 仍已写入。
	if !reach.OK(upstream.ID, upstream.NetworkRevision) {
		t.Fatal("unknown/reachable must remain OK for L2 gating")
	}
}
