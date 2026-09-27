package probe

import (
	"context"
	"net/http"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/observation"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

var (
	recoveryL1Selector = model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	recoveryL2Selector = model.EvidencePolicySelector{
		Kind: model.EvidenceL2, Endpoint: model.EndpointMessages, TimeoutProfile: model.TimeoutL2Standard,
	}
)

func recoveryRow(t *testing.T, selector model.EvidencePolicySelector, networkRevision int64,
	state model.ReachabilityState, order int64) *model.UpstreamReachability {

	t.Helper()
	policy, err := revisioncodec.BuildReachabilityEvidencePolicy(model.DefaultSettings(), selector)
	if err != nil {
		t.Fatal(err)
	}
	fp := revisioncodec.ReachabilitySettingsFingerprint(policy)
	return &model.UpstreamReachability{
		UpstreamID: 10, PolicySelector: selector, State: state,
		ObservedNetworkRevision: networkRevision, SettingsFingerprint: fp,
		ObservationToken: revisioncodec.NewReachabilityToken(model.ReachabilityRevision{
			NetworkRevision: networkRevision, SettingsFingerprint: fp,
		}),
		LastObservationOrder: order,
	}
}

func l2Execution(trigger model.ProbeTrigger) model.ProbeExecution {
	return model.ProbeExecution{
		ID: "l2", Trigger: trigger, UpstreamID: 10, Reachable: true, StatusCode: 200,
		Endpoint: model.EndpointMessages, ReachabilityPolicySelector: recoveryL2Selector,
	}
}

func newRecoveryRecorderHarness(t *testing.T, results ...model.ProbeApplyResult) (*schedHarness, *health.ReachabilityTracker, *ResultRecorder) {
	t.Helper()
	h := newSchedHarness(t, 1, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h.track.states[100] = model.StateDead
	reach := health.NewReachabilityTracker(nil)
	recorder := NewResultRecorder(&recordingCommitter{results: results},
		health.NewObservationReducer(nil), reach, nil).
		WithReachabilityRecovered(h.sched.OnReachabilityRecovered)
	return h, reach, recorder
}

// §8.10：「Reachability 从 unreachable 恢复会触发即时调度」不限于 L1 轮次。
// 手动测试或定时 L2 的已提交观察先让站离开 unreachable 时，dead Route 同样
// 必须立即排 L2；否则之后的 L1 看到的已不是 unreachable，永远不会补发。
func TestResultRecorder_NonL1CommitLeavingUnreachableTriggersDeadRoutes(t *testing.T) {
	for _, trigger := range []model.ProbeTrigger{model.TriggerManual, model.TriggerScheduled} {
		t.Run(string(trigger), func(t *testing.T) {
			h, reach, recorder := newRecoveryRecorderHarness(t, model.ProbeApplyResult{
				ExecutionStored: true, Reachability: model.ApplyCurrent,
				CommittedReachability: recoveryRow(t, recoveryL2Selector, 0, model.ReachabilityUnknown, 2),
			})
			reach.ApplyCommitted(recoveryRow(t, recoveryL1Selector, 0, model.ReachabilityUnreachable, 1))
			if reach.OK(10, 0) {
				t.Fatal("前置条件：站应 unreachable")
			}

			exec := l2Execution(trigger)
			if _, err := recorder.Record(context.Background(), &model.ProbeObservation{Execution: exec}); err != nil {
				t.Fatal(err)
			}
			_, _, _, triggered, _ := h.track.snapshot()
			if len(triggered) != 1 || triggered[0] != 100 {
				t.Fatalf("非 L1 提交离开 unreachable 应触发 dead Route 100 的 L2，得到 %v", triggered)
			}
		})
	}
}

func TestResultRecorder_RecoveryHookDoesNotFireWithoutLeavingUnreachable(t *testing.T) {
	unreachablePrior := func(t *testing.T) *model.UpstreamReachability {
		return recoveryRow(t, recoveryL1Selector, 0, model.ReachabilityUnreachable, 1)
	}
	current := func(row *model.UpstreamReachability) model.ProbeApplyResult {
		return model.ProbeApplyResult{Reachability: model.ApplyCurrent, CommittedReachability: row}
	}
	cases := []struct {
		name   string
		prior  func(t *testing.T) *model.UpstreamReachability
		result func(t *testing.T) model.ProbeApplyResult
		exec   model.ProbeExecution
	}{
		{
			name:  "still unreachable",
			prior: unreachablePrior,
			result: func(t *testing.T) model.ProbeApplyResult {
				return current(recoveryRow(t, recoveryL2Selector, 0, model.ReachabilityUnreachable, 2))
			},
			exec: func() model.ProbeExecution {
				e := l2Execution(model.TriggerManual)
				e.Reachable, e.StatusCode = false, 0
				return e
			}(),
		},
		{
			name: "blip below threshold",
			prior: func(t *testing.T) *model.UpstreamReachability {
				row := recoveryRow(t, recoveryL1Selector, 0, model.ReachabilityUnknown, 1)
				row.ConsecutiveFail = 1
				return row
			},
			result: func(t *testing.T) model.ProbeApplyResult {
				return current(recoveryRow(t, recoveryL2Selector, 0, model.ReachabilityReachable, 2))
			},
			exec: l2Execution(model.TriggerManual),
		},
		{
			name: "already reachable 404",
			prior: func(t *testing.T) *model.UpstreamReachability {
				return recoveryRow(t, recoveryL1Selector, 0, model.ReachabilityReachable, 1)
			},
			result: func(t *testing.T) model.ProbeApplyResult {
				return current(recoveryRow(t, recoveryL2Selector, 0, model.ReachabilityReachable, 2))
			},
			exec: func() model.ProbeExecution {
				e := l2Execution(model.TriggerManual)
				e.StatusCode = 404
				return e
			}(),
		},
		{
			name:  "scheduled L1 round is left to runL1",
			prior: unreachablePrior,
			result: func(t *testing.T) model.ProbeApplyResult {
				return current(recoveryRow(t, recoveryL1Selector, 0, model.ReachabilityUnknown, 2))
			},
			exec: model.ProbeExecution{ID: "l1", Trigger: model.TriggerScheduled, UpstreamID: 10, Reachable: true,
				StatusCode: 200, Endpoint: model.EndpointModels, ReachabilityPolicySelector: recoveryL1Selector},
		},
		{
			name:  "superseded commit",
			prior: unreachablePrior,
			result: func(t *testing.T) model.ProbeApplyResult {
				return model.ProbeApplyResult{Reachability: model.ApplySuperseded}
			},
			exec: l2Execution(model.TriggerManual),
		},
		{
			name:  "prior unreachable on stale network revision",
			prior: unreachablePrior,
			result: func(t *testing.T) model.ProbeApplyResult {
				return current(recoveryRow(t, recoveryL2Selector, 1, model.ReachabilityUnknown, 2))
			},
			exec: l2Execution(model.TriggerManual),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, reach, recorder := newRecoveryRecorderHarness(t, tc.result(t))
			reach.ApplyCommitted(tc.prior(t))
			exec := tc.exec
			if _, err := recorder.Record(context.Background(), &model.ProbeObservation{Execution: exec}); err != nil {
				t.Fatal(err)
			}
			if _, _, _, triggered, _ := h.track.snapshot(); len(triggered) != 0 {
				t.Fatalf("未离开 unreachable 不得触发 dead Route 的 L2，得到 %v", triggered)
			}
		})
	}
}

// reducingCommitter 让 reachReducingRecorder 充当 ObservationCommitter：它只算
// committed 行（写进自己的一次性 tracker），真实 Registry 由 ResultRecorder 更新。
type reducingCommitter struct{ inner *reachReducingRecorder }

func (c reducingCommitter) CommitProbeObservation(ctx context.Context, v *model.ProbeObservation,
	_ observation.StateReducer) (model.ProbeApplyResult, error) {
	return c.inner.Record(ctx, v)
}

func newRecoveryL1Harness(t *testing.T) (*l1RecoveryHarness, *ResultRecorder) {
	t.Helper()
	h := newL1RecoveryHarness(t)
	committer := reducingCommitter{inner: &reachReducingRecorder{t: t,
		reach: health.NewReachabilityTracker(nil), reducer: health.NewObservationReducer(nil),
		settings: model.DefaultSettings()}}
	recorder := NewResultRecorder(committer, health.NewObservationReducer(nil), h.reach, nil).
		WithReachabilityRecovered(h.sched.OnReachabilityRecovered)
	h.recorder = committer.inner
	h.sched.WithExecutor(NewExecutor(testTargets(), nil, nil,
		ManagerTransports{Manager: outbound.NewManager()},
		recorder, AlwaysOpenAdmission(), WallClock(), discardLogger()))
	return h, recorder
}

// 生产装配下 L1 轮次的恢复只触发一次：runL1 自己发，recorder 回调跳过。
func TestScheduler_L1RecoveryThroughResultRecorderFiresOnce(t *testing.T) {
	h, _ := newRecoveryL1Harness(t)

	h.l1(t, 0)
	h.l1(t, 1)
	h.l1(t, 1)
	if h.gate.OKAt(10, 0) {
		t.Fatal("前置条件：连续两次失败后站应 unreachable")
	}
	h.l1(t, 0)
	_, _, _, triggered, _ := h.track.snapshot()
	if len(triggered) != 1 || triggered[0] != 100 {
		t.Fatalf("L1 恢复应恰好触发一次 dead Route 100 的 L2，得到 %v", triggered)
	}
}

// 手动测试先让站离开 unreachable：立即触发一次；随后的成功 L1 已不是恢复，不再重复。
func TestScheduler_ManualCommitLeavingUnreachableTriggersBeforeL1(t *testing.T) {
	h, recorder := newRecoveryL1Harness(t)

	h.l1(t, 0)
	h.l1(t, 1)
	h.l1(t, 1)
	if h.gate.OKAt(10, 0) {
		t.Fatal("前置条件：连续两次失败后站应 unreachable")
	}
	exec := l2Execution(model.TriggerManual)
	exec.ID = "manual"
	if _, err := recorder.Record(context.Background(), &model.ProbeObservation{Execution: exec}); err != nil {
		t.Fatal(err)
	}
	if !h.gate.OKAt(10, 0) {
		t.Fatal("前置条件：手动测试拿到响应后站应离开 unreachable")
	}
	_, _, _, triggered, _ := h.track.snapshot()
	if len(triggered) != 1 || triggered[0] != 100 {
		t.Fatalf("手动测试让站离开 unreachable 应立即触发 dead Route 100 的 L2，得到 %v", triggered)
	}

	h.l1(t, 0)
	if _, _, _, triggered, _ := h.track.snapshot(); len(triggered) != 1 {
		t.Fatalf("恢复已触发过，随后的 L1 不得重复触发，得到 %v", triggered)
	}
}
