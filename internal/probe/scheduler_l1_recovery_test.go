package probe

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

// reachReducingRecorder 模拟生产 ResultRecorder 的 Reachability 半边：
// 用真 ObservationReducer（含 fail/ok 阈值）推进站级行，再 ApplyCommitted
// 到 ReachabilityTracker，并按 ApplyCurrent 回报。
type reachReducingRecorder struct {
	t        *testing.T
	reach    *health.ReachabilityTracker
	reducer  *health.ObservationReducer
	settings model.Settings

	mu    sync.Mutex
	order int64
	row   *model.UpstreamReachability
}

func (r *reachReducingRecorder) stamp(row *model.UpstreamReachability, upstreamID int64) {
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	policy, err := revisioncodec.BuildReachabilityEvidencePolicy(r.settings, selector)
	if err != nil {
		r.t.Fatal(err)
	}
	fp := revisioncodec.ReachabilitySettingsFingerprint(policy)
	row.UpstreamID = upstreamID
	row.PolicySelector = selector
	row.ObservedNetworkRevision = 0
	row.SettingsFingerprint = fp
	row.ObservationToken = revisioncodec.NewReachabilityToken(model.ReachabilityRevision{
		NetworkRevision: 0, SettingsFingerprint: fp,
	})
	r.order++
	row.LastObservationOrder = r.order
}

// seed 直接提交一行站级结论，模拟非 L1 来源（例如 L2 传输失败）写入的状态。
func (r *reachReducingRecorder) seed(upstreamID int64, state model.ReachabilityState, fails int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row := &model.UpstreamReachability{State: state, ConsecutiveFail: fails}
	r.stamp(row, upstreamID)
	r.row = row
	r.reach.ApplyCommitted(row)
}

func (r *reachReducingRecorder) Record(_ context.Context, v *model.ProbeObservation) (model.ProbeApplyResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v.Execution.ErrorClass == model.ErrorIgnored {
		return model.ProbeApplyResult{ExecutionStored: true,
			Reachability: model.ApplyNotApplicable, Capability: model.ApplyNotApplicable}, nil
	}
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	policy, err := revisioncodec.BuildReachabilityEvidencePolicy(r.settings, selector)
	if err != nil {
		r.t.Fatal(err)
	}
	next, err := r.reducer.ReduceReachability(r.row, v.Execution, policy.State)
	if err != nil {
		r.t.Fatal(err)
	}
	r.stamp(next, v.Execution.UpstreamID)
	r.row = next
	r.reach.ApplyCommitted(next)
	committed := *next
	return model.ProbeApplyResult{
		ExecutionStored:       true,
		Reachability:          model.ApplyCurrent,
		Capability:            model.ApplyNotApplicable,
		CommittedReachability: &committed,
	}, nil
}

type l1RecoveryHarness struct {
	*schedHarness
	reach    *health.ReachabilityTracker
	recorder *reachReducingRecorder
	mode     atomic.Int32 // 0 = 200, 1 = 断连（拿不到响应头）, 2 = 404
}

func newL1RecoveryHarness(t *testing.T) *l1RecoveryHarness {
	t.Helper()
	h := &l1RecoveryHarness{}
	h.schedHarness = newSchedHarness(t, 1, func(w http.ResponseWriter, r *http.Request) {
		switch h.mode.Load() {
		case 1:
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("server does not support hijack")
				return
			}
			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.Close()
			}
		case 2:
			w.WriteHeader(http.StatusNotFound)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":[]}`))
		}
	})
	settings := model.DefaultSettings()
	h.reach = health.NewReachabilityTracker(nil)
	h.gate = health.NewUpstreamGate().WithTracker(h.reach)
	h.sched.gate = h.gate
	h.recorder = &reachReducingRecorder{t: t, reach: h.reach,
		reducer: health.NewObservationReducer(nil), settings: settings}
	executor := NewExecutor(testTargets(), nil, nil,
		ManagerTransports{Manager: outbound.NewManager()},
		h.recorder, AlwaysOpenAdmission(), WallClock(), discardLogger())
	h.sched.WithExecutor(executor)
	h.track.states[100] = model.StateDead
	return h
}

func (h *l1RecoveryHarness) l1(t *testing.T, mode int32) {
	t.Helper()
	h.mode.Store(mode)
	snap, _ := h.cfg.Snapshot()
	h.sched.runL1(context.Background(), snap.Upstreams[10], h.cfg.settings)
}

func (h *l1RecoveryHarness) triggeredCount() int {
	_, _, _, triggered, _ := h.track.snapshot()
	return len(triggered)
}

// §8.10：只有 Reachability 从 unreachable 恢复才触发即时调度。
// 站级阈值（fail_threshold=2）之下的一次传输失败不让站进入 unreachable，
// 之后的成功 L1 不是「恢复」，不得触发 dead Route 的 L2。
func TestScheduler_L1BlipBelowThresholdDoesNotTriggerRecovery(t *testing.T) {
	h := newL1RecoveryHarness(t)

	h.l1(t, 0)
	h.l1(t, 1)
	if got := h.reach.Effective(10, 0); got == model.ReachabilityUnreachable {
		t.Fatalf("前置条件：一次失败低于阈值，站不应 unreachable，得到 %s", got)
	}
	if !h.gate.OKAt(10, 0) {
		t.Fatal("前置条件：低于阈值时模型探测不应被短路")
	}
	h.l1(t, 0)
	if n := h.triggeredCount(); n != 0 {
		t.Fatalf("站从未 unreachable，成功 L1 不得走恢复路径，TriggerL2=%d", n)
	}
}

// 404 是 reachable（§8.9）：既不短路模型探测，也不构成随后的「恢复」。
func TestScheduler_L1NotFoundIsNotRecovery(t *testing.T) {
	h := newL1RecoveryHarness(t)

	h.l1(t, 0)
	h.l1(t, 2)
	if !h.gate.OKAt(10, 0) {
		t.Fatal("/models 404 不得短路模型探测")
	}
	h.l1(t, 0)
	if n := h.triggeredCount(); n != 0 {
		t.Fatalf("404 后的成功 L1 不是恢复，TriggerL2=%d", n)
	}
}

// 真正达到阈值进入 unreachable 后，成功 L1 必须触发 dead Route 的 L2。
func TestScheduler_L1ReturnFromUnreachableTriggersDeadRoutes(t *testing.T) {
	h := newL1RecoveryHarness(t)

	h.l1(t, 0)
	h.l1(t, 1)
	h.l1(t, 1)
	if h.gate.OKAt(10, 0) {
		t.Fatal("前置条件：连续两次失败后站应 unreachable 并短路模型探测")
	}
	h.l1(t, 0)
	_, _, _, triggered, _ := h.track.snapshot()
	if len(triggered) != 1 || triggered[0] != 100 {
		t.Fatalf("从 unreachable 恢复应触发 dead Route 100 的 L2，得到 %v", triggered)
	}
}

// 站级 unreachable 也可能由非 L1 观察（例如 L2 传输失败）提交；
// 之后第一次成功 L1 同样是「从 unreachable 恢复」。
func TestScheduler_L1RecoveryFollowsCommittedReachability(t *testing.T) {
	h := newL1RecoveryHarness(t)

	h.l1(t, 0)
	h.recorder.seed(10, model.ReachabilityUnreachable, 2)
	if h.gate.OKAt(10, 0) {
		t.Fatal("前置条件：站应 unreachable")
	}
	h.l1(t, 0)
	_, _, _, triggered, _ := h.track.snapshot()
	if len(triggered) != 1 || triggered[0] != 100 {
		t.Fatalf("从 unreachable 恢复应触发 dead Route 100 的 L2，得到 %v", triggered)
	}
}
