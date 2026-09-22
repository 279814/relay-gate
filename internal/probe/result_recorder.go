package probe

// ResultRecorder 是 P0-10 的生产 ExecutionRecorder（§4.7 / §5.5）。
//
// 它持有 Store、纯 StateReducer 与两个 Registry，调用 Store.CommitProbeObservation；
// 内存 Registry 只在事务返回对应 ApplyCurrent 后 CAS 更新。P0-09 的
// ExecutionOnlyRecorder 只写 execution 行；生产 main 在本任务后不得再注入它。

import (
	"context"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/observation"
)

// ObservationCommitter 是 ResultRecorder 需要的唯一存储面。
//
// *store.Store 通过 CommitProbeObservation 满足它。定义成窄接口避免 probe→store
// 为了几个方法而把整个 Store API 拉进热路径测试。
type ObservationCommitter interface {
	CommitProbeObservation(ctx context.Context, value *model.ProbeObservation, reducer observation.StateReducer) (model.ProbeApplyResult, error)
}

// ResultRecorder 把一次 ProbeObservation 原子提交，并刷新内存 Registry。
type ResultRecorder struct {
	store   ObservationCommitter
	reducer observation.StateReducer
	reach   *health.ReachabilityTracker
	caps    *CapabilityRegistry
}

// NewResultRecorder 装配生产 recorder。reach/caps 可为 nil（只落库不刷内存）。
func NewResultRecorder(store ObservationCommitter, reducer observation.StateReducer,
	reach *health.ReachabilityTracker, caps *CapabilityRegistry) *ResultRecorder {

	return &ResultRecorder{store: store, reducer: reducer, reach: reach, caps: caps}
}

// Record 调用 CommitProbeObservation，并仅在 ApplyCurrent 时更新 Registry。
func (recorder *ResultRecorder) Record(ctx context.Context,
	value *model.ProbeObservation) (model.ProbeApplyResult, error) {

	if recorder == nil || recorder.store == nil || recorder.reducer == nil {
		return model.ProbeApplyResult{}, model.WrapValidation("result recorder 未装配 store/reducer")
	}
	if value == nil {
		return model.ProbeApplyResult{}, model.WrapValidation("probe observation 不能为空")
	}

	result, err := recorder.store.CommitProbeObservation(ctx, value, recorder.reducer)
	if err != nil {
		return model.ProbeApplyResult{}, err
	}

	if result.Reachability == model.ApplyCurrent && result.CommittedReachability != nil && recorder.reach != nil {
		recorder.reach.ApplyCommitted(result.CommittedReachability)
	}
	if result.Capability == model.ApplyCurrent && result.CommittedCapability != nil && recorder.caps != nil {
		recorder.caps.ApplyCommitted(result.CommittedCapability)
	}
	return result, nil
}

// 编译期断言：两种 adapter 都满足 Executor 的 ExecutionRecorder。
var (
	_ ExecutionRecorder = (*ResultRecorder)(nil)
	_ ExecutionRecorder = (*ExecutionOnlyRecorder)(nil)
)
