package probe

// ExecutionOnlyRecorder 是 P0-09 的落库 recorder：它只把一行 ProbeExecution
// 写进库，**不推进任何 Reachability/Capability 状态**。
//
// 为什么单独一个「只写 execution」的 recorder：P0-09 交付的是「恰好一次请求
// 的可观测执行单元」，而状态推进（reduce → commit）是 P0-10 的事
// （ResultRecorder + Registry）。这一版先把「发送主链 → 落 execution 行」跑通，
// 让 execution 表、成本事件与 daily rollup 在同一个事务里就位；P0-10 只换
// recorder 与 Registry 接线，不再重新迁一遍发送主链（§P0-09 末段）。
//
// 两个 disposition 一律 not_applicable：这一版不比较 expectation 与 DB-current
// 配置，所以它既没有「applied」也没有「config_stale」的依据。硬填一个别的值
// 会让 P0-10 的状态机读到一份它没算过的结论。

import (
	"context"

	"github.com/279814/relay-gate/internal/model"
)

// ExecutionStore 是 ExecutionOnlyRecorder 需要的唯一存储面。
//
// 定义成窄接口而不是直接收 *store.Store：Executor 不该看见 Store 的其余方法，
// 而测试用一个假实现（记录写入、可注入失败）比搭一个真库更直接。
// *store.Store 通过 InsertProbeExecution 满足它。
type ExecutionStore interface {
	InsertProbeExecution(ctx context.Context, execution *model.ProbeExecution) error
}

// ExecutionOnlyRecorder 把 ProbeObservation 里的 execution 落库，
// 两个 disposition 恒为 not_applicable。
type ExecutionOnlyRecorder struct {
	store ExecutionStore
}

// NewExecutionOnlyRecorder 构造一个只写 execution 行的 recorder。
func NewExecutionOnlyRecorder(store ExecutionStore) *ExecutionOnlyRecorder {
	return &ExecutionOnlyRecorder{store: store}
}

// Record 落一行 execution，并返回「未推进任何状态」的 apply 结果。
//
// 写库失败作为 Go error 返回（§P0-09 第 10 条）：那是持久化故障，不是站点
// 的失败，也不是站点的成功 —— 伪装成任何一种都会让健康视图撒谎。
func (recorder *ExecutionOnlyRecorder) Record(ctx context.Context,
	value *model.ProbeObservation) (model.ProbeApplyResult, error) {

	if recorder == nil || recorder.store == nil {
		return model.ProbeApplyResult{}, model.WrapValidation("execution recorder 未装配 store")
	}
	if value == nil {
		return model.ProbeApplyResult{}, model.WrapValidation("probe observation 不能为空")
	}

	// 落库前钉死两个 disposition：这一版不推进状态，所以只有 not_applicable
	// 是诚实的。InsertProbeExecution 内部会把空 disposition 也补成
	// not_applicable，这里显式写一遍是为了让「本 recorder 从不推进状态」
	// 这件事在读代码时就成立，而不是依赖下游的补默认行为。
	execution := value.Execution
	execution.ReachabilityDisposition = model.ApplyNotApplicable
	execution.CapabilityDisposition = model.ApplyNotApplicable

	if err := recorder.store.InsertProbeExecution(ctx, &execution); err != nil {
		return model.ProbeApplyResult{}, err
	}

	return model.ProbeApplyResult{
		ExecutionStored: true,
		Reachability:    model.ApplyNotApplicable,
		Capability:      model.ApplyNotApplicable,
	}, nil
}
