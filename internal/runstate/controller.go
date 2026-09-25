// Package runstate 是服务总闸（running/paused）的唯一写入口与热路径读面。
//
// P0-12：proxy / count_tokens / Scheduler / 管理 API 都只读 Current()，
// 不再依赖 livecfg 的 2 秒 TTL。pause 后由绑定的 SyntheticController
// 关闭 admission 并 drain 全部合成 context；resume 在 Current 仍为 paused
// 时先 PrepareResume，再发布 running，避免旧正结论被并发消费。
//
// P2 Runtime Controller 扩展（§4.4 / §12.7 / §13.5）：maintenance 是内存
// 叠加态，不覆盖持久化 paused；暖机进度在 resume 后供 UI 展示，不暗示
// 全部 Route 已立即验证。
package runstate

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

const (
	// PauseDrainPendingCode 是 DB 已提交 paused、但 drain 尚未完成时的诊断码。
	PauseDrainPendingCode = "pause_drain_pending"

	// MaintenanceActiveCode 表示已在 maintenance，拒绝重复进入凭据轮换。
	MaintenanceActiveCode = "maintenance_active"

	// defaultDrainRetry 是后台幂等 drain 的重试间隔上界。
	defaultDrainRetry = 2 * time.Second

	// defaultWarmupMax 是 resume 后暖机展示的最长窗口（超时后 UI 不再标 active）。
	defaultWarmupMax = 30 * time.Minute
)

// Snapshot 是运行态与独立 revision 的对外视图。
//
// State/Revision 是持久化用户意图（仅 running|paused）。Maintenance 是内部
// 叠加态（§4.4），不写库、不覆盖 paused。
type Snapshot struct {
	State             model.RunState  `json:"state"`
	Revision          int64           `json:"revision"`
	Maintenance       bool            `json:"maintenance"`
	MaintenanceReason string          `json:"maintenance_reason,omitempty"`
	Warmup            *WarmupProgress `json:"warmup,omitempty"`
}

// WarmupProgress 是 resume 后的暖机视图（§13.5）。
type WarmupProgress struct {
	Active   bool `json:"active"`
	Pending  int  `json:"pending"` // 仍为 unknown、待复核
	Alive    int  `json:"alive"`
	Negative int  `json:"negative"` // dead/recovering/cooldown 等负状态
	Total    int  `json:"total"`
}

// Effective 返回 UI/代理可见态：maintenance 优先于持久化 state。
func (s Snapshot) Effective() string {
	if s.Maintenance {
		return "maintenance"
	}
	return string(s.State)
}

// Admitting 为 true 时才接受新模型流量 / count_tokens。
func (s Snapshot) Admitting() bool {
	return !s.Maintenance && s.State == model.RunStateRunning
}

// Reader 是热路径只读面（proxy / Scheduler / count_tokens）。
type Reader interface {
	Current() Snapshot
}

// WarmupSource 提供 Route 健康计数；由 health.Tracker 实现。
type WarmupSource interface {
	RouteHealthCounts() (unknown, alive, negative, total int)
}

// StateStore 持久化运行态（乐观并发）。由 store.Store 实现。
type StateStore interface {
	GetRunStateWithRevision() (model.RunState, int64, error)
	SetRunStateWithRevision(v model.RunState, expectedRevision int64) (int64, error)
}

// SyntheticController 由 probe.SyntheticCoordinator 实现。
//
// Controller 不直接依赖 Scheduler：pause 取消与 resume 准备都经 Coordinator，
// 以消除 Controller↔Scheduler/Executor 的构造环。
type SyntheticController interface {
	CancelSynthetic(ctx context.Context, cause error) error
	PrepareResume()
	ResumeGradually()
}

// TransitionPendingError 表示 DB 已提交、副作用（drain）仍在进行。
//
// 绝不回滚 paused；API 映射 503 + persisted=true。
type TransitionPendingError struct {
	Code      string
	Persisted Snapshot
	Cause     error
}

func (e *TransitionPendingError) Error() string {
	if e == nil {
		return "transition pending"
	}
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Code, e.Cause)
	}
	return e.Code
}

func (e *TransitionPendingError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// ErrNotBound 表示尚未 BindSyntheticController。
var ErrNotBound = errors.New("runstate: SyntheticController 未绑定")

// ErrAlreadyBound 表示重复绑定。
var ErrAlreadyBound = errors.New("runstate: SyntheticController 已绑定")

// ErrMaintenanceActive 表示已在 maintenance（拒绝重复进入轮换）。
var ErrMaintenanceActive = errors.New("runstate: maintenance already active")

// Controller 持有原子快照，并协调 pause/resume 副作用。
type Controller struct {
	store StateStore

	mu    sync.Mutex
	synth SyntheticController
	bound bool

	// snap 是热路径真相；DB commit 后立即更新（resume 除外，见 Set）。
	snap atomic.Value // Snapshot

	// drainPending 在 pause drain 失败后置位；后台清掉，不加 revision。
	drainPending atomic.Bool
	drainOnce    sync.Once
	drainStop    chan struct{}

	// maintenance 叠加态（§4.4）：不写库，不覆盖 persisted paused。
	maintenance       atomic.Bool
	maintenanceReason atomic.Value // string

	// warmup：resume 后展示进度；不暗示全部 Route 已验证。
	warmupMu      sync.Mutex
	warmupActive  bool
	warmupStarted time.Time
	warmupSource  WarmupSource
	warmupMax     time.Duration

	// 测试可注入。
	drainRetry time.Duration
	now        func() time.Time
}

// NewController 从持久化状态构造。listener/worker 启动前必须先 New+Bind。
func NewController(st StateStore) (*Controller, error) {
	if st == nil {
		return nil, errors.New("runstate: StateStore 不能为空")
	}
	state, rev, err := st.GetRunStateWithRevision()
	if err != nil {
		return nil, err
	}
	if !state.Valid() {
		state = model.RunStateRunning
	}
	c := &Controller{
		store:      st,
		drainStop:  make(chan struct{}),
		drainRetry: defaultDrainRetry,
		warmupMax:  defaultWarmupMax,
		now:        time.Now,
	}
	c.maintenanceReason.Store("")
	c.snap.Store(Snapshot{State: state, Revision: rev})
	return c, nil
}

// BindWarmupSource 可选绑定暖机计数源（通常为 health.Tracker）。
func (c *Controller) BindWarmupSource(src WarmupSource) {
	if c == nil {
		return
	}
	c.warmupMu.Lock()
	c.warmupSource = src
	c.warmupMu.Unlock()
}

// BindSyntheticController 恰好绑定一次；nil 或重复失败。
func (c *Controller) BindSyntheticController(v SyntheticController) error {
	if c == nil {
		return errors.New("runstate: Controller 为空")
	}
	if v == nil {
		return errors.New("runstate: SyntheticController 不能为空")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.bound {
		return ErrAlreadyBound
	}
	c.synth = v
	c.bound = true
	return nil
}

// Current 返回热路径快照，不读库、不经 livecfg TTL。
func (c *Controller) Current() Snapshot {
	if c == nil {
		return Snapshot{State: model.RunStatePaused, Revision: 0}
	}
	v, _ := c.snap.Load().(Snapshot)
	v.Maintenance = c.maintenance.Load()
	if v.Maintenance {
		if reason, _ := c.maintenanceReason.Load().(string); reason != "" {
			v.MaintenanceReason = reason
		}
	}
	v.Warmup = c.warmupProgressLocked(v)
	return v
}

// Get 与 Current 相同；保留 ctx 以匹配管理 API 契约。
func (c *Controller) Get(ctx context.Context) (Snapshot, error) {
	_ = ctx
	if c == nil {
		return Snapshot{}, errors.New("runstate: Controller 为空")
	}
	return c.Current(), nil
}

// InMaintenance 报告叠加态。
func (c *Controller) InMaintenance() bool {
	return c != nil && c.maintenance.Load()
}

// EnterMaintenance 进入内部维护叠加态（§4.4 / §12.7）。
//
// 不修改持久化 running/paused；拒绝新模型流量；取消合成作业。
// 已在 maintenance 时返回 ErrMaintenanceActive（禁止重复触发凭据轮换）。
func (c *Controller) EnterMaintenance(reason string) error {
	if c == nil {
		return errors.New("runstate: Controller 为空")
	}
	if reason == "" {
		reason = "maintenance"
	}
	if !c.maintenance.CompareAndSwap(false, true) {
		return ErrMaintenanceActive
	}
	c.maintenanceReason.Store(reason)

	c.mu.Lock()
	synth := c.synth
	bound := c.bound
	c.mu.Unlock()
	if bound && synth != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_ = safeCancel(synth, ctx)
		cancel()
	}
	return nil
}

// ExitMaintenance 退出维护叠加态。若持久化为 running，须在仍 maintenance
// （Admitting=false）时先同步 PrepareResume，清掉旧正结论，再放下叠加态并
// ResumeGradually——与 Set(running) 同序，避免「已可准入却仍消费 stale alive」。
func (c *Controller) ExitMaintenance() error {
	if c == nil {
		return errors.New("runstate: Controller 为空")
	}
	if !c.maintenance.Load() {
		return nil // 幂等
	}

	c.mu.Lock()
	synth := c.synth
	bound := c.bound
	c.mu.Unlock()
	base, _ := c.snap.Load().(Snapshot)

	// 仍在 maintenance：Current().Admitting()==false。先 DemotePositive。
	if bound && synth != nil && base.State == model.RunStateRunning {
		safePrepareResume(synth)
	}

	if !c.maintenance.CompareAndSwap(true, false) {
		return nil // 并发 ExitMaintenance 已清除
	}
	c.maintenanceReason.Store("")

	if bound && synth != nil && base.State == model.RunStateRunning {
		safeResumeGradually(synth)
		c.markWarmup()
	}
	return nil
}

// PauseDrainPending 报告是否仍有后台 drain。
func (c *Controller) PauseDrainPending() bool {
	return c != nil && c.drainPending.Load()
}

// Close 停止后台 drain（进程退出时调用）。
func (c *Controller) Close() {
	if c == nil {
		return
	}
	c.drainOnce.Do(func() { close(c.drainStop) })
}

// Set 乐观并发切换运行态。
//
// paused：DB commit → 立即发布 paused → CancelSynthetic（先关 admission 再 drain）。
// drain 失败不回滚，返回 TransitionPendingError 并启动后台幂等 drain。
//
// running：DB commit 后 Current 仍保持 paused，同步 PrepareResume，再发布 running，
// 最后 ResumeGradually。消除「running 已可见却仍消费旧正结论」的窗口。
//
// 相同状态：空更新，不增 revision、不重复取消/调度（Store CAS 已保证）。
func (c *Controller) Set(ctx context.Context, state model.RunState, expectedRevision int64) (Snapshot, error) {
	if c == nil {
		return Snapshot{}, errors.New("runstate: Controller 为空")
	}
	if !state.Valid() {
		return Snapshot{}, model.WrapValidation("state 必须是 running 或 paused，收到 %q", state)
	}
	c.mu.Lock()
	synth := c.synth
	bound := c.bound
	c.mu.Unlock()
	if !bound || synth == nil {
		return Snapshot{}, ErrNotBound
	}

	cur := c.Current()
	if cur.Revision != expectedRevision {
		// 与 Store 一致：旧 revision → 冲突（API 409）。
		return cur, errRevisionConflict
	}
	if cur.State == state {
		// 空更新：不增 revision。drain 仍挂起时可重建 pause_drain_pending。
		if state == model.RunStatePaused && c.drainPending.Load() {
			return cur, &TransitionPendingError{
				Code:      PauseDrainPendingCode,
				Persisted: cur,
				Cause:     errors.New("pause drain still pending"),
			}
		}
		return cur, nil
	}

	newRev, err := c.store.SetRunStateWithRevision(state, expectedRevision)
	if err != nil {
		return c.Current(), err
	}
	persisted := Snapshot{State: state, Revision: newRev}

	switch state {
	case model.RunStatePaused:
		c.snap.Store(persisted)
		drainErr := safeCancel(synth, ctx)
		out := c.enrich(persisted)
		if drainErr != nil {
			c.drainPending.Store(true)
			c.startBackgroundDrain(synth)
			return out, &TransitionPendingError{
				Code:      PauseDrainPendingCode,
				Persisted: out,
				Cause:     drainErr,
			}
		}
		c.drainPending.Store(false)
		return out, nil

	case model.RunStateRunning:
		// 关键：Current 仍为 paused，先 PrepareResume。
		safePrepareResume(synth)
		c.snap.Store(persisted)
		safeResumeGradually(synth)
		c.drainPending.Store(false)
		c.markWarmup()
		return c.Current(), nil
	}
	return c.enrich(persisted), nil
}

func (c *Controller) enrich(base Snapshot) Snapshot {
	base.Maintenance = c.maintenance.Load()
	if base.Maintenance {
		if reason, _ := c.maintenanceReason.Load().(string); reason != "" {
			base.MaintenanceReason = reason
		}
	}
	base.Warmup = c.warmupProgressLocked(base)
	return base
}

func (c *Controller) markWarmup() {
	c.warmupMu.Lock()
	c.warmupActive = true
	c.warmupStarted = c.now()
	c.warmupMu.Unlock()
}

func (c *Controller) warmupProgressLocked(base Snapshot) *WarmupProgress {
	c.warmupMu.Lock()
	active := c.warmupActive
	started := c.warmupStarted
	src := c.warmupSource
	max := c.warmupMax
	c.warmupMu.Unlock()

	if !active || base.State != model.RunStateRunning || base.Maintenance {
		return nil
	}
	if max <= 0 {
		max = defaultWarmupMax
	}
	now := c.now()
	if !started.IsZero() && now.Sub(started) > max {
		c.warmupMu.Lock()
		c.warmupActive = false
		c.warmupMu.Unlock()
		return nil
	}
	out := &WarmupProgress{Active: true}
	if src != nil {
		u, a, n, total := src.RouteHealthCounts()
		out.Pending, out.Alive, out.Negative, out.Total = u, a, n, total
		if total > 0 && u == 0 {
			c.warmupMu.Lock()
			c.warmupActive = false
			c.warmupMu.Unlock()
			return nil
		}
	}
	return out
}

// errRevisionConflict 与 store.ErrRevisionConflict 同语义；api 层用 errors.Is 映射 409。
//
// 不直接 import store，避免 runstate → store → … 额外耦合；api 用 errors.As /
// 字符串或把 store 错误原样上抛。Controller 在 revision 预检失败时返回本哨兵，
// SetRunStateWithRevision 冲突时原样返回 store 错误。
var errRevisionConflict = errors.New("runstate: revision conflict")

// RevisionConflict 供 api 判断 409（预检路径）。
func RevisionConflict(err error) bool {
	return errors.Is(err, errRevisionConflict)
}

// errCancelSyntheticPanic is the fixed client/log-safe stand-in when
// CancelSynthetic panics. The panic value must never be formatted into an
// error that reaches HTTP responses (it may hold secrets or request data).
var errCancelSyntheticPanic = errors.New("CancelSynthetic panic")

func safeCancel(synth SyntheticController, ctx context.Context) (err error) {
	defer func() {
		if recover() != nil {
			err = errCancelSyntheticPanic
		}
	}()
	if ctx == nil {
		ctx = context.Background()
	}
	return synth.CancelSynthetic(ctx, context.Canceled)
}

func safePrepareResume(synth SyntheticController) {
	defer func() { _ = recover() }()
	synth.PrepareResume()
}

func safeResumeGradually(synth SyntheticController) {
	defer func() { _ = recover() }()
	synth.ResumeGradually()
}

func (c *Controller) startBackgroundDrain(synth SyntheticController) {
	go func() {
		retry := c.drainRetry
		if retry <= 0 {
			retry = defaultDrainRetry
		}
		for {
			select {
			case <-c.drainStop:
				return
			default:
			}
			if !c.drainPending.Load() {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := safeCancel(synth, ctx)
			cancel()
			if err == nil {
				c.drainPending.Store(false)
				return
			}
			select {
			case <-c.drainStop:
				return
			case <-time.After(retry):
			}
		}
	}()
}

// Ensure paused 启动态时 Current 可读；running 启动态须在 Bind 后由 main
// 显式 PrepareResume 再对外服务——见 EnsureStartupPrepare。
func (c *Controller) EnsureStartupPrepare() error {
	c.mu.Lock()
	synth := c.synth
	bound := c.bound
	c.mu.Unlock()
	if !bound || synth == nil {
		return ErrNotBound
	}
	if c.Current().State == model.RunStateRunning {
		safePrepareResume(synth)
	}
	return nil
}
