package probe

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/279814/relay-gate/internal/model"
)

// ErrSyntheticClosed 表示 admission 已关闭（paused / shutdown）。
//
// Executor 拿到此错误时零发送、不上抛为站点失败以外的路径：
// 调用方应视为 ignored / 不构造公网请求。
var ErrSyntheticClosed = errors.New("synthetic admission closed")

// SyntheticResumeTarget 是 Scheduler 的 resume 面。
//
// Coordinator 恰好一次绑定；PrepareResume/ResumeGradually 只委托给它。
type SyntheticResumeTarget interface {
	PrepareResume()
	ResumeGradually()
}

// SyntheticCoordinator 是进程级合成探活闸。
//
// scheduled / recovery / manual / calibration / synthetic count_tokens
// 共用一张 admission、同一组可取消 child context 与 drain waitgroup。
// TriggerRealTraffic 不占 lease（见 AcquireSynthetic）。
type SyntheticCoordinator struct {
	mu sync.Mutex

	open atomic.Bool // admission 是否放行新 lease

	// root 是所有合成 child 的父；CancelSynthetic 替换并 cancel 旧 root。
	root       context.Context
	rootCancel context.CancelFunc

	leases sync.WaitGroup // 在途 lease 数

	resume   SyntheticResumeTarget
	resumeOK bool

	closed atomic.Bool // Close 后永久拒绝
}

// NewSyntheticCoordinator 按持久运行态构造。paused → admission 关闭。
func NewSyntheticCoordinator(initial model.RunState) *SyntheticCoordinator {
	root, cancel := context.WithCancel(context.Background())
	c := &SyntheticCoordinator{
		root:       root,
		rootCancel: cancel,
	}
	c.open.Store(initial == model.RunStateRunning)
	return c
}

// BindResumeTarget 恰好一次绑定 Scheduler；nil/重复失败。
func (c *SyntheticCoordinator) BindResumeTarget(v SyntheticResumeTarget) error {
	if c == nil {
		return errors.New("SyntheticCoordinator 为空")
	}
	if v == nil {
		return errors.New("SyntheticResumeTarget 不能为空")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.resumeOK {
		return errors.New("SyntheticResumeTarget 已绑定")
	}
	c.resume = v
	c.resumeOK = true
	return nil
}

// AcquireSynthetic 实现 SyntheticAdmission。
//
// 先占名额再检查 open：与 Cancel 并发时只允许「取得 lease 后被 cancel」
// 或「admission 拒绝且零发送」，不能漏出第三种路径。
func (c *SyntheticCoordinator) AcquireSynthetic(ctx context.Context, trigger model.ProbeTrigger) (context.Context, func(), error) {
	if c == nil {
		return nil, nil, errors.New("SyntheticCoordinator 为空")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if !trigger.Valid() {
		return nil, nil, errors.New("synthetic admission trigger 无效")
	}
	if trigger == model.TriggerRealTraffic {
		return nil, nil, ErrRealTrafficNoLease
	}
	if c.closed.Load() || !c.open.Load() {
		return nil, nil, ErrSyntheticClosed
	}

	c.mu.Lock()
	if c.closed.Load() || !c.open.Load() {
		c.mu.Unlock()
		return nil, nil, ErrSyntheticClosed
	}
	parent := c.root
	c.leases.Add(1)
	c.mu.Unlock()

	child, childCancel := context.WithCancel(parent)
	// 与调用方 ctx 联动：调用方取消也结束这次 Attempt。
	stop := context.AfterFunc(ctx, childCancel)

	var once sync.Once
	release := func() {
		once.Do(func() {
			stop()
			childCancel()
			c.leases.Done()
		})
	}

	// 占位后再确认：Cancel 可能已先关 gate 并 cancel root。
	if !c.open.Load() || c.closed.Load() {
		release()
		return nil, nil, ErrSyntheticClosed
	}
	select {
	case <-child.Done():
		release()
		return nil, nil, ErrSyntheticClosed
	default:
	}
	return child, release, nil
}

// errCancelSyntheticPanic is fixed text only — never include the panic value
// (secrets / request fragments must not reach pause-drain API responses).
var errCancelSyntheticPanic = errors.New("CancelSynthetic panic")

// CancelSynthetic 先关闭 admission，再广播 cancel，最后等待 lease 释放。
//
// panic 隔离、可重复调用。ctx 超时返回错误，但 admission 保持关闭。
func (c *SyntheticCoordinator) CancelSynthetic(ctx context.Context, cause error) (err error) {
	if c == nil {
		return errors.New("SyntheticCoordinator 为空")
	}
	defer func() {
		if recover() != nil {
			err = errCancelSyntheticPanic
		}
	}()
	if ctx == nil {
		ctx = context.Background()
	}
	if cause == nil {
		cause = context.Canceled
	}

	c.open.Store(false)

	c.mu.Lock()
	oldCancel := c.rootCancel
	root, cancel := context.WithCancel(context.Background())
	c.root = root
	c.rootCancel = cancel
	c.mu.Unlock()

	if oldCancel != nil {
		oldCancel()
	}

	done := make(chan struct{})
	go func() {
		c.leases.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// PrepareResume 委托 Scheduler；admission 仍保持关闭直到 OpenAdmission。
func (c *SyntheticCoordinator) PrepareResume() {
	c.mu.Lock()
	target := c.resume
	c.mu.Unlock()
	if target != nil {
		target.PrepareResume()
	}
}

// ResumeGradually 先打开 admission，再委托渐进复核。
func (c *SyntheticCoordinator) ResumeGradually() {
	if c.closed.Load() {
		return
	}
	c.open.Store(true)
	c.mu.Lock()
	target := c.resume
	c.mu.Unlock()
	if target != nil {
		target.ResumeGradually()
	}
}

// OpenAdmission 仅测试/显式恢复路径；生产 resume 走 ResumeGradually。
func (c *SyntheticCoordinator) OpenAdmission() {
	if c == nil || c.closed.Load() {
		return
	}
	c.open.Store(true)
}

// CloseAdmission 仅关闭 gate，不 cancel 在途（测试用）。
func (c *SyntheticCoordinator) CloseAdmission() {
	if c != nil {
		c.open.Store(false)
	}
}

// InFlight 返回当前 lease 数（近似；WaitGroup 无计数器时用探测）。
//
// 生产诊断不依赖此值；测试用 Add/Done 外的旁路计数。
func (c *SyntheticCoordinator) AdmissionOpen() bool {
	return c != nil && c.open.Load() && !c.closed.Load()
}

// Close 永久关闭并取消全部合成 context。
func (c *SyntheticCoordinator) Close() {
	if c == nil {
		return
	}
	c.closed.Store(true)
	c.open.Store(false)
	c.mu.Lock()
	cancel := c.rootCancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	c.leases.Wait()
}

// 编译期断言：Coordinator 满足 admission 与 runstate.SyntheticController。
var (
	_ SyntheticAdmission = (*SyntheticCoordinator)(nil)
)
