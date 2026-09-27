package probe

// P0-12 调度控制面：ScheduleKey、PrepareResume、Lazy 感知的辅助方法。
// 与 scheduler.go 同包，避免把整文件一次性重写弄坏。

import (
	"math/rand"
	"sync"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/runstate"
	"github.com/279814/relay-gate/internal/store"
)

// ScheduleKey 标识一次可调度的合成探活目标（§4.11）。
type ScheduleKey struct {
	UpstreamID int64
	ScopeType  model.RecipeScope
	ScopeID    int64
	Endpoint   model.EndpointKind
}

// ScheduleReason 解释为何触发。
type ScheduleReason string

const (
	SchedulePeriodic ScheduleReason = "periodic"
	ScheduleConfig   ScheduleReason = "config_changed"
	ScheduleManual   ScheduleReason = "manual"
	ScheduleRecovery ScheduleReason = "reachability_recovered"
)

// schedulerP012 是挂在 Scheduler 上的 P0-12 扩展状态（避免改造函数签名爆炸）。
type schedulerP012 struct {
	runState  runstate.Reader
	capReg    *CapabilityRegistry
	rng       *rand.Rand
	pendingL1 map[int64]bool
	pendingL2 map[int64]bool
	mu        sync.Mutex

	// 恢复复核波（§4.4「按全局限流和抖动逐步复核，不得瞬时齐发」）：
	// resumeDone 记本轮恢复已发出复核 L1 的站，resumeInflight 记其中仍在途的
	// hold；在途数受全局并发上限约束，全部站复核发出后 resumeRamp 结束。
	resumeRamp     bool
	resumeDone     map[int64]bool
	resumeInflight map[int64]uint64
}

func (s *Scheduler) ensureP012() *schedulerP012 {
	if s.p012 != nil {
		return s.p012
	}
	s.p012 = &schedulerP012{
		pendingL1: map[int64]bool{},
		pendingL2: map[int64]bool{},
		rng:       rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	return s.p012
}

// WithRunState 注入热路径总闸（优先于 livecfg TTL）。
func (s *Scheduler) WithRunState(r runstate.Reader) *Scheduler {
	s.ensureP012().runState = r
	return s
}

// WithCapabilityRegistry 注入 Capability 正结论降级面。
func (s *Scheduler) WithCapabilityRegistry(reg *CapabilityRegistry) *Scheduler {
	s.ensureP012().capReg = reg
	return s
}

// WithRNG 注入可复现 jitter 源。
func (s *Scheduler) WithRNG(r *rand.Rand) *Scheduler {
	if r != nil {
		s.ensureP012().rng = r
	}
	return s
}

func (s *Scheduler) currentRunState() store.RunState {
	p := s.ensureP012()
	if p.runState != nil {
		return store.RunState(p.runState.Current().State)
	}
	state, err := s.cfg.RunState()
	if err != nil {
		return store.StateRunning
	}
	return state
}

func (s *Scheduler) jitterFactor() float64 {
	p := s.ensureP012()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.rng == nil {
		return 1.0
	}
	return 0.9 + p.rng.Float64()*0.2
}

// PrepareResume 把正结论降为 effective unknown，保留负状态（§P0-12）。
func (s *Scheduler) PrepareResume() {
	if demoter, ok := s.track.(interface{ DemotePositiveConclusions() }); ok {
		demoter.DemotePositiveConclusions()
	} else {
		s.track.ResetAll()
	}
	if s.gate != nil && s.gate.Tracker() != nil {
		s.gate.Tracker().DemotePositive()
	} else if s.gate != nil {
		s.gate.Reset()
	}
	if s.ensureP012().capReg != nil {
		s.ensureP012().capReg.DemotePositive()
	}
	s.log.Info("PrepareResume：正结论已降为 unknown，负状态保留")
}

// ResumeGradually 允许后续 tick 按并发闸渐进复核。
//
// L2 本来就受全局并发闸约束；L1 平时不设全局上限，但 PrepareResume 清空了
// 全部到期时间，不加约束的话下一个 tick 会对所有站同时发 /models。
// 因此开启一轮恢复复核波，让每站的首个复核 L1 也受同一个全局上限。
func (s *Scheduler) ResumeGradually() {
	s.mu.Lock()
	s.lastRunning = store.StateRunning
	s.mu.Unlock()
	p := s.ensureP012()
	p.mu.Lock()
	p.resumeRamp = true
	p.resumeDone = map[int64]bool{}
	p.resumeInflight = map[int64]uint64{}
	p.mu.Unlock()
	s.log.Info("ResumeGradually：已允许调度按并发闸渐进复核")
}

// admitResumeL1 判断该站的 L1 能否在恢复复核波中发出。
// ramp 为 true 表示这次 L1 属于复核波，发出后须 noteResumeL1Started。
func (s *Scheduler) admitResumeL1(upstreamID int64) (ramp, ok bool) {
	limit := s.l2Limit()
	p := s.ensureP012()
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.resumeRamp || p.resumeDone[upstreamID] {
		return false, true
	}
	return true, len(p.resumeInflight) < limit
}

func (s *Scheduler) noteResumeL1Started(upstreamID int64, hold uint64) {
	p := s.ensureP012()
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.resumeRamp {
		return
	}
	p.resumeDone[upstreamID] = true
	p.resumeInflight[upstreamID] = hold
}

func (s *Scheduler) noteResumeL1Ended(upstreamID int64, hold uint64) {
	p := s.ensureP012()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.resumeInflight[upstreamID] == hold {
		delete(p.resumeInflight, upstreamID)
	}
}

// finishResumeRamp 在本轮参与调度的站都已发出复核 L1 后结束复核波。
func (s *Scheduler) finishResumeRamp(eligible map[int64]bool) {
	p := s.ensureP012()
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.resumeRamp {
		return
	}
	for id := range eligible {
		if !p.resumeDone[id] {
			return
		}
	}
	p.resumeRamp = false
	p.resumeDone = nil
}

// Trigger 事件驱动调度；在途时只置 pending。
func (s *Scheduler) Trigger(key ScheduleKey, reason ScheduleReason) {
	_ = reason
	if key.UpstreamID < 1 {
		return
	}
	p := s.ensureP012()
	s.mu.Lock()
	inflightL1 := s.inflightL1[key.UpstreamID] != 0
	inflightL2 := key.ScopeID > 0 && s.inflightL2[key.ScopeID] != 0
	s.mu.Unlock()

	p.mu.Lock()
	defer p.mu.Unlock()
	if key.Endpoint == model.EndpointModels || key.ScopeType == model.RecipeScopeUpstream {
		if inflightL1 {
			p.pendingL1[key.UpstreamID] = true
			return
		}
	} else if inflightL2 {
		p.pendingL2[key.ScopeID] = true
		return
	}
	if key.ScopeID > 0 {
		s.track.TriggerL2(key.ScopeID)
		if key.Endpoint == model.EndpointModels || key.ScopeType == model.RecipeScopeUpstream {
			s.track.TriggerL1(key.ScopeID)
		}
	}
}

// InvalidateUpstream 使该站尽快被调度。
func (s *Scheduler) InvalidateUpstream(upstreamID int64) {
	if s.gate != nil {
		s.gate.Forget(upstreamID)
	}
	s.Trigger(ScheduleKey{
		UpstreamID: upstreamID, ScopeType: model.RecipeScopeUpstream, Endpoint: model.EndpointModels,
	}, ScheduleConfig)
	snap, err := s.cfg.Snapshot()
	if err != nil {
		return
	}
	for _, rts := range snap.RoutesByModelName {
		for _, rt := range rts {
			if rt.UpstreamID == upstreamID {
				s.InvalidateRoute(rt.ID)
			}
		}
	}
}

// InvalidateRoute 使该 Route 的 L2 尽快发生（single-flight pending）。
func (s *Scheduler) InvalidateRoute(routeID int64) {
	p := s.ensureP012()
	s.mu.Lock()
	inflight := s.inflightL2[routeID] != 0
	s.mu.Unlock()
	if inflight {
		p.mu.Lock()
		p.pendingL2[routeID] = true
		p.mu.Unlock()
		return
	}
	s.track.TriggerL2(routeID)
	s.track.TriggerL1(routeID)
}

func (s *Scheduler) noteL1Finished(upstreamID int64) {
	p := s.ensureP012()
	p.mu.Lock()
	pending := p.pendingL1[upstreamID]
	delete(p.pendingL1, upstreamID)
	p.mu.Unlock()
	if pending {
		s.InvalidateUpstream(upstreamID)
	}
}

func (s *Scheduler) noteL2Finished(routeID int64) {
	p := s.ensureP012()
	p.mu.Lock()
	pending := p.pendingL2[routeID]
	delete(p.pendingL2, routeID)
	p.mu.Unlock()
	if !pending {
		return
	}
	// 完成瞬间 inflight 已清除；直接补一次，避免 InvalidateRoute 再看到
	// 陈旧 inflight 又把 pending 置回。
	s.track.TriggerL2(routeID)
}

// ObserveRealSuccess 用真实成功推迟 Active Route 的下次 L2（piggyback）。
func (s *Scheduler) ObserveRealSuccess(key ScheduleKey, observedAt time.Time) {
	if key.ScopeID < 1 {
		return
	}
	if observedAt.IsZero() {
		observedAt = time.Now()
	}
	generation := ensureRouteGeneration(s.track, key.ScopeID)
	s.track.Report(health.Report{
		RouteID: key.ScopeID, Generation: generation,
		Verdict: health.VerdictOK, Source: health.SourceReal,
	})
	if completer, ok := s.track.(interface {
		CompleteL2(routeID int64, completedAt time.Time, jitter float64)
	}); ok {
		completer.CompleteL2(key.ScopeID, observedAt, s.jitterFactor())
	}
}

var _ SyntheticResumeTarget = (*Scheduler)(nil)
