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
func (s *Scheduler) ResumeGradually() {
	s.mu.Lock()
	s.lastRunning = store.StateRunning
	s.mu.Unlock()
	s.log.Info("ResumeGradually：已允许调度按并发闸渐进复核")
}

// Trigger 事件驱动调度；在途时只置 pending。
func (s *Scheduler) Trigger(key ScheduleKey, reason ScheduleReason) {
	_ = reason
	if key.UpstreamID < 1 {
		return
	}
	p := s.ensureP012()
	s.mu.Lock()
	inflightL1 := s.inflightL1[key.UpstreamID]
	inflightL2 := key.ScopeID > 0 && s.inflightL2[key.ScopeID]
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
	inflight := s.inflightL2[routeID]
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
