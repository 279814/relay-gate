package probe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/observationseq"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/sample"
	"github.com/279814/relay-gate/internal/store"
)

// tickInterval 是调度轮询周期。
//
// 1 秒是「够快」与「够省」的折中：最短的探活间隔是 20 秒（dead 状态的 L1），
// 1 秒的调度粒度对它只有 5% 的误差；而事件驱动的即时探活（§4.5）走
// TriggerL1/L2 清预占，最多也就等一个 tick。
//
// 不用「为每个 Route 起一个 timer」：Route 会随配置增删，那种做法要维护
// timer 的生命周期，而漏 Stop 一个就是一个永久泄漏的 goroutine。
const tickInterval = time.Second

// 手动探活的配置错误。返回 error 而不是静默跳过：用户点了「测试」
// 就该看到结果，无声无息什么都不发生比报错更难排查。
var (
	errNoUpstream  = errors.New("该 Route 指向的 Upstream 不存在")
	errNoModelName = errors.New("该 Route 指向的 ModelName 不存在")
)

// ConfigSource 提供调度需要的配置。与 proxy.ConfigSource 同源（livecfg）。
type ConfigSource interface {
	Snapshot() (*router.Snapshot, error)
	Settings() (model.Settings, error)
	RunState() (store.RunState, error)
}

// ProbeSnapshotSource 是 P0-10 起 Scheduler 构造 expectation 的来源。
//
// livecfg.Source 实现它；缺少已发布快照时任何合成探活都不发送。
type ProbeSnapshotSource interface {
	ProbeSnapshot() (*livecfg.ProbeSnapshot, error)
}

// Scheduler 驱动两级探活（§4.6）。
type Scheduler struct {
	cfg   ConfigSource
	track Tracker
	reach *health.ReachabilityTracker
	log   *slog.Logger

	// recipes 是必须显式装配的 Recipe 四级解析器（§8.2）。
	recipes *RecipeResolver

	// piggyback 记录真实成功替代合成探活的节省事件（§5.2d）。
	piggyback PiggybackRecorder
	realWake  chan struct{}

	// executor 是 L1/L2 唯一的发送与落库执行器；缺失时不发送。
	executor *Executor

	// sequencer 分配 observation order（§P0-06）。走 executor 时，每次发送前
	// 先要一个号；拿不到号就不发（发出去却没有 order 的结果无法排先后）。
	sequencer *observationseq.Sequencer

	// busyUp / inflightL2 的值是 hold token（非 0 = 占用中）。Forget 丢弃
	// 条目后，迟到的 endL2 必须凭 token 比对，否则同 id 新 Route/Upstream
	// 的占用会被旧探活偷清（与 RecoveryGate 同构）。
	mu         sync.Mutex
	busyUp     map[int64]uint64
	inflightL1 map[int64]uint64
	inflightL2 map[int64]uint64
	holdSeq    uint64
	// l2Inflight 是当前已占用的全局 L2 名额。上限每次 beginL2 从
	// Settings.GlobalL2Concurrency 现读（§4.3 Settings 快照；改值无需重启），
	// 在途占用自然收尾，不因缩容而提前释放。
	l2Inflight  int
	lastRunning store.RunState

	// l1Scheduled 收敛同一轮 tick 内「同时到期」的多条 Route。
	//
	// 与 inflightL1 的分工：inflightL1 标记 goroutine 生命周期（跨 tick，
	// L1 最长 25s 必然跨 tick）；l1Scheduled 标记本轮 tick（每轮开始重置）。
	// 两道闸缺一不可 —— 只靠 inflightL1，同一 tick 内如果第一个 L1 先跑完
	// endL1，后面的 Route 会再抢一次（Issue #21 的根因）；只靠 l1Scheduled，
	// 则一个慢 L1 跨 tick 时会放行并发重复。
	//
	// 只在 tick() 的单线程遍历里读写，不需要额外锁。
	l1Scheduled map[int64]bool

	// l1Followers 按 L1 hold 记录被 beginL1 收敛进这次站级 /models 的同站
	// Route。它们只在 Claim 时预占过，完成时须与发起者一起从完成时刻重算
	// （§8.10），否则下一次 /models 会按开始时刻提前到期。
	l1Followers map[uint64][]int64

	// wg 等所有在途探活收尾，让 Close 有确定的语义。
	wg sync.WaitGroup

	// p012 挂 P0-12 扩展（runstate / pending / jitter）。
	p012 *schedulerP012
}

// Tracker 是 Scheduler 需要的健康状态读写面，由 *health.Tracker 实现。
//
// 定义成接口而不是直接用 *health.Tracker：调度逻辑的分支很多
// （分层间隔、piggyback、并发闸、事件驱动），用假实现测比造一个
// 真 Tracker + 控时钟更直接。
type Tracker interface {
	ClaimL1(routeID int64) (generation uint64, ok bool)
	ClaimL2(routeID int64) (generation uint64, ok bool)
	TriggerL1(routeID int64)
	TriggerL2(routeID int64)
	Report(rep health.Report) bool
	State(routeID int64) model.HealthState
	RetainOnly(keep map[int64]bool)
	ResetAll()
}

func NewScheduler(cfg ConfigSource, track Tracker, reach *health.ReachabilityTracker, log *slog.Logger) *Scheduler {
	if log == nil {
		log = slog.Default()
	}
	if reach == nil {
		reach = health.NewReachabilityTracker(cfg)
	}
	return &Scheduler{cfg: cfg, track: track, reach: reach, log: log, busyUp: map[int64]uint64{}, inflightL1: map[int64]uint64{}, inflightL2: map[int64]uint64{}, l1Scheduled: map[int64]bool{}, l1Followers: map[uint64][]int64{}, lastRunning: store.StateRunning, realWake: make(chan struct{}, 1)}
}

// WithExecutor 注入 P0-09 的单发执行器（§P0-09 目标）。
//
// L1/L2 经 Executor 发送并落一行 ProbeExecution，再使用事务已提交的结论。
func (s *Scheduler) WithExecutor(executor *Executor) *Scheduler {
	s.executor = executor
	return s
}

// WithSequencer 注入 observation order 分配器（§P0-06）。
//
// 只在走 Executor 时用：每次发送前分配一个号，写进 ExecutionRequest。
func (s *Scheduler) WithSequencer(sequencer *observationseq.Sequencer) *Scheduler {
	s.sequencer = sequencer
	return s
}

// nextOrder 为一次探活分配 observation order。
//
// sequencer 未装配或拿不到号时返回错误，调用方据此不发这次探活。
func (s *Scheduler) nextOrder(ctx context.Context, trigger model.ProbeTrigger) (int64, error) {
	if s.sequencer == nil {
		return 0, observationseq.ErrUnavailable
	}
	return s.sequencer.Next(ctx, trigger)
}

// execL1 经 Executor 跑一次站级 L1。
func (s *Scheduler) execL1(ctx context.Context, up *model.Upstream, settings model.Settings) (ExecutionResult, *model.ReachabilityExpectation) {
	order, err := s.nextOrder(ctx, model.TriggerScheduled)
	if err != nil {
		return ExecutionResult{Outcome: Outcome{Verdict: health.VerdictIgnore}}, nil
	}
	req := ExecutionRequest{
		ExecutionID:      sample.NewReqID(),
		Trigger:          model.TriggerScheduled,
		Upstream:         up,
		Endpoint:         model.EndpointModels,
		Mode:             ObserveProbe,
		Budget:           outbound.L1Budget(settings),
		ObservationOrder: order,
	}
	if err := s.attachExpectations(ctx, &req, up, nil, nil, model.EndpointModels); err != nil {
		return ExecutionResult{Outcome: Outcome{Verdict: health.VerdictIgnore, Err: err}}, nil
	}
	res, err := s.executor.Execute(ctx, req)
	if err != nil {
		s.log.Error("L1 执行失败", "upstream", up.Name, "err", err)
		return ExecutionResult{Outcome: Outcome{Verdict: health.VerdictIgnore}}, nil
	}
	return res, req.ReachabilityExpectation
}

// execL2 经 Executor 跑一次 Route 级 L2。
func (s *Scheduler) execL2(ctx context.Context, up *model.Upstream, mn *model.ModelName,
	rt *model.Route, settings model.Settings) (ExecutionResult, *model.SemanticExpectation) {

	kind, ok := mn.Protocol.Endpoint()
	if !ok {
		return ExecutionResult{Outcome: Outcome{Verdict: health.VerdictUnavailable,
			Err: fmt.Errorf("协议 %q 没有对应的 Endpoint", mn.Protocol)}}, nil
	}
	order, err := s.nextOrder(ctx, model.TriggerScheduled)
	if err != nil {
		return ExecutionResult{Outcome: Outcome{Verdict: health.VerdictIgnore}}, nil
	}
	req := ExecutionRequest{
		ExecutionID:      sample.NewReqID(),
		Trigger:          model.TriggerScheduled,
		Upstream:         up,
		ModelName:        mn,
		Route:            rt,
		Endpoint:         kind,
		Mode:             ObserveProbe,
		Budget:           outbound.L2Budget(settings),
		ObservationOrder: order,
	}
	if err := s.attachExpectations(ctx, &req, up, mn, rt, kind); err != nil {
		return ExecutionResult{Outcome: Outcome{Verdict: health.VerdictIgnore, Err: err}}, nil
	}
	res, err := s.executor.Execute(ctx, req)
	if err != nil {
		s.log.Error("L2 执行失败", "upstream", up.Name, "model", mn.Name, "err", err)
		return ExecutionResult{Outcome: Outcome{Verdict: health.VerdictIgnore}}, nil
	}
	return res, req.CapabilityExpectation
}

// attachExpectations binds the actual fixed attempt to one published snapshot.
// Missing configuration, order or identity must stop before any network request.
func (s *Scheduler) attachExpectations(ctx context.Context, req *ExecutionRequest,
	up *model.Upstream, mn *model.ModelName, rt *model.Route, endpoint model.EndpointKind) error {
	src, ok := s.cfg.(ProbeSnapshotSource)
	if !ok || src == nil {
		return livecfg.ErrProbeSnapshotUnavailable
	}
	snap, err := src.ProbeSnapshot()
	if err != nil {
		return err
	}
	if snap == nil || up == nil {
		return livecfg.ErrProbeSnapshotUnavailable
	}
	currentUp := snap.Upstreams[up.ID]
	if currentUp == nil || !currentUp.Enabled || currentUp.CreatedAt != up.CreatedAt ||
		currentUp.NetworkRevision != up.NetworkRevision || currentUp.CredentialRevision != up.CredentialRevision {
		return livecfg.ErrProbeSnapshotUnavailable
	}
	var routeID int64
	if endpoint != model.EndpointModels {
		if rt == nil || mn == nil {
			return livecfg.ErrProbeSnapshotUnavailable
		}
		currentRoute, currentModel := snap.Routes[rt.ID], snap.ModelNames[mn.ID]
		if currentRoute == nil || currentModel == nil || !currentRoute.Enabled || !currentModel.Enabled ||
			currentRoute.UpstreamID != up.ID || currentRoute.ModelNameID != mn.ID ||
			currentRoute.CreatedAt != rt.CreatedAt || currentRoute.CapabilityRevision != rt.CapabilityRevision ||
			currentModel.CapabilityRevision != mn.CapabilityRevision {
			return livecfg.ErrProbeSnapshotUnavailable
		}
		routeID = rt.ID
	}
	recipe, err := s.resolveRecipeForExpectation(ctx, up.ID, routeID, endpoint)
	if err != nil {
		return err
	}
	if endpoint == model.EndpointModels {
		reach, reachPol, cap, capPol, err := buildL1Expectations(snap, up.ID, recipe)
		if err != nil {
			return err
		}
		req.ReachabilityExpectation, req.ReachabilityPolicy = reach, reachPol
		req.CapabilityExpectation, req.CapabilityPolicy = cap, capPol
		req.Budget = outbound.L1Budget(snap.Settings)
		return nil
	}
	reach, reachPol, cap, capPol, err := buildL2Expectations(snap, up, rt, endpoint, recipe)
	if err != nil {
		return err
	}
	req.ReachabilityExpectation, req.ReachabilityPolicy = reach, reachPol
	req.CapabilityExpectation, req.CapabilityPolicy = cap, capPol
	timeout := recipe.TimeoutProfile
	if timeout == "" {
		timeout = model.TimeoutL2Standard
	}
	req.Budget = outbound.L2BudgetForProfile(snap.Settings, timeout)
	if endpoint == model.EndpointCountTokens {
		req.Budget = outbound.CountTokensBudget(snap.Settings)
	}
	return nil
}

func (s *Scheduler) resolveRecipeForExpectation(ctx context.Context, upstreamID, routeID int64,
	endpoint model.EndpointKind) (ResolvedRecipe, error) {

	if s.recipes == nil {
		return ResolvedRecipe{}, fmt.Errorf("recipe resolver 未装配")
	}
	return s.recipes.Resolve(ctx, RecipeQuery{UpstreamID: upstreamID, RouteID: routeID, Endpoint: endpoint})
}

// WithRecipes 注入 Recipe 四级解析器（§8.2）。
//
// 未装配时不能验证有效 Recipe 绑定，合成探活必须停止。
func (s *Scheduler) WithRecipes(recipes *RecipeResolver) *Scheduler {
	s.recipes = recipes
	return s
}

// Run 阻塞运行调度循环，直到 ctx 结束。
func (s *Scheduler) Run(ctx context.Context) {
	t := time.NewTicker(tickInterval)
	defer t.Stop()

	s.log.Info("探活调度器已启动", "tick", tickInterval)
	for {
		select {
		case <-ctx.Done():
			// 等在途探活收尾。不等的话进程退出时会有一批半开的连接，
			// 上游侧看到的是「连上就断」，在它们的日志里像是被攻击。
			s.wg.Wait()
			s.log.Info("探活调度器已停止")
			return
		case <-t.C:
			s.tick(ctx)
		case <-s.realWake:
			s.tick(ctx)
		}
	}
}

// tick 是一轮调度。
//
// 全程不阻塞：探活都丢给 goroutine，tick 自己只做「谁该探」的判断。
// 阻塞的话一个卡住的站（L1 给了 25 秒）会拖住整个调度循环，
// 其余站的探活全部延后 —— 而那正是最需要探活的时候。
func (s *Scheduler) tick(ctx context.Context) {
	settings, err := s.cfg.Settings()
	if err != nil {
		s.log.Error("探活调度读取设置失败，本轮跳过", "err", err)
		return
	}
	state := s.currentRunState()

	// §4.8：暂停时探活全停。目的是「不用时不浪费探活额度」。
	if state == store.StatePaused {
		s.onPaused()
		return
	}
	s.onRunning()

	snap, err := s.cfg.Snapshot()
	if err != nil {
		s.log.Error("探活调度读取配置快照失败，本轮跳过", "err", err)
		return
	}

	s.rememberSnapshot(snap)
	s.gcRemoved(snap)

	// 每轮 tick 重新开始，站级 L1 收敛只对本轮生效。
	// 不能把「本轮已调度」的信息留在 inflightL1 里 —— 那是 goroutine
	// 生命周期级的标记，会跨 tick 残留（L1 最长 25s，必然跨 tick）。
	//
	// 在锁内重置：beginL1 在 s.mu 内读写 l1Scheduled，重置与读写必须
	// 用同一把锁，否则将来若有人从其他 goroutine 调 maybeProbe，
	// 这里就成了一个未加锁的整表替换。
	s.mu.Lock()
	s.l1Scheduled = map[int64]bool{}
	s.mu.Unlock()

	eligible := map[int64]bool{}
	for _, mn := range snap.ModelNames {
		if !mn.Enabled {
			continue
		}
		for _, rt := range snap.RoutesByModelName[mn.ID] {
			if !rt.Enabled {
				continue
			}
			up := snap.Upstreams[rt.UpstreamID]
			if up == nil || !up.Enabled {
				continue
			}
			if up.ProbeMode == model.ProbeModeLazy {
				continue
			}
			eligible[up.ID] = true
			s.maybeProbe(ctx, up, mn, rt, settings)
		}
	}
	s.finishResumeRamp(eligible)
}

// maybeProbe 判断并发起一个 Route 的 L1/L2。
func (s *Scheduler) maybeProbe(ctx context.Context, up *model.Upstream,
	mn *model.ModelName, rt *model.Route, settings model.Settings) {

	// L1 是站级的，但到期判定挂在 Route 上（间隔取决于 Route 的状态）。
	// 同一个站下的多个 Route 会各自判定到期，由 beginL1 收敛成一次请求 ——
	// 这正是分两级的收益：N 个 Route 共享一次 L1 结果。
	//
	// beginL1 有两道闸（见其注释）：l1Scheduled 收本轮 tick 内同时到期的
	// 多条 Route，inflightL1 收跨 tick 仍在跑的 L1。
	if _, ok := s.track.ClaimL1(rt.ID); ok {
		ramp, admitted := s.admitResumeL1(up.ID)
		if !admitted {
			// 恢复复核波已满：撤回预占，下个 tick 再排队。
			s.track.TriggerL1(rt.ID)
		} else if hold, ok := s.beginL1(up.ID); ok {
			if ramp {
				s.noteResumeL1Started(up.ID, hold)
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				if ramp {
					defer s.noteResumeL1Ended(up.ID, hold)
				}
				defer s.endL1(up.ID, hold)
				defer s.completeL1(up, rt.ID, hold)
				s.runL1(ctx, up, settings)
			}()
		} else {
			s.followL1(up.ID, rt.ID)
		}
	}

	// 站级不可达时跳过 L2：站都连不上，探模型纯属浪费 token。
	// 必须用快照里的 network revision。用内存行自己的 revision 去比，
	// 等于永远相等，代理或地址改过之后旧的 unreachable 会一直挡住 L2。
	if !s.reach.OK(up.ID, up.NetworkRevision) {
		return
	}
	claim := s.track.ClaimL2
	if s.ensureP012().capReg != nil {
		if current, ok := s.track.(interface{ ClaimL2WithoutPiggyback(int64) (uint64, bool) }); ok {
			claim = current.ClaimL2WithoutPiggyback
		}
	}
	gen, ok := claim(rt.ID)
	if !ok {
		return
	}
	if s.tryPiggyback(rt.ID, gen, time.Now()) {
		return
	}
	hold, ok := s.beginL2(up.ID, rt.ID)
	if !ok {
		// 抢不到并发额度就把预占撤掉，让下一个 tick 重试。
		// 不撤的话这个 Route 要白等一整个 L2 周期（alive 时是 5 分钟）。
		s.track.TriggerL2(rt.ID)
		return
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.endL2(up.ID, rt.ID, hold)
		defer s.completeL2(rt.ID)
		s.runL2(ctx, up, mn, rt, settings, gen)
	}()
}

func (s *Scheduler) runL1(ctx context.Context, up *model.Upstream, settings model.Settings) {
	if s.executor == nil || !s.syntheticUpstreamStillEnabled(up.ID) {
		return
	}
	wasUnreachable := s.reach.Effective(up.ID, up.NetworkRevision) == model.ReachabilityUnreachable
	targets := s.captureL1HealthTargets(up.ID)
	result, expectation := s.execL1(ctx, up, settings)
	if result.Outcome.Verdict == health.VerdictIgnore || result.Decision.ErrorClass == model.ErrorIgnored || result.Apply.Reachability != model.ApplyCurrent || result.Apply.CommittedReachability == nil {
		return
	}
	if !reachabilityHealthCurrent(s.cfg, expectation) {
		return
	}
	reachable, applicable := l1StationEffect(result.Decision)
	if !applicable {
		return
	}
	if !reachable {
		s.propagateL1Failure(up, result.Outcome, targets)
		return
	}
	if wasUnreachable && result.Apply.CommittedReachability.State != model.ReachabilityUnreachable && s.reach.OK(up.ID, up.NetworkRevision) {
		n := s.triggerDeadRoutes(up.ID)
		s.log.Info("上游 Reachability 恢复，已触发 dead Route L2", "upstream", up.Name, "routes", n)
	}
}

// l1StationEffect 决定这次 L1 能不能当成「站不可达」。
//
// 拿到响应头（任何状态码，含 401/404/429/503）都算可达，不得连坐 RouteHealth。
// 只有 ErrorUnreachable，或状态码为 0 且不是本地 config_error，才更新站级失败。
// config_error 返回 apply=false：调用方不得改 Gate，也不得传播到 Route。
func l1StationEffect(decision Decision) (reachable, apply bool) {
	switch decision.ErrorClass {
	case model.ErrorIgnored:
		return false, false
	case model.ErrorConfig:
		if decision.StatusCode <= 0 {
			return false, false
		}
	case model.ErrorUnreachable:
		return false, true
	}
	if decision.StatusCode > 0 || decision.Reachable {
		return true, true
	}
	return false, true
}

type l1HealthTarget struct {
	routeID    int64
	generation uint64
}

// Capture child generations before sending. A committed SQL return can arrive
// after re-enable or ID reuse; enumerating current routes then reporting an
// unbound generation would turn that old failure into new health evidence.
func (s *Scheduler) captureL1HealthTargets(upstreamID int64) []l1HealthTarget {
	snap, err := s.cfg.Snapshot()
	if err != nil || snap == nil {
		return nil
	}
	var targets []l1HealthTarget
	for _, rts := range snap.RoutesByModelName {
		for _, rt := range rts {
			if rt.UpstreamID != upstreamID || !rt.Enabled {
				continue
			}
			if generation := ensureRouteGeneration(s.track, rt.ID); generation > 0 {
				targets = append(targets, l1HealthTarget{rt.ID, generation})
			}
		}
	}
	return targets
}

// propagateL1Failure updates only the child identities captured for this attempt.
func (s *Scheduler) propagateL1Failure(up *model.Upstream, out Outcome, targets []l1HealthTarget) {
	var affected int
	for _, target := range targets {
		if s.track.Report(health.Report{RouteID: target.routeID, Generation: target.generation,
			Verdict: out.Verdict, Source: health.SourceL1, Err: out.Err, RetryAfter: out.RetryAfter}) {
			affected++
		}
	}
	s.log.Warn("上游 L1 失败", "upstream", up.Name, "verdict", out.Verdict.String(),
		"err", out.Err, "state_changed_routes", affected)
}

// triggerDeadRoutes 对该站所有 dead 的 Route 清掉 L2 预占。
func (s *Scheduler) triggerDeadRoutes(upstreamID int64) int {
	snap, err := s.cfg.Snapshot()
	if err != nil {
		return 0
	}
	var n int
	for _, rts := range snap.RoutesByModelName {
		for _, rt := range rts {
			if rt.UpstreamID != upstreamID || !rt.Enabled {
				continue
			}
			if s.track.State(rt.ID) == model.StateDead {
				s.track.TriggerL2(rt.ID)
				n++
			}
		}
	}
	return n
}

// OnReachabilityRecovered 是 ResultRecorder 的回调：非 L1 轮次的已提交观察
// （L2、手动测试）让站离开 unreachable 时，同样即时调度 dead Route 的 L2
// （§8.10）。定时 L1 轮次由 runL1 自己按同一条件触发，这里跳过以免重复。
func (s *Scheduler) OnReachabilityRecovered(execution model.ProbeExecution) {
	if execution.Trigger == model.TriggerScheduled && execution.Endpoint == model.EndpointModels {
		return
	}
	n := s.triggerDeadRoutes(execution.UpstreamID)
	s.log.Info("上游 Reachability 离开 unreachable，已触发该站 dead Route 的 L2",
		"upstream_id", execution.UpstreamID, "trigger", execution.Trigger, "routes", n)
}

func (s *Scheduler) runL2(ctx context.Context, up *model.Upstream,
	mn *model.ModelName, rt *model.Route, settings model.Settings, generation uint64) {

	// 同 runL1：已 Claim/beginL2 的回调在 RoundTrip 前必须再确认目标仍启用。
	if !s.syntheticRouteStillEnabled(rt.ID, up.ID) {
		s.log.Info("Route/Upstream 已停用，跳过已武装的 L2",
			"upstream", up.Name, "route", rt.ID)
		return
	}
	if s.executor == nil {
		return
	}
	result, expectation := s.execL2(ctx, up, mn, rt, settings)
	out := result.Outcome
	if out.Verdict == health.VerdictIgnore || result.Apply.Capability != model.ApplyCurrent {
		return
	}
	if !capabilityHealthCurrent(s.cfg, expectation) {
		return
	}
	if out.Verdict == health.VerdictOK && (result.Apply.CommittedCapability == nil || result.Apply.CommittedCapability.State != model.CapabilitySupported) {
		return
	}

	changed := s.track.Report(health.Report{
		RouteID: rt.ID, Generation: generation,
		Verdict: out.Verdict, Source: health.SourceL2,
		HalfOpen: true, // Claimed L2 is the armed synthetic recovery path (§9.1)
		Err:      out.Err, TTFT: out.TTFT, RetryAfter: out.RetryAfter,
	})

	// 只在状态变化时记 info，否则每 5 分钟一行「still alive」会把日志刷满。
	if changed {
		s.log.Info("L2 探活导致状态变化",
			"upstream", up.Name, "model", mn.Name, "route", rt.ID,
			"state", s.track.State(rt.ID), "verdict", out.Verdict.String(),
			"ttft_ms", out.TTFT.Milliseconds(), "err", out.Err)
		return
	}
	s.log.Debug("L2 探活完成", "upstream", up.Name, "model", mn.Name,
		"verdict", out.Verdict.String(), "ttft_ms", out.TTFT.Milliseconds())
}

// completeL1 从完成时刻重算发起者及其同站跟随者的下次 L1（共用一个 jitter，
// 同站到期保持一致才能继续收敛成一次 /models）。
//
// 站已提交 unreachable 时走 CompleteL1Unreachable：unknown Route 不得因间隔为 0
// 在该站的 20 秒连接恢复周期内反复触发 /models（§8.9 / §8.10）。
func (s *Scheduler) completeL1(up *model.Upstream, routeID int64, hold uint64) {
	s.mu.Lock()
	followers := s.l1Followers[hold]
	delete(s.l1Followers, hold)
	s.mu.Unlock()
	completer, ok := s.track.(interface {
		CompleteL1(routeID int64, completedAt time.Time, jitter float64)
	})
	if !ok {
		return
	}
	complete := completer.CompleteL1
	if !s.reach.OK(up.ID, up.NetworkRevision) {
		if u, ok := s.track.(interface {
			CompleteL1Unreachable(routeID int64, completedAt time.Time, jitter float64)
		}); ok {
			complete = u.CompleteL1Unreachable
		}
	}
	now, jitter := time.Now(), s.jitterFactor()
	complete(routeID, now, jitter)
	for _, id := range followers {
		complete(id, now, jitter)
	}
}

// followL1 把被在途站级 L1 收敛掉的 Route 挂到该次 L1 上。
func (s *Scheduler) followL1(upstreamID, routeID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hold := s.inflightL1[upstreamID]
	routes, open := s.l1Followers[hold]
	if hold == 0 || !open || slices.Contains(routes, routeID) {
		return
	}
	s.l1Followers[hold] = append(routes, routeID)
}

func (s *Scheduler) completeL2(routeID int64) {
	completer, ok := s.track.(interface {
		CompleteL2(routeID int64, completedAt time.Time, jitter float64)
	})
	if !ok {
		return
	}
	completer.CompleteL2(routeID, time.Now(), s.jitterFactor())
}

// ── 并发闸 ───────────────────────────────────────────────

// beginL1 保证「同一轮 tick 内同一个站只调度一次 L1」，且「同一时刻
// 同一个站只有一个 L1 在跑」。
//
// 两道闸，各挡一种重复：
//
//  1. l1Scheduled 挡「同一 tick 内同时到期」。一个站下挂 5 个 Route 时，
//     5 个 Route 各自判定 L1 到期，若都放行就会对同一个 /v1/models 打 5 次
//     完全相同的请求。这个标记在每轮 tick 开始重置（见 tick）。
//
//  2. inflightL1 挡「跨 tick 重叠」。L1 最长给 25s，必然跨 tick；若一个站
//     的 L1 还在跑，下一个 tick 里该站的 Route 不该再发一个。这个标记在
//     L1 goroutine 完成时清除（endL1）。
//
// 缺任一道闸都会重复：Issue #21 的根因就是只靠 inflightL1 —— 同一 tick 内
// 若第一个 L1 先跑完 endL1，后面的 Route 会再抢一次。
func (s *Scheduler) beginL1(upstreamID int64) (hold uint64, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.l1Scheduled[upstreamID] || s.inflightL1[upstreamID] != 0 {
		return 0, false
	}
	s.holdSeq++
	hold = s.holdSeq
	s.l1Scheduled[upstreamID] = true
	s.inflightL1[upstreamID] = hold
	s.l1Followers[hold] = nil
	return hold, true
}

func (s *Scheduler) endL1(upstreamID int64, hold uint64) {
	s.mu.Lock()
	if s.inflightL1[upstreamID] == hold {
		delete(s.inflightL1, upstreamID)
	} else {
		hold = 0
	}
	s.mu.Unlock()
	if hold != 0 {
		s.noteL1Finished(upstreamID)
	}
}

// beginL2 同时满足三个约束：全局并发上限、同 Upstream 串行、同 Route 不重入。
//
// 拒绝时不置 pendingL2：周期到期被拒由调用方撤预占、下个 tick 重试；
// 置了 pending 会在该 Route 下一次完成后立刻再补一发，绕过从完成时刻
// 计算的间隔（§8.10）。pending 只留给在途期间的事件触发。
func (s *Scheduler) beginL2(upstreamID, routeID int64) (hold uint64, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.busyUp[upstreamID] != 0 || s.inflightL2[routeID] != 0 || s.l2Inflight >= s.l2Limit() {
		return 0, false
	}
	s.holdSeq++
	hold = s.holdSeq
	s.l2Inflight++
	s.busyUp[upstreamID] = hold
	s.inflightL2[routeID] = hold
	return hold, true
}

func (s *Scheduler) endL2(upstreamID, routeID int64, hold uint64) {
	s.mu.Lock()
	released := false
	if s.inflightL2[routeID] == hold {
		delete(s.inflightL2, routeID)
		if s.l2Inflight > 0 {
			s.l2Inflight--
		}
		released = true
	}
	if s.busyUp[upstreamID] == hold {
		delete(s.busyUp, upstreamID)
	}
	s.mu.Unlock()
	if released {
		s.noteL2Finished(routeID)
	}
}

// ForgetRoute drops L2 scheduler flags for a deleted Route so a reused rowid
// is not skipped as still inflight/pending. Stale endL2 with the old hold
// token becomes a no-op (does not clear a new incarnation's hold).
func (s *Scheduler) ForgetRoute(routeID int64) {
	if routeID < 1 {
		return
	}
	s.mu.Lock()
	if hold := s.inflightL2[routeID]; hold != 0 {
		delete(s.inflightL2, routeID)
		if s.l2Inflight > 0 {
			s.l2Inflight--
		}
		for upID, tok := range s.busyUp {
			if tok == hold {
				delete(s.busyUp, upID)
				break
			}
		}
	}
	s.mu.Unlock()
	p := s.ensureP012()
	p.mu.Lock()
	delete(p.pendingL2, routeID)
	p.mu.Unlock()
}

// ForgetUpstream drops L1/L2 scheduler flags for a deleted Upstream and its
// child Routes (CASCADE skips per-route delete hooks).
func (s *Scheduler) ForgetUpstream(upstreamID int64, routeIDs []int64) {
	if upstreamID > 0 {
		s.mu.Lock()
		delete(s.inflightL1, upstreamID)
		delete(s.busyUp, upstreamID)
		delete(s.l1Scheduled, upstreamID)
		s.mu.Unlock()
		p := s.ensureP012()
		p.mu.Lock()
		delete(p.pendingL1, upstreamID)
		p.mu.Unlock()
	}
	for _, id := range routeIDs {
		s.ForgetRoute(id)
	}
}

// l2Limit 现读全局 L2 并发上限。Settings 不可读或值不大于 0 时回退默认 3。
func (s *Scheduler) l2Limit() int {
	n := model.DefaultSettings().GlobalL2Concurrency
	if settings, err := s.cfg.Settings(); err == nil && settings.GlobalL2Concurrency > 0 {
		n = settings.GlobalL2Concurrency
	}
	return n
}

// ── 总闸联动（§4.8）─────────────────────────────────────

// onPaused 在进入暂停时记一次日志。
//
// 不在这里取消在途探活：探活本身有 Total 超时（L1 25s / L2 150s），
// 自己会收尾。为了「立刻停」而额外维护一组 cancel func，换来的只是
// 几十秒的差别，代价是一份需要与 goroutine 生命周期保持同步的状态。
func (s *Scheduler) onPaused() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastRunning == store.StatePaused {
		return
	}
	s.lastRunning = store.StatePaused
	s.log.Info("服务已暂停，探活全停")
}

// onRunning 在从暂停恢复时把状态清回 unknown（§4.8）。
//
// 必须清：暂停期间站点可能恢复也可能挂掉，暂停前的状态已经过期了。
// 清成 unknown 而不是保留，还顺带实现了「暖机窗口」—— unknown 是乐观的
// （视为可用），所以恢复瞬间就能承接流量，不会出现「刚点开就 503」。
func (s *Scheduler) onRunning() {
	s.mu.Lock()
	if s.lastRunning == store.StateRunning {
		s.mu.Unlock()
		return
	}
	s.lastRunning = store.StateRunning
	s.mu.Unlock()

	s.PrepareResume()
	s.ResumeGradually()
}

// gcRemoved 丢弃已被删除的 Route/Upstream 的状态。
//
// 放在调度循环里而不是在每个删除入口挂钩子：钩子漏一处就会留下
// 一条永远不被清理的记录，而「漏没漏」只能靠人去核对每个入口。
// 这里以配置快照为唯一真相，天然不会漏。
func (s *Scheduler) gcRemoved(snap *router.Snapshot) {
	routes := map[int64]bool{}
	for _, rts := range snap.RoutesByModelName {
		for _, rt := range rts {
			routes[rt.ID] = true
		}
	}
	s.track.RetainOnly(routes)

	ups := make(map[int64]bool, len(snap.Upstreams))
	for id := range snap.Upstreams {
		ups[id] = true
	}
	s.reach.RetainOnly(ups)

	// Scheduler L2/L1 flags are keyed by integer id. Delete hooks Forget them
	// immediately (id reuse); this sweep covers any missed hook so maps do
	// not grow for forever-deleted ids.
	s.mu.Lock()
	for id, hold := range s.inflightL2 {
		if routes[id] {
			continue
		}
		delete(s.inflightL2, id)
		if s.l2Inflight > 0 {
			s.l2Inflight--
		}
		for upID, tok := range s.busyUp {
			if tok == hold {
				delete(s.busyUp, upID)
				break
			}
		}
	}
	for id := range s.busyUp {
		if !ups[id] {
			delete(s.busyUp, id)
		}
	}
	for id := range s.inflightL1 {
		if !ups[id] {
			delete(s.inflightL1, id)
		}
	}
	for id := range s.l1Scheduled {
		if !ups[id] {
			delete(s.l1Scheduled, id)
		}
	}
	s.mu.Unlock()
	p := s.ensureP012()
	p.mu.Lock()
	for id := range p.pendingL2 {
		if !routes[id] {
			delete(p.pendingL2, id)
		}
	}
	for id := range p.pendingL1 {
		if !ups[id] {
			delete(p.pendingL1, id)
		}
	}
	p.mu.Unlock()
}

// ── 即时探活（§4.5）──────────────────────────────────────

// PrepareManual 为管理面的一次 manual Execute 分配 observation order 并附上
// 同一套双期望。缺了期望，结论只落 execution 行、不推进
// Capability，人工重测便无法按 §8.13 解除 config_error。拿不到号返回错误，
// 调用方据此不发。
func (s *Scheduler) PrepareManual(ctx context.Context, req *ExecutionRequest) error {
	order, err := s.nextOrder(ctx, model.TriggerManual)
	if err != nil {
		return err
	}
	req.ObservationOrder = order
	return s.attachExpectations(ctx, req, req.Upstream, req.ModelName, req.Route, req.Endpoint)
}

func findModelName(snap *router.Snapshot, id int64) *model.ModelName {
	for _, mn := range snap.ModelNames {
		if mn.ID == id {
			return mn
		}
	}
	return nil
}

func findRoute(snap *router.Snapshot, routeID int64) *model.Route {
	if snap == nil {
		return nil
	}
	for _, rts := range snap.RoutesByModelName {
		for _, rt := range rts {
			if rt.ID == routeID {
				return rt
			}
		}
	}
	return nil
}

// syntheticUpstreamStillEnabled is the L1 pre-send gate: an armed station probe
// must not RoundTrip after the Upstream was disabled between Claim and send.
func (s *Scheduler) syntheticUpstreamStillEnabled(upstreamID int64) bool {
	snap, err := s.cfg.Snapshot()
	if err != nil || snap == nil {
		return false
	}
	up := snap.Upstreams[upstreamID]
	return up != nil && up.Enabled
}

// syntheticRouteStillEnabled is the L2 pre-send gate for an armed Route probe.
func (s *Scheduler) syntheticRouteStillEnabled(routeID, upstreamID int64) bool {
	snap, err := s.cfg.Snapshot()
	if err != nil || snap == nil {
		return false
	}
	up := snap.Upstreams[upstreamID]
	if up == nil || !up.Enabled {
		return false
	}
	rt := findRoute(snap, routeID)
	if rt == nil || !rt.Enabled || rt.UpstreamID != upstreamID {
		return false
	}
	mn := findModelName(snap, rt.ModelNameID)
	return mn != nil && mn.Enabled
}

// ensureRouteGeneration 在未先 Claim 的路径上绑定世代（手动探活 / piggyback）。
func ensureRouteGeneration(track Tracker, routeID int64) uint64 {
	if eg, ok := track.(interface{ EnsureGeneration(int64) uint64 }); ok {
		return eg.EnsureGeneration(routeID)
	}
	return 0
}

// ── 配置变更触发即时探活（§4.5）─────────────────
// InvalidateRoute / InvalidateUpstream 见 scheduler_control.go。
