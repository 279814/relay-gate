package probe

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/router"
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

// TransportSource 按 Upstream 提供出站 Transport。
//
// 与转发路径共用（proxy.Handler 实现它）：探活顺带把连接热着，
// 真实请求就省掉一次 TLS 握手 —— 对高延迟的公益站，握手占首字节的
// 可观比例。各建一套连接池的话这份收益就没了，还多一倍空闲连接。
type TransportSource interface {
	TransportFor(up *model.Upstream, s model.Settings) (*http.Transport, error)
}

// Scheduler 驱动两级探活（§4.6）。
type Scheduler struct {
	cfg   ConfigSource
	tr    TransportSource
	track Tracker
	gate  *health.UpstreamGate
	log   *slog.Logger

	// cost 累计探活开销（§5.2d）。可以为 nil —— 测试里多数用例不关心计数，
	// 而记账失败绝不该影响探活本身。
	cost *Cost

	// l2Sem 是全局 L2 并发闸。L2 消耗 token 且打的是真实模型端点，
	// 不限并发的话，一次「全部 Route 都到期」会同时向所有站发请求 ——
	// 那看起来就像一次小型压测，很容易触发站点的限流。
	l2Sem chan struct{}

	// busyUp 保证同一 Upstream 的 L2 串行（§4.6）。
	// 一个站下挂 5 个模型时，同时探 5 个几乎必然吃 429。
	mu          sync.Mutex
	busyUp      map[int64]bool
	inflightL1  map[int64]bool
	inflightL2  map[int64]bool
	lastRunning store.RunState

	// wg 等所有在途探活收尾，让 Close 有确定的语义。
	wg sync.WaitGroup
}

// Tracker 是 Scheduler 需要的健康状态读写面，由 *health.Tracker 实现。
//
// 定义成接口而不是直接用 *health.Tracker：调度逻辑的分支很多
// （分层间隔、piggyback、并发闸、事件驱动），用假实现测比造一个
// 真 Tracker + 控时钟更直接。
type Tracker interface {
	ClaimL1(routeID int64) bool
	ClaimL2(routeID int64) bool
	TriggerL1(routeID int64)
	TriggerL2(routeID int64)
	Report(rep health.Report) bool
	State(routeID int64) model.HealthState
	RetainOnly(keep map[int64]bool)
	ResetAll()
}

func NewScheduler(cfg ConfigSource, tr TransportSource, track Tracker,
	gate *health.UpstreamGate, log *slog.Logger) *Scheduler {

	return &Scheduler{
		cfg: cfg, tr: tr, track: track, gate: gate, log: log,
		busyUp:      map[int64]bool{},
		inflightL1:  map[int64]bool{},
		inflightL2:  map[int64]bool{},
		lastRunning: store.StateRunning,
	}
}

// WithCost 接上探活成本计数器（§5.2d）。
//
// 分成单独的 setter 而不是加构造参数：计数是观测，不是调度的依赖，
// 而 NewScheduler 已经有五个参数了。
func (s *Scheduler) WithCost(c *Cost) *Scheduler {
	s.cost = c
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
	state, err := s.cfg.RunState()
	if err != nil {
		s.log.Error("探活调度读取运行状态失败，本轮跳过", "err", err)
		return
	}

	// §4.8：暂停时探活全停。目的是「不用时不浪费探活额度」。
	if state == store.StatePaused {
		s.onPaused()
		return
	}
	s.onRunning()

	if !settings.ProbeEnabled {
		return
	}

	snap, err := s.cfg.Snapshot()
	if err != nil {
		s.log.Error("探活调度读取配置快照失败，本轮跳过", "err", err)
		return
	}

	s.gcRemoved(snap)

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
			s.maybeProbe(ctx, up, mn, rt, settings)
		}
	}
}

// maybeProbe 判断并发起一个 Route 的 L1/L2。
func (s *Scheduler) maybeProbe(ctx context.Context, up *model.Upstream,
	mn *model.ModelName, rt *model.Route, settings model.Settings) {

	// L1 是站级的，但到期判定挂在 Route 上（间隔取决于 Route 的状态）。
	// 同一个站下的多个 Route 会各自判定到期，由 inflightL1 收敛成一次请求 ——
	// 这正是分两级的收益：N 个 Route 共享一次 L1 结果。
	if s.track.ClaimL1(rt.ID) && s.beginL1(up.ID) {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.endL1(up.ID)
			s.runL1(ctx, up, settings)
		}()
	}

	// 站级 L1 失败时跳过 L2（§4.1）：站都连不上，探模型纯属浪费 token。
	if !s.gate.OK(up.ID) {
		return
	}
	if !s.track.ClaimL2(rt.ID) {
		return
	}
	if !s.beginL2(up.ID, rt.ID) {
		// 抢不到并发额度就把预占撤掉，让下一个 tick 重试。
		// 不撤的话这个 Route 要白等一整个 L2 周期（alive 时是 5 分钟）。
		s.track.TriggerL2(rt.ID)
		return
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.endL2(up.ID, rt.ID)
		s.runL2(ctx, up, mn, rt, settings)
	}()
}

func (s *Scheduler) runL1(ctx context.Context, up *model.Upstream, settings model.Settings) {
	tr, err := s.tr.TransportFor(up, settings)
	if err != nil {
		s.log.Error("探活构造 Transport 失败", "upstream", up.Name, "err", err)
		return
	}

	out := (&Prober{Transport: tr}).L1(ctx, up, settings)
	if out.Verdict == health.VerdictIgnore {
		return // 探活被取消（暂停/关闭），不是上游的问题
	}

	ok := out.Verdict == health.VerdictOK
	s.countL1(up.ID, ok)
	recovered := s.gate.Report(up.ID, ok, out.Err)

	if !ok {
		// L1 失败 → 整站 dead：该 Upstream 下所有 Route 一并标记（§4.1）。
		// 这是分两级的主要收益 —— 一次零 token 的探测就否决了整站。
		s.propagateL1Failure(up, out)
		return
	}

	if recovered {
		// §4.4b：L1 从失败转成功，立即对该站所有 dead Route 触发 L2，
		// 不等 L2 周期。站级恢复的发现延迟因此收敛到 L1 周期（20s）。
		n := s.triggerDeadRoutes(up.ID)
		s.log.Info("上游 L1 恢复，已触发该站 dead Route 的 L2",
			"upstream", up.Name, "routes", n)
	}
}

// propagateL1Failure 把站级失败落到该 Upstream 下的每个 Route。
func (s *Scheduler) propagateL1Failure(up *model.Upstream, out Outcome) {
	snap, err := s.cfg.Snapshot()
	if err != nil {
		return
	}
	var affected int
	for _, rts := range snap.RoutesByModelName {
		for _, rt := range rts {
			if rt.UpstreamID != up.ID || !rt.Enabled {
				continue
			}
			if s.track.Report(health.Report{
				RouteID: rt.ID, Verdict: out.Verdict, Source: health.SourceL1,
				Err: out.Err, RetryAfter: out.RetryAfter,
			}) {
				affected++
			}
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

func (s *Scheduler) runL2(ctx context.Context, up *model.Upstream,
	mn *model.ModelName, rt *model.Route, settings model.Settings) {

	tr, err := s.tr.TransportFor(up, settings)
	if err != nil {
		s.log.Error("探活构造 Transport 失败", "upstream", up.Name, "err", err)
		return
	}

	out := (&Prober{Transport: tr}).L2(ctx, up, mn, rt, settings)
	if out.Verdict == health.VerdictIgnore {
		return
	}
	s.countL2(rt.ID, mn, out.Verdict == health.VerdictOK)

	changed := s.track.Report(health.Report{
		RouteID: rt.ID, Verdict: out.Verdict, Source: health.SourceL2,
		Err: out.Err, TTFT: out.TTFT, RetryAfter: out.RetryAfter,
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

// ── 并发闸 ───────────────────────────────────────────────

// beginL1 保证同一个站同时只有一个 L1 在跑。
//
// 收敛是必须的：一个站下挂 5 个 Route 时，5 个 Route 各自判定 L1 到期，
// 不收敛就会对同一个 /v1/models 打 5 次完全相同的请求。
func (s *Scheduler) beginL1(upstreamID int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflightL1[upstreamID] {
		return false
	}
	s.inflightL1[upstreamID] = true
	return true
}

func (s *Scheduler) endL1(upstreamID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inflightL1, upstreamID)
}

// beginL2 同时满足三个约束：全局并发上限、同 Upstream 串行、同 Route 不重入。
func (s *Scheduler) beginL2(upstreamID, routeID int64) bool {
	s.mu.Lock()
	if s.busyUp[upstreamID] || s.inflightL2[routeID] {
		s.mu.Unlock()
		return false
	}
	sem := s.sem()
	s.mu.Unlock()

	// 非阻塞获取全局额度：满了就让这个 Route 等下一个 tick，
	// 而不是把 tick 的 goroutine 堵在这里。
	select {
	case sem <- struct{}{}:
	default:
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// 双检：等额度期间可能已被同站的另一个 Route 抢先。
	if s.busyUp[upstreamID] || s.inflightL2[routeID] {
		<-sem
		return false
	}
	s.busyUp[upstreamID] = true
	s.inflightL2[routeID] = true
	return true
}

func (s *Scheduler) endL2(upstreamID, routeID int64) {
	s.mu.Lock()
	delete(s.busyUp, upstreamID)
	delete(s.inflightL2, routeID)
	sem := s.l2Sem
	s.mu.Unlock()
	if sem != nil {
		<-sem
	}
}

// sem 懒建全局 L2 闸。调用方必须已持有锁。
//
// 懒建是因为容量来自配置（global_l2_concurrency），而配置在启动时
// 未必已经可读（数据库可能还没打开）。改容量需要重启 —— 与
// sample_queue_size 同理：它是 channel 的容量。
func (s *Scheduler) sem() chan struct{} {
	if s.l2Sem != nil {
		return s.l2Sem
	}
	n := model.DefaultSettings().GlobalL2Concurrency
	if settings, err := s.cfg.Settings(); err == nil && settings.GlobalL2Concurrency > 0 {
		n = settings.GlobalL2Concurrency
	}
	s.l2Sem = make(chan struct{}, n)
	return s.l2Sem
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

	s.track.ResetAll()
	s.gate.Reset()
	s.log.Info("服务已恢复，全部 Route 置 unknown 并立即重新探活")
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
	s.gate.RetainOnly(ups)
}

// ── 即时探活（§4.5）──────────────────────────────────────

// ProbeNow 立即探一个 Route，同步返回结果。供 UI 的「测试」按钮用。
//
// 同步是刻意的：用户点了按钮就是要看结果，异步的话还得再设计一个
// 「查询上次手动探活结果」的接口。它不走并发闸 —— 手动触发是单次的，
// 而且用户正在等。
func (s *Scheduler) ProbeNow(ctx context.Context, snap *router.Snapshot,
	rt *model.Route) (l1, l2 Outcome, err error) {

	settings, err := s.cfg.Settings()
	if err != nil {
		return l1, l2, err
	}
	up := snap.Upstreams[rt.UpstreamID]
	if up == nil {
		return l1, l2, errNoUpstream
	}
	mn := findModelName(snap, rt.ModelNameID)
	if mn == nil {
		return l1, l2, errNoModelName
	}

	tr, err := s.tr.TransportFor(up, settings)
	if err != nil {
		return l1, l2, err
	}
	p := &Prober{Transport: tr}

	l1 = p.L1(ctx, up, settings)
	s.countL1(up.ID, l1.Verdict == health.VerdictOK)
	s.gate.Report(up.ID, l1.Verdict == health.VerdictOK, l1.Err)

	// L1 失败就不必再探 L2 —— 站都连不上，探模型只是白等一次超时。
	// 但仍要把失败落到状态机，否则手动测试看到「站挂了」而状态没变。
	if l1.Verdict != health.VerdictOK {
		s.track.Report(health.Report{
			RouteID: rt.ID, Verdict: l1.Verdict, Source: health.SourceL1,
			Err: l1.Err, RetryAfter: l1.RetryAfter,
		})
		return l1, l2, nil
	}

	l2 = p.L2(ctx, up, mn, rt, settings)
	s.countL2(rt.ID, mn, l2.Verdict == health.VerdictOK)
	s.track.Report(health.Report{
		RouteID: rt.ID, Verdict: l2.Verdict, Source: health.SourceL2,
		Err: l2.Err, TTFT: l2.TTFT, RetryAfter: l2.RetryAfter,
	})
	return l1, l2, nil
}

// countL1 / countL2 记一次探活开销（§5.2d）。
//
// cost 为 nil 时静默跳过：记账是观测，绝不该让探活因为它而失败。
func (s *Scheduler) countL1(upstreamID int64, ok bool) {
	if s.cost != nil {
		s.cost.AddL1(upstreamID, ok)
	}
}

func (s *Scheduler) countL2(routeID int64, mn *model.ModelName, ok bool) {
	if s.cost != nil {
		s.cost.AddL2(routeID, ok, estimateL2Tokens(mn))
	}
}

func findModelName(snap *router.Snapshot, id int64) *model.ModelName {
	for _, mn := range snap.ModelNames {
		if mn.ID == id {
			return mn
		}
	}
	return nil
}

// ── 配置变更触发即时探活（§4.5 表格第 3 行）─────────────────

// InvalidateRoute 让某个 Route 在下一个 tick 立刻重探。
//
// 只清预占，不在这里直接发探活请求。理由与 TriggerL2 相同（health/schedule.go）：
// 直接探的话，一次批量配置导入会同时发起几十个请求，而 tick 里已经有
// 完整的并发闸与「同站串行」约束。走 tick 最多等 1 秒。
//
// 顺带清 L1：改了 key 或 base_url 时，L1 的结论同样过期了 —— 而站级 L1
// 失败会让 L2 被整个跳过（§4.1），不清 L1 的话，一个刚被改对的站
// 仍会因为旧的 L1 失败结论而探不到 L2。
func (s *Scheduler) InvalidateRoute(routeID int64) {
	s.track.TriggerL1(routeID)
	s.track.TriggerL2(routeID)
}

// InvalidateUpstream 让某个 Upstream 下所有 Route 立刻重探。
//
// 同时清掉站级 L1 结论：改 key 后旧的「这个站 401」必须作废，
// 否则 L2 会被 gate.OK 挡住，用户改对了 key 也看不到恢复。
func (s *Scheduler) InvalidateUpstream(upstreamID int64) {
	s.gate.Forget(upstreamID)

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

// InvalidateModelName 让某个 ModelName 下所有 Route 重探 L2。
//
// 只清 L2：这个层级能改的是 probe_prompt / probe_max_tokens / protocol，
// 全都只影响 L2 的请求内容。L1 打的是站的 /v1/models，与模型无关 ——
// 清它等于白发一次请求。
func (s *Scheduler) InvalidateModelName(modelNameID int64) {
	snap, err := s.cfg.Snapshot()
	if err != nil {
		return
	}
	for _, rt := range snap.RoutesByModelName[modelNameID] {
		s.track.TriggerL2(rt.ID)
	}
}
