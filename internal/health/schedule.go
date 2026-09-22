package health

import (
	"sort"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

const (
	// shortDeadWindow：dead 不超过 10 分钟 → L2 30s（§8.10）。
	shortDeadWindow = 10 * time.Minute
	// midDeadWindow：dead 10–60 分钟 → L2 120s。
	midDeadWindow = 60 * time.Minute
	// longDeadL2Short / Mid / Long 是三档 dead L2 间隔。
	longDeadL2Short = 30 * time.Second
	longDeadL2Mid   = 120 * time.Second
	longDeadL2Long  = 300 * time.Second
)

// intervalFor 按状态返回 L1/L2 间隔（§4.6 / §8.10）。
//
// dead 用固定短周期而不是指数退避：核心诉求是「死了要尽快发现恢复」。
// 唯一放宽：长期死亡只拉长 L2；L1 / 连接恢复检查保持 20 秒。
func intervalFor(rs *routeState, s model.Settings, now time.Time) (l1, l2 time.Duration) {
	switch rs.state {
	case model.StateDead:
		l1 = time.Duration(s.L1IntervalDeadSec) * time.Second
		l2 = deadL2Interval(rs, s, now)
	case model.StateAlive:
		l1 = time.Duration(s.L1IntervalAliveSec) * time.Second
		l2 = time.Duration(s.L2IntervalAliveSec) * time.Second
	default: // unknown：立即探，两级都要
		return 0, 0
	}
	return l1, l2
}

func deadL2Interval(rs *routeState, s model.Settings, now time.Time) time.Duration {
	// 优先按「已死多久」分档（§8.10）；没有 lastErrAt 时退回设置值。
	if !rs.lastErrAt.IsZero() {
		age := now.Sub(rs.lastErrAt)
		switch {
		case age <= shortDeadWindow:
			return longDeadL2Short
		case age <= midDeadWindow:
			return longDeadL2Mid
		default:
			return longDeadL2Long
		}
	}
	base := time.Duration(s.L2IntervalDeadSec) * time.Second
	if base <= 0 {
		return longDeadL2Short
	}
	return base
}

// ClaimL1 原子地「判断 L1 是否到期并预占下一次」。到期返回 true。
//
// 必须是一个操作，不能拆成 DueL1() + MarkL1()。拆开的话两步之间有窗口：
// 调度器每个 tick 都会遍历所有 Route，若上一轮的探活还没跑完（公益站
// 连接慢，L1 给了 25 秒），下一个 tick 会再次看到「到期」，于是同一个
// Route 被同时探两次 —— 探活请求翻倍，还会互相覆盖判定结果。
//
// 预占的方式是立刻把 nextAt 推到「现在 + 间隔」。探活跑完后由
// Report 触发的状态变化会重算间隔，不需要再回填。
func (t *Tracker) ClaimL1(routeID int64) bool {
	s := t.currentSettings()
	t.mu.Lock()
	defer t.mu.Unlock()

	rs := t.get(routeID)
	now := t.now()
	if !rs.nextL1At.IsZero() && now.Before(rs.nextL1At) {
		return false
	}
	l1, _ := intervalFor(rs, s, now)
	rs.nextL1At = now.Add(l1)
	return true
}

// ClaimL2 同 ClaimL1，另外实现 piggyback（§4.6）。
//
// piggyback：真实请求成功等价于一次 L2 探活 —— 它比 `1+1=?` 有力得多。
// 所以若距上次真实成功还没超过 L2 间隔，就跳过本轮，省下探活 token。
// 活跃使用时 alive 渠道的 L2 次数接近 0，这是设计意图。
//
// 跳过时同样要推进 nextL2At，否则下个 tick 会立刻再判一次 —— 那样
// piggyback 就从「省一次探活」变成了「每个 tick 都白跑一遍判定逻辑」。
func (t *Tracker) ClaimL2(routeID int64) bool {
	s := t.currentSettings()
	t.mu.Lock()
	defer t.mu.Unlock()

	rs := t.get(routeID)
	now := t.now()
	if !rs.nextL2At.IsZero() && now.Before(rs.nextL2At) {
		return false
	}
	_, l2 := intervalFor(rs, s, now)

	// Tracker 侧 piggyback 仅按时间窗粗判；P0-12 Scheduler 以
	// LastRealOKToken == current SemanticRevision 为权威跳过条件。
	// 这里保留时间窗以避免无 Scheduler 装配时的旧路径空转。
	if s.PiggybackEnabled && rs.state != model.StateDead && !rs.lastRealOKAt.IsZero() {
		if now.Sub(rs.lastRealOKAt) < l2 {
			rs.nextL2At = rs.lastRealOKAt.Add(l2)
			return false
		}
	}

	rs.nextL2At = now.Add(l2)
	return true
}

// TriggerL2 清掉 L2 的预占，让下一个 tick 立刻探它（§4.4b / §4.5）。
//
// 用于事件驱动：L1 从失败转成功时对该站所有 dead Route 调它，
// 真实请求失败时对该 Route 调它。
//
// 不在这里直接发起探活，是为了不让状态机依赖 probe 包 —— 那会形成
// health → probe → health 的循环依赖。调度器每秒一个 tick，
// 「下一个 tick」的延迟最多 1 秒，对 20 秒的探活周期无影响。
func (t *Tracker) TriggerL2(routeID int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.get(routeID).nextL2At = time.Time{}
}

// TriggerL1 同 TriggerL2，清掉 L1 预占。
func (t *Tracker) TriggerL1(routeID int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.get(routeID).nextL1At = time.Time{}
}

// ResetAll 把所有 Route 置回 unknown 并清空探活预占。
//
// P0-12 PrepareResume 改用 DemotePositiveConclusions：只降正结论，保留
// dead/recovering/cooldown 等负状态。ResetAll 仍保留给测试与旧调用方。
func (t *Tracker) ResetAll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, rs := range t.state {
		rs.state = model.StateUnknown
		rs.consecutiveOK = 0
		rs.consecutiveFail = 0
		rs.cooldownUntil = time.Time{}
		rs.nextL1At = time.Time{}
		rs.nextL2At = time.Time{}
	}
}

// DemotePositiveConclusions 把 alive 正结论降为 effective unknown（§P0-12 resume）。
//
// dead / recovering / cooldown 负状态保留；只清探活预占以便渐进复核。
func (t *Tracker) DemotePositiveConclusions() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, rs := range t.state {
		if rs.state == model.StateAlive {
			rs.state = model.StateUnknown
			rs.consecutiveOK = 0
		}
		rs.nextL1At = time.Time{}
		rs.nextL2At = time.Time{}
	}
}

// CompleteL1 在探活完成后从完成时刻计算下次到期（§8.10）。
func (t *Tracker) CompleteL1(routeID int64, completedAt time.Time, jitter float64) {
	s := t.currentSettings()
	t.mu.Lock()
	defer t.mu.Unlock()
	rs := t.get(routeID)
	l1, _ := intervalFor(rs, s, completedAt)
	if completedAt.IsZero() {
		completedAt = t.now()
	}
	rs.nextL1At = completedAt.Add(applyJitter(l1, jitter))
}

// CompleteL2 同 CompleteL1。
func (t *Tracker) CompleteL2(routeID int64, completedAt time.Time, jitter float64) {
	s := t.currentSettings()
	t.mu.Lock()
	defer t.mu.Unlock()
	rs := t.get(routeID)
	_, l2 := intervalFor(rs, s, completedAt)
	if completedAt.IsZero() {
		completedAt = t.now()
	}
	rs.nextL2At = completedAt.Add(applyJitter(l2, jitter))
}

// applyJitter 把间隔乘以 [0.9, 1.1] 内的因子；factor<=0 时不加 jitter。
func applyJitter(base time.Duration, factor float64) time.Duration {
	if base <= 0 || factor <= 0 {
		return base
	}
	if factor < 0.9 {
		factor = 0.9
	}
	if factor > 1.1 {
		factor = 1.1
	}
	return time.Duration(float64(base) * factor)
}

// Forget 丢弃某个 Route 的状态，用于 Route 被删除后。
//
// 不清理的话 map 会随「反复增删 Route」单调增长。虽然量级很小
// （每个 Route 一个小结构体），但删掉的 Route 若 ID 被复用，
// 残留的失败计数会被新 Route 继承 —— 那是个说不清的 bug。
func (t *Tracker) Forget(routeID int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.state, routeID)
}

// RetainOnly 只保留 keep 里的 Route，其余丢弃。
// 调度器每轮用当前配置快照调它，省得在每个删除入口挂钩子。
func (t *Tracker) RetainOnly(keep map[int64]bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for id := range t.state {
		if !keep[id] {
			delete(t.state, id)
		}
	}
}

// Status 是单个 Route 健康状态的对外快照（UI 与落库共用）。
type Status struct {
	RouteID         int64             `json:"route_id"`
	State           model.HealthState `json:"state"`
	InFlight        int               `json:"in_flight"`
	ConsecutiveOK   int               `json:"consecutive_ok"`
	ConsecutiveFail int               `json:"consecutive_fail"`
	LastOKAt        int64             `json:"last_ok_at"`
	LastErrAt       int64             `json:"last_err_at"`
	LastError       string            `json:"last_error"`
	LastTTFTMS      int64             `json:"last_ttft_ms"`
	// Reason 区分「配置/鉴权错误」与「服务不可用」。UI 必须分开显示：
	// 前者要用户去改配置，后者等它自己恢复就行（§4.3）。
	Reason string `json:"reason"`
	// CooldownUntil 是 429 冷却截止（Unix 毫秒）。0 表示不在冷却中。
	CooldownUntil int64 `json:"cooldown_until"`
	LastRealOKAt  int64 `json:"last_real_ok_at"`
	NextL1At      int64 `json:"next_l1_at"`
	NextL2At      int64 `json:"next_l2_at"`
}

// Status 返回单个 Route 的快照。
func (t *Tracker) Status(routeID int64) Status {
	t.mu.RLock()
	defer t.mu.RUnlock()
	rs := t.state[routeID]
	if rs == nil {
		return Status{RouteID: routeID, State: model.StateUnknown, Reason: VerdictOK.String()}
	}
	return t.statusOf(routeID, rs)
}

// AllStatus 返回所有已知 Route 的快照，按 RouteID 升序（稳定输出便于 UI 与测试）。
func (t *Tracker) AllStatus() []Status {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]Status, 0, len(t.state))
	for id, rs := range t.state {
		out = append(out, t.statusOf(id, rs))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RouteID < out[j].RouteID })
	return out
}

// statusOf 组装快照。调用方必须已持有读锁。
func (t *Tracker) statusOf(id int64, rs *routeState) Status {
	st := Status{
		RouteID:         id,
		State:           rs.state,
		InFlight:        rs.inFlight,
		ConsecutiveOK:   rs.consecutiveOK,
		ConsecutiveFail: rs.consecutiveFail,
		LastOKAt:        msOrZero(rs.lastOKAt),
		LastErrAt:       msOrZero(rs.lastErrAt),
		LastError:       rs.lastError,
		LastTTFTMS:      rs.lastTTFT.Milliseconds(),
		Reason:          rs.lastReason.String(),
		LastRealOKAt:    msOrZero(rs.lastRealOKAt),
		NextL1At:        msOrZero(rs.nextL1At),
		NextL2At:        msOrZero(rs.nextL2At),
	}
	// 只在冷却仍然有效时报告。过期的截止时刻对 UI 是噪音 ——
	// 「冷却到 10 分钟前」读起来像个 bug。
	if !rs.cooldownUntil.IsZero() && t.now().Before(rs.cooldownUntil) {
		st.CooldownUntil = msOrZero(rs.cooldownUntil)
	}
	return st
}

func msOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}
