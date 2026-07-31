// Package health 维护 Route 的运行时健康状态。
//
// 状态以内存为准（§2.4）：重启后一律回到 unknown，不从库里恢复。
// route_health 表只是给 UI 看的历史快照。
package health

import (
	"sync"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// Tracker 是 router.HealthView 的生产实现，也是 §4.3/§4.4 状态机的宿主。
//
// 在途计数与判死状态机长在同一个类型上：它们读写同一份 per-Route 状态，
// 拆成两个类型只会引入锁的协调问题（谁先拿锁、能不能互相调用）。
type Tracker struct {
	mu    sync.RWMutex
	state map[int64]*routeState

	// settings 提供阈值与间隔。现读而不是定格 —— 用户改了 fail_threshold
	// 就该立刻按新值判定，定格会变成「改了不生效」。
	settings SettingsSource

	now func() time.Time // 测试注入时钟
}

// SettingsSource 提供状态机需要的阈值。由 livecfg 实现（带 2s 缓存）。
type SettingsSource interface {
	Settings() (model.Settings, error)
}

// routeState 是单个 Route 的全部运行时状态。
type routeState struct {
	state    model.HealthState
	inFlight int

	consecutiveOK   int
	consecutiveFail int

	lastOKAt   time.Time
	lastErrAt  time.Time
	lastError  string
	lastTTFT   time.Duration
	lastReason Verdict // 最近一次失败的类别，UI 用它区分「配置错」与「站挂了」

	// cooldownUntil 是 429 冷却的截止时刻。零值表示不在冷却中。
	cooldownUntil time.Time

	// lastRealOKAt 支撑 piggyback（§4.6）：真实请求成功等价于一次 L2 探活，
	// 所以 L2 周期到了但这个时间戳还新鲜的话就跳过本轮，省掉探活 token。
	lastRealOKAt time.Time

	// nextL1At / nextL2At 是下一次探活的**最早**时刻，由调度器读写。
	// 放在这里而不是调度器自己的 map 里，是因为间隔取决于 state ——
	// 分开存就要在两处之间同步状态，而状态变化恰恰是最频繁的事件。
	nextL1At time.Time
	nextL2At time.Time
}

func NewTracker(settings SettingsSource) *Tracker {
	return &Tracker{
		state:    map[int64]*routeState{},
		settings: settings,
		now:      time.Now,
	}
}

// get 取或建某个 Route 的状态。调用方必须已持有写锁。
func (t *Tracker) get(routeID int64) *routeState {
	rs := t.state[routeID]
	if rs == nil {
		rs = &routeState{state: model.StateUnknown}
		t.state[routeID] = rs
	}
	return rs
}

// State 返回 Route 的健康状态。未知的 Route 返回 StateUnknown（视为可用，乐观）。
func (t *Tracker) State(routeID int64) model.HealthState {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if rs := t.state[routeID]; rs != nil {
		return rs.state
	}
	return model.StateUnknown
}

// CoolingDown 表示该 Route 在 429 冷却期内，本轮不选它（但不算 dead）。
func (t *Tracker) CoolingDown(routeID int64) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	rs := t.state[routeID]
	if rs == nil || rs.cooldownUntil.IsZero() {
		return false
	}
	return t.now().Before(rs.cooldownUntil)
}

// InFlight 返回当前在途计数，供管理界面与日志展示。
//
// **不要**用它做并发上限判定：读完再决定要不要占用，两步之间有窗口。
// 判定走 TryAcquire。
func (t *Tracker) InFlight(routeID int64) int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if rs := t.state[routeID]; rs != nil {
		return rs.inFlight
	}
	return 0
}

// TryAcquire 原子地「检查并占用」一个并发额度。limit <= 0 表示不限。
//
// 检查与占用必须是同一个操作。拆成「先读 InFlight 判断、再登记」的话，
// 两步之间有窗口：并发涌入时每个请求都读到涌入前的计数，于是全部通过检查，
// max_concurrency=1 的 Route 会被同时打进去 N 个 —— 而这恰好是限流
// 最需要生效的时刻（站点已经吃不消了）。
//
// 成功时返回的 release 必须在请求结束时调用，漏掉的后果隐蔽且永久：
// 计数只增不减，该 Route 会被永远排除在选路之外。ok 为 false 时 release 为 nil。
func (t *Tracker) TryAcquire(routeID int64, limit int) (release func(), ok bool) {
	t.mu.Lock()
	rs := t.get(routeID)
	if limit > 0 && rs.inFlight >= limit {
		t.mu.Unlock()
		return nil, false
	}
	rs.inFlight++
	t.mu.Unlock()

	// 返回闭包而不是配对的 Acquire/Release：调用方 defer 一下就不可能
	// 记错 routeID，也不可能重复释放（once 兜住）。
	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			defer t.mu.Unlock()
			if rs := t.state[routeID]; rs != nil && rs.inFlight > 0 {
				rs.inFlight--
			}
		})
	}, true
}

// Snapshot 返回所有非零在途计数的副本，供管理界面展示。
func (t *Tracker) Snapshot() map[int64]int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := map[int64]int{}
	for id, rs := range t.state {
		if rs.inFlight > 0 {
			out[id] = rs.inFlight
		}
	}
	return out
}

// Report 按 §4.3 把一次判定应用到状态机，返回状态是否发生了变化。
//
// 返回 changed 是为了让调用方决定要不要落库与打日志：探活每 20 秒跑一次，
// 每次都写库、每次都打一行「still alive」，会把日志和磁盘都刷满。
func (t *Tracker) Report(rep Report) (changed bool) {
	s := t.currentSettings()

	t.mu.Lock()
	defer t.mu.Unlock()

	rs := t.get(rep.RouteID)
	before := rs.state
	now := t.now()

	switch rep.Verdict {
	case VerdictIgnore:
		// 客户端的行为，与上游健康无关。连计数都不动。
		return false

	case VerdictOK:
		t.applyOK(rs, rep, s, now)

	case VerdictFatal:
		// 立即判死，不累计。配置不改就永远是这个结果。
		rs.consecutiveOK = 0
		rs.consecutiveFail++
		rs.state = model.StateDead
		t.noteErr(rs, rep, now)

	case VerdictUnavailable:
		rs.consecutiveOK = 0
		rs.consecutiveFail++
		if rs.consecutiveFail >= s.FailThreshold {
			rs.state = model.StateDead
		}
		t.noteErr(rs, rep, now)

	case VerdictRateLimited:
		// 冷却但不判死，也不动成功计数 —— 站是好的，只是这会儿满了。
		// 清零失败计数同样重要：429 与真实故障交替出现时，
		// 不清零会让限流「帮着」把一个可用的站推向 dead。
		rs.consecutiveFail = 0
		d := rep.RetryAfter
		if d <= 0 {
			d = time.Duration(s.CooldownSec) * time.Second
		}
		rs.cooldownUntil = now.Add(d)
		t.noteErr(rs, rep, now)
	}

	return rs.state != before
}

// applyOK 处理成功判定，实现 §4.4 的恢复规则。
func (t *Tracker) applyOK(rs *routeState, rep Report, s model.Settings, now time.Time) {
	rs.consecutiveFail = 0
	rs.consecutiveOK++
	rs.lastOKAt = now
	rs.lastError = ""
	rs.lastReason = VerdictOK
	// 成功即解除冷却：上游明确回了一次正常响应，说明限流窗口已经过去，
	// 没有理由继续把它排除在选路之外。
	rs.cooldownUntil = time.Time{}
	if rep.TTFT > 0 {
		rs.lastTTFT = rep.TTFT
	}

	if rep.Source == SourceReal {
		rs.lastRealOKAt = now
	}

	switch {
	case rs.state == model.StateDead:
		// 死站首次探通 → unknown（乐观，立即可承接真实流量）。
		// 不直接跳 alive 是因为一次成功可能是偶然；但也绝不留在 dead ——
		// 那会让恢复的站空等第二次探活（§4.4）。
		rs.state = model.StateUnknown

	case rs.state == model.StateUnknown && rep.Source == SourceReal:
		// unknown 期间真实请求成功 → 直接 alive。真实请求比探活的
		// `1+1=?` 有力得多：它带着完整上下文和工具定义都通过了。
		rs.state = model.StateAlive

	case rs.consecutiveOK >= s.OKThreshold:
		rs.state = model.StateAlive
	}
}

func (t *Tracker) noteErr(rs *routeState, rep Report, now time.Time) {
	rs.lastErrAt = now
	rs.lastReason = rep.Verdict
	if rep.Err != nil {
		rs.lastError = rep.Err.Error()
	} else {
		rs.lastError = rep.Verdict.String()
	}
}

// currentSettings 读设置，读不出来就用默认值。
//
// 不返回 error：状态机在探活与转发的收尾路径上被调用，那里没有
// 「因为读不到配置所以不更新健康状态」的合理处理方式 —— 真正的后果是
// 一个死站永远不被判死。默认值虽不精确，但保证状态机继续运转。
func (t *Tracker) currentSettings() model.Settings {
	if t.settings != nil {
		if s, err := t.settings.Settings(); err == nil {
			return s
		}
	}
	return model.DefaultSettings()
}
