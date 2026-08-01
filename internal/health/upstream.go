package health

import (
	"sync"
	"time"
)

// UpstreamGate 记录 L1 的站级结论（§4.1）。
//
// 单独放一个类型而不是塞进 Tracker：L1 的粒度是 Upstream，Tracker 的粒度是
// Route，两者的 key 空间不同。混在一个 map 里就要靠命名约定区分「这个 ID
// 是站还是路由」—— 那种约定迟早会被记错，而记错的表现是把某个 Route 的
// 状态当成站的状态来传播，一次误判连坐整站。
//
// 它仍在 health 包内，与 Tracker 共享包内可见性：调度器要同时读两者，
// 分到两个包就得把内部状态导出成公开 API。
type UpstreamGate struct {
	mu  sync.Mutex
	ups map[int64]*upstreamState
	now func() time.Time
}

type upstreamState struct {
	// ok 是最近一次 L1 的结论。初始 true（乐观）：没探过的站不该被当成挂了，
	// 否则重启后所有站在首轮 L1 跑完前都不可用。
	ok        bool
	probed    bool
	lastError string
	lastAt    time.Time
}

func NewUpstreamGate() *UpstreamGate {
	return &UpstreamGate{ups: map[int64]*upstreamState{}, now: time.Now}
}

// Report 记录一次 L1 结论，返回该站是否**从失败转为成功**。
//
// 返回 recovered 是 §4.4b 的触发点：L1 一旦转通，立即对该 Upstream 下
// 所有 dead 的 Route 触发一轮 L2，不等 L2 自己的周期。站级恢复的发现延迟
// 因此收敛到 L1 周期（20 秒），而不是 L2 周期。
func (g *UpstreamGate) Report(upstreamID int64, ok bool, err error) (recovered bool) {
	g.mu.Lock()
	defer g.mu.Unlock()

	st := g.ups[upstreamID]
	if st == nil {
		st = &upstreamState{ok: true}
		g.ups[upstreamID] = st
	}

	// 只有「探过且失败」之后的成功才算恢复。没探过的站初始是 ok，
	// 首次探活成功不该被当成「恢复」而去触发一轮全量 L2 —— 那会让
	// 每次重启都对所有站打一轮探活，正好撞上启动时最忙的时刻。
	recovered = ok && st.probed && !st.ok

	st.ok = ok
	st.probed = true
	st.lastAt = g.now()
	if err != nil {
		st.lastError = err.Error()
	} else {
		st.lastError = ""
	}
	return recovered
}

// OK 返回该站最近一次 L1 的结论。没探过的站返回 true（乐观）。
func (g *UpstreamGate) OK(upstreamID int64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if st := g.ups[upstreamID]; st != nil {
		return st.ok
	}
	return true
}

// UpstreamStatus 是站级 L1 状态的对外快照。
type UpstreamStatus struct {
	UpstreamID int64  `json:"upstream_id"`
	OK         bool   `json:"ok"`
	Probed     bool   `json:"probed"`
	LastError  string `json:"last_error"`
	LastAt     int64  `json:"last_at"`
}

func (g *UpstreamGate) Status(upstreamID int64) UpstreamStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.ups[upstreamID]
	if st == nil {
		return UpstreamStatus{UpstreamID: upstreamID, OK: true}
	}
	return UpstreamStatus{
		UpstreamID: upstreamID,
		OK:         st.ok,
		Probed:     st.probed,
		LastError:  st.lastError,
		LastAt:     msOrZero(st.lastAt),
	}
}

// RetainOnly 只保留 keep 里的 Upstream，其余丢弃（配置删站后清理）。
func (g *UpstreamGate) RetainOnly(keep map[int64]bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for id := range g.ups {
		if !keep[id] {
			delete(g.ups, id)
		}
	}
}

// Forget 丢弃某个站的 L1 结论，让它回到「没探过」（乐观视为 OK）。
//
// 用于配置变更（§4.5）：改了 key 或 base_url 之后，旧的「这个站 401」
// 必须作废。不作废的话 L2 会被 OK() 一直挡住（§4.1 的「站连不上就别探模型」），
// 于是用户明明改对了 key，界面上却看不到恢复 —— 而这正是最需要立刻
// 看到结果的时刻。
//
// 与 RetainOnly 的区别：那个按「配置里还剩谁」批量清理，是垃圾回收；
// 这个是针对单个站的定点作废。
func (g *UpstreamGate) Forget(upstreamID int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.ups, upstreamID)
}

// Reset 清空全部站级状态（§4.8 从暂停恢复时用）。
func (g *UpstreamGate) Reset() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ups = map[int64]*upstreamState{}
}
