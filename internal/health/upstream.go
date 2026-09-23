package health

import (
	"sync"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// UpstreamGate 记录 L1 的站级结论（§4.1），P0-10 起是 ReachabilityTracker 的兼容 facade。
//
// 单独放一个类型而不是塞进 Tracker：L1 的粒度是 Upstream，Route Tracker 的粒度是
// Route，两者的 key 空间不同。混在一个 map 里就要靠命名约定区分「这个 ID
// 是站还是路由」—— 那种约定迟早会被记错，而记错的表现是把某个 Route 的
// 状态当成站的状态来传播，一次误判连坐整站。
//
// 生产路径由 ResultRecorder.ApplyCommitted 写入 ReachabilityTracker；Report
// 仍更新 legacy 视图，以便未接 Commit 的单元测试（旧 Prober 路径）保持原语义。
// Report 绑定 generation：Forget 后同 id 新站不得被迟到的 L1 写回。
type UpstreamGate struct {
	tracker *ReachabilityTracker

	mu      sync.Mutex
	ups     map[int64]*upstreamState
	nextGen uint64
	now     func() time.Time
}

type upstreamState struct {
	// generation 在本条目创建时分配，Forget 后同 id 新条目不会复用该值。
	generation uint64
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

// WithTracker 把 Gate 接到 ReachabilityTracker。生产装配必须调用。
func (g *UpstreamGate) WithTracker(tracker *ReachabilityTracker) *UpstreamGate {
	g.tracker = tracker
	return g
}

// Tracker 返回底层 ReachabilityTracker（可能为 nil）。
func (g *UpstreamGate) Tracker() *ReachabilityTracker { return g.tracker }

// EnsureGeneration 取或建 upstreamID 的 legacy 条目并返回其世代。
//
// 探活开始时绑定，结束时原样带进 Report：Forget 后同 id 新站世代不同，
// 迟到结论必须丢弃。
func (g *UpstreamGate) EnsureGeneration(upstreamID int64) uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.getLocked(upstreamID).generation
}

func (g *UpstreamGate) getLocked(upstreamID int64) *upstreamState {
	st := g.ups[upstreamID]
	if st == nil {
		g.nextGen++
		st = &upstreamState{ok: true, generation: g.nextGen}
		g.ups[upstreamID] = st
	}
	return st
}

// Report 记录一次 L1 结论，返回该站是否**从失败转为成功**。
//
// 返回 recovered 是 §4.4b 的触发点：L1 一旦转通，立即对该 Upstream 下
// 所有 dead 的 Route 触发一轮 L2，不等 L2 自己的周期。站级恢复的发现延迟
// 因此收敛到 L1 周期（20 秒），而不是 L2 周期。
//
// generation > 0 时必须与当前条目一致；Forget 后或同 id 新站不匹配则丢弃
// （且不得经 get 重建行）。generation == 0 表示未绑定世代的调用（测试），
// 仍按 id 取或建。
func (g *UpstreamGate) Report(upstreamID int64, generation uint64, ok bool, err error) (recovered bool) {
	g.mu.Lock()
	defer g.mu.Unlock()

	var st *upstreamState
	if generation > 0 {
		st = g.ups[upstreamID]
		if st == nil || st.generation != generation {
			return false
		}
	} else {
		st = g.getLocked(upstreamID)
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
//
// 没有当前 network revision 时，不能拿内存行里记下的 revision 自己比自己：
// 那样网络配置变了也永远判「仍是当前结论」。调度热路径用 OKAt。
// 这里在接了 Tracker 且没有外部 revision 时，只在行内 revision 与
// settings 指纹仍自洽时采信；调用方拿得到快照 revision 时必须走 OKAt。
func (g *UpstreamGate) OK(upstreamID int64) bool {
	if g.tracker != nil {
		row := g.tracker.Snapshot(upstreamID)
		if row == nil {
			return true
		}
		return g.tracker.OK(upstreamID, row.ObservedNetworkRevision)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if st := g.ups[upstreamID]; st != nil {
		return st.ok
	}
	return true
}

// OKAt 用调用方提供的当前 networkRevision 做读侧失效。
func (g *UpstreamGate) OKAt(upstreamID, networkRevision int64) bool {
	if g.tracker != nil {
		return g.tracker.OK(upstreamID, networkRevision)
	}
	return g.OK(upstreamID)
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
	if g.tracker != nil {
		if row := g.tracker.Snapshot(upstreamID); row != nil {
			return statusFromRow(upstreamID, row, g.tracker.Effective(upstreamID, row.ObservedNetworkRevision))
		}
		// Tracker 已接但无行：不得回落 legacy Report（Forget 后迟到
		// Report 可能仍写在 ups 里），一律乐观「未探过」。
		return UpstreamStatus{UpstreamID: upstreamID, OK: true}
	}
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

// StatusAt 用调用方的当前 network revision 做读侧失效。
//
// revision 对不上时按「还没探过」返回：界面上的旧 unreachable 不能在
// 地址或代理已经改过之后继续显示成现在的结论。
func (g *UpstreamGate) StatusAt(upstreamID, networkRevision int64) UpstreamStatus {
	if g.tracker != nil {
		if row := g.tracker.Snapshot(upstreamID); row != nil {
			if row.ObservedNetworkRevision != networkRevision {
				return UpstreamStatus{UpstreamID: upstreamID, OK: true}
			}
			return statusFromRow(upstreamID, row, g.tracker.Effective(upstreamID, networkRevision))
		}
		return UpstreamStatus{UpstreamID: upstreamID, OK: true}
	}
	return g.Status(upstreamID)
}

func statusFromRow(upstreamID int64, row *model.UpstreamReachability, state model.ReachabilityState) UpstreamStatus {
	return UpstreamStatus{
		UpstreamID: upstreamID,
		OK:         state != model.ReachabilityUnreachable,
		Probed:     state != model.ReachabilityUnknown,
		LastError:  row.LastError,
		LastAt:     maxInt64(row.LastOKAt, row.LastErrorAt),
	}
}

// RetainOnly 只保留 keep 里的 Upstream，其余丢弃（配置删站后清理）。
func (g *UpstreamGate) RetainOnly(keep map[int64]bool) {
	if g.tracker != nil {
		g.tracker.RetainOnly(keep)
	}
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
	if g.tracker != nil {
		g.tracker.Invalidate(upstreamID)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.ups, upstreamID)
}

// Reset 清空全部站级状态（§4.8 从暂停恢复时用）。
func (g *UpstreamGate) Reset() {
	if g.tracker != nil {
		g.tracker.InvalidateAll()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ups = map[int64]*upstreamState{}
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
