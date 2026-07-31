// Package health 维护 Route 的运行时健康状态。
//
// 状态以内存为准（§2.4）：重启后一律回到 unknown，不从库里恢复。
// route_health 表只是给 UI 看的历史快照。
package health

import (
	"sync"

	"github.com/279814/relay-gate/internal/model"
)

// Tracker 是 router.HealthView 的生产实现。
//
// M2 只做在途计数 —— 选路的并发上限（§3.4 步骤 7）依赖它，缺了它
// max_concurrency 就是个配了不生效的空档。判死状态机、429 冷却、
// 半开放行在 M3 补上，届时长在同一个 Tracker 上：它们与在途计数
// 读写同一份 per-Route 状态，拆成两个类型只会引入锁的协调问题。
type Tracker struct {
	mu       sync.RWMutex
	inFlight map[int64]int
}

func NewTracker() *Tracker {
	return &Tracker{inFlight: map[int64]int{}}
}

// State 目前恒为 unknown，即**视为可用**（乐观，§2.4）。
//
// M3 接入探活后这里才会返回 alive/dead。在那之前所有 Route 都参与选路，
// 行为等价于「按优先级顺序试」—— 不比现有方案差，只是还没有主动探活的增益。
func (t *Tracker) State(int64) model.HealthState { return model.StateUnknown }

// CoolingDown 目前恒为 false。429 冷却在 M3 随状态机一起接入。
func (t *Tracker) CoolingDown(int64) bool { return false }

// InFlight 返回当前在途计数，供管理界面与日志展示。
//
// **不要**用它做并发上限判定：读完再决定要不要占用，两步之间有窗口。
// 判定走 TryAcquire。
func (t *Tracker) InFlight(routeID int64) int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.inFlight[routeID]
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
	if limit > 0 && t.inFlight[routeID] >= limit {
		t.mu.Unlock()
		return nil, false
	}
	t.inFlight[routeID]++
	t.mu.Unlock()

	// 返回闭包而不是配对的 Acquire/Release：调用方 defer 一下就不可能
	// 记错 routeID，也不可能重复释放（once 兜住）。
	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			defer t.mu.Unlock()
			if n := t.inFlight[routeID]; n > 1 {
				t.inFlight[routeID] = n - 1
			} else {
				// 减到 0 就删键，避免删掉的 Route 在 map 里堆积
				delete(t.inFlight, routeID)
			}
		})
	}, true
}

// Snapshot 返回所有非零在途计数的副本，供管理界面展示。
func (t *Tracker) Snapshot() map[int64]int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[int64]int, len(t.inFlight))
	for k, v := range t.inFlight {
		out[k] = v
	}
	return out
}
