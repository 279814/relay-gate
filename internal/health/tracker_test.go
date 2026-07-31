package health

import (
	"sync"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

// acquire 是测试里的便捷包装：不关心上限，只要占位成功。
func acquire(t *testing.T, tr *Tracker, routeID int64) func() {
	t.Helper()
	release, ok := tr.TryAcquire(routeID, 0)
	if !ok {
		t.Fatalf("不限并发时 TryAcquire(%d) 不该失败", routeID)
	}
	return release
}

func TestTracker_InFlightCounting(t *testing.T) {
	tr := NewTracker()

	if tr.InFlight(100) != 0 {
		t.Error("初始在途应为 0")
	}
	done1 := acquire(t, tr, 100)
	done2 := acquire(t, tr, 100)
	if got := tr.InFlight(100); got != 2 {
		t.Errorf("两个在途请求应计为 2，得到 %d", got)
	}
	// 不同 Route 之间不能互相干扰
	if tr.InFlight(200) != 0 {
		t.Error("另一个 Route 的计数不该受影响")
	}

	done1()
	if got := tr.InFlight(100); got != 1 {
		t.Errorf("结束一个后应为 1，得到 %d", got)
	}
	done2()
	if got := tr.InFlight(100); got != 0 {
		t.Errorf("全部结束后应为 0，得到 %d", got)
	}
}

// done 重复调用不能把计数减穿 —— 否则一个 Route 的计数会变成负数，
// 之后再也触发不了并发上限。
func TestTracker_DoneIsIdempotent(t *testing.T) {
	tr := NewTracker()
	doneA := acquire(t, tr, 100)
	doneB := acquire(t, tr, 100)

	doneA()
	doneA()
	doneA()
	if got := tr.InFlight(100); got != 1 {
		t.Errorf("重复调用 done 不该多减，应为 1，得到 %d", got)
	}
	doneB()
	if got := tr.InFlight(100); got != 0 {
		t.Errorf("应为 0，得到 %d", got)
	}
}

// 计数归零后应从 map 里删键，避免删掉的 Route 永久堆积。
func TestTracker_ZeroCountsAreRemoved(t *testing.T) {
	tr := NewTracker()
	done := acquire(t, tr, 100)
	done()
	if len(tr.Snapshot()) != 0 {
		t.Errorf("归零后不该在 Snapshot 里，得到 %v", tr.Snapshot())
	}
}

// M2 阶段所有 Route 视为可用（乐观）。M3 接入探活后才有 alive/dead。
func TestTracker_OptimisticUntilProbing(t *testing.T) {
	tr := NewTracker()
	if tr.State(100) != model.StateUnknown {
		t.Error("M2 阶段应恒为 unknown（即视为可用）")
	}
	if tr.CoolingDown(100) {
		t.Error("M2 阶段不该有冷却")
	}
}

// 并发 Begin/done 必须精确配平。计数只增不减的话，配了 max_concurrency 的
// Route 会被永久排除在选路之外 —— 隐蔽且不会自愈。
func TestTracker_ConcurrentBeginDone(t *testing.T) {
	tr := NewTracker()
	const goroutines = 50
	const perRoute = 20

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		routeID := int64(i%3 + 1) // 3 个 Route 交错
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perRoute; j++ {
				done, ok := tr.TryAcquire(routeID, 0)
				if !ok {
					continue // 不限并发时不该发生，交给下面的配平断言暴露
				}
				done()
			}
		}()
	}
	wg.Wait()

	for id := int64(1); id <= 3; id++ {
		if got := tr.InFlight(id); got != 0 {
			t.Errorf("Route %d 的在途计数应回到 0，得到 %d", id, got)
		}
	}
	if n := len(tr.Snapshot()); n != 0 {
		t.Errorf("全部结束后 Snapshot 应为空，得到 %d 项", n)
	}
}

// limit 是硬上限：占满后必须拒绝，释放一个才腾出一格。
func TestTracker_TryAcquireEnforcesLimit(t *testing.T) {
	tr := NewTracker()

	r1, ok := tr.TryAcquire(100, 2)
	if !ok {
		t.Fatal("第 1 个应放行")
	}
	if _, ok = tr.TryAcquire(100, 2); !ok {
		t.Fatal("第 2 个应放行")
	}
	if _, ok = tr.TryAcquire(100, 2); ok {
		t.Fatal("第 3 个超过 limit=2，应被拒绝")
	}
	// 上限是 per-Route 的，别的 Route 不受影响
	if _, ok = tr.TryAcquire(200, 2); !ok {
		t.Error("另一个 Route 的额度不该被占用")
	}

	r1()
	if _, ok = tr.TryAcquire(100, 2); !ok {
		t.Error("释放一个后应腾出一格")
	}
}

// limit <= 0 表示不限。这是默认值，绝不能被当成「一个都不许」——
// 那会让所有没配上限的 Route 直接不可用。
func TestTracker_ZeroLimitMeansUnlimited(t *testing.T) {
	tr := NewTracker()
	for _, limit := range []int{0, -1} {
		tr = NewTracker()
		for i := 0; i < 100; i++ {
			if _, ok := tr.TryAcquire(100, limit); !ok {
				t.Fatalf("limit=%d 应视为不限，第 %d 个被拒", limit, i)
			}
		}
		if got := tr.InFlight(100); got != 100 {
			t.Errorf("limit=%d 时应全部放行并计数，得到 %d", limit, got)
		}
	}
}

// 并发压上限时不得超发。这是 max_concurrency 唯一真正要防的场景：
// 检查与占位若不在同一个临界区，一批同时到达的请求会全部通过检查。
func TestTracker_TryAcquireNoOversubscribeUnderRace(t *testing.T) {
	const limit = 4
	const burst = 200

	tr := NewTracker()
	var mu sync.Mutex
	var live, peak int

	var start sync.WaitGroup
	start.Add(1)
	var wg sync.WaitGroup
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start.Wait()

			release, ok := tr.TryAcquire(100, limit)
			if !ok {
				return
			}
			mu.Lock()
			live++
			if live > peak {
				peak = live
			}
			mu.Unlock()

			mu.Lock()
			live--
			mu.Unlock()
			release()
		}()
	}
	start.Done()
	wg.Wait()

	if peak > limit {
		t.Errorf("同时持有额度的峰值 %d 超过 limit=%d", peak, limit)
	}
	if got := tr.InFlight(100); got != 0 {
		t.Errorf("全部释放后应归零，得到 %d", got)
	}
}

// Snapshot 是副本，改它不能影响内部状态。
func TestTracker_SnapshotIsCopy(t *testing.T) {
	tr := NewTracker()
	defer acquire(t, tr, 100)()

	snap := tr.Snapshot()
	snap[100] = 999
	snap[200] = 1
	if tr.InFlight(100) != 1 {
		t.Error("修改 Snapshot 影响了内部状态")
	}
	if tr.InFlight(200) != 0 {
		t.Error("修改 Snapshot 影响了内部状态")
	}
}
