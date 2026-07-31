package health

import (
	"sync"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestTracker_InFlightCounting(t *testing.T) {
	tr := NewTracker()

	if tr.InFlight(100) != 0 {
		t.Error("初始在途应为 0")
	}
	done1 := tr.Begin(100)
	done2 := tr.Begin(100)
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
	doneA := tr.Begin(100)
	doneB := tr.Begin(100)

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
	done := tr.Begin(100)
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
				done := tr.Begin(routeID)
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

// Snapshot 是副本，改它不能影响内部状态。
func TestTracker_SnapshotIsCopy(t *testing.T) {
	tr := NewTracker()
	defer tr.Begin(100)()

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
