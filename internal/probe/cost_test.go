package probe

import (
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// atDay 造一个时钟固定在某天的 Cost。
func atDay(day string) (*Cost, func(string)) {
	c := NewCost()
	cur := mustParseDay(day)
	c.now = func() time.Time { return cur }
	return c, func(next string) { cur = mustParseDay(next) }
}

func mustParseDay(day string) time.Time {
	t, err := time.ParseInLocation("2006-01-02 15:04", day, time.Local)
	if err != nil {
		panic(err)
	}
	return t
}

func TestCost_CountsL1AndL2Separately(t *testing.T) {
	// L1 与 L2 记在不同的 key 空间：L1 是站级的（一次 L1 被同站多个 Route
	// 共享，scheduler.beginL1 会收敛），L2 是 Route 级的。混在一起会把
	// 一次 L1 请求算成 N 次。
	c, _ := atDay("2026-07-31 10:00")
	c.AddL1(1, true)
	c.AddL1(1, true)
	c.AddL2(10, true, 5)

	snap := c.Snapshot()
	if snap.L1Count != 2 {
		t.Errorf("L1Count = %d，期望 2", snap.L1Count)
	}
	if snap.L2Count != 1 {
		t.Errorf("L2Count = %d，期望 1", snap.L2Count)
	}
	// L1 不该在 Route 明细里留下任何东西。
	if len(snap.Routes) != 1 || snap.Routes[0].RouteID != 10 {
		t.Errorf("Route 明细应只有 route 10，得到 %+v", snap.Routes)
	}
	if len(snap.Upstreams) != 1 || snap.Upstreams[0].UpstreamID != 1 {
		t.Errorf("Upstream 明细应只有 upstream 1，得到 %+v", snap.Upstreams)
	}
}

func TestCost_TracksFailuresSeparately(t *testing.T) {
	// 失败的探活同样花钱（请求已经发出去了），而「失败占比高」是策略
	// 过激的直接信号：探一个死站 100 次全失败，那 100 次是纯浪费。
	c, _ := atDay("2026-07-31 10:00")
	c.AddL2(10, true, 5)
	c.AddL2(10, false, 5)
	c.AddL2(10, false, 5)
	c.AddL1(1, false)

	snap := c.Snapshot()
	if snap.L2Count != 3 || snap.L2Failed != 2 {
		t.Errorf("L2 应为 3 次 2 失败，得到 %d 次 %d 失败", snap.L2Count, snap.L2Failed)
	}
	if snap.L1Count != 1 || snap.L1Failed != 1 {
		t.Errorf("L1 应为 1 次 1 失败，得到 %d 次 %d 失败", snap.L1Count, snap.L1Failed)
	}
	// 估算 token 不区分成败：失败的请求也已经把 prompt 发出去了。
	if snap.EstTokens != 15 {
		t.Errorf("EstTokens = %d，期望 15（失败的也计入）", snap.EstTokens)
	}
}

func TestCost_RollsOverAtMidnight(t *testing.T) {
	// 「今日」必须真的是今日。跨天不清零的话，这个数字会一直涨，
	// 「今天探了 4300 次」就成了「自上次重启以来探了 4300 次」——
	// 两者对「策略是否过激」的判断完全不同。
	c, setDay := atDay("2026-07-31 23:59")
	c.AddL1(1, true)
	c.AddL2(10, true, 5)
	if snap := c.Snapshot(); snap.L1Count != 1 || snap.L2Count != 1 {
		t.Fatalf("跨天前应有计数，得到 %+v", snap)
	}

	setDay("2026-08-01 00:01")
	snap := c.Snapshot()
	if snap.Day != "2026-08-01" {
		t.Errorf("Day = %q，期望 2026-08-01", snap.Day)
	}
	if snap.L1Count != 0 || snap.L2Count != 0 || snap.EstTokens != 0 {
		t.Errorf("跨天后应归零，得到 %+v", snap)
	}
	if len(snap.Routes) != 0 || len(snap.Upstreams) != 0 {
		t.Errorf("跨天后明细应清空，得到 routes=%v ups=%v", snap.Routes, snap.Upstreams)
	}
}

func TestCost_RollsOverOnWrite(t *testing.T) {
	// 归零不能只发生在读的时候：如果只有 Snapshot 会 roll，
	// 那么跨天后第一次 AddL2 会把新一天的计数加到旧一天的桶里，
	// 而那个桶随后才被清空 —— 于是这次探活凭空消失了。
	c, setDay := atDay("2026-07-31 23:59")
	c.AddL2(10, true, 5)

	setDay("2026-08-01 00:01")
	c.AddL2(10, true, 7)

	snap := c.Snapshot()
	if snap.L2Count != 1 {
		t.Errorf("新一天应只有 1 次，得到 %d", snap.L2Count)
	}
	if snap.EstTokens != 7 {
		t.Errorf("EstTokens = %d，期望 7（只有新一天的那次）", snap.EstTokens)
	}
}

func TestCost_RestoreAcceptsSameDay(t *testing.T) {
	// 落库/恢复存在的唯一理由：让「今日」跨重启成立。
	c, _ := atDay("2026-07-31 10:00")
	c.Restore(CostSnapshot{
		Day:       "2026-07-31",
		Routes:    []RouteCost{{RouteID: 10, L2Count: 3, EstTokens: 30, L2Failed: 1}},
		Upstreams: []UpstreamCost{{UpstreamID: 1, L1Count: 7, L1Failed: 2}},
	})

	snap := c.Snapshot()
	if snap.L2Count != 3 || snap.EstTokens != 30 || snap.L2Failed != 1 {
		t.Errorf("恢复后的 L2 数据不对：%+v", snap)
	}
	if snap.L1Count != 7 || snap.L1Failed != 2 {
		t.Errorf("恢复后的 L1 数据不对：%+v", snap)
	}

	// 恢复之后继续累加，应该接着算而不是从头。
	c.AddL2(10, true, 5)
	if snap := c.Snapshot(); snap.L2Count != 4 || snap.EstTokens != 35 {
		t.Errorf("恢复后继续累加不对：%+v", snap)
	}
}

func TestCost_RestoreRejectsStaleDay(t *testing.T) {
	// 库里存的是昨天的数据时，「今日」必须从零开始。
	// 不判日期的话，重启一次就把昨天的账算到今天头上。
	c, _ := atDay("2026-08-01 09:00")
	c.Restore(CostSnapshot{
		Day:       "2026-07-31",
		Routes:    []RouteCost{{RouteID: 10, L2Count: 999, EstTokens: 9990}},
		Upstreams: []UpstreamCost{{UpstreamID: 1, L1Count: 999}},
	})

	snap := c.Snapshot()
	if snap.L2Count != 0 || snap.L1Count != 0 || snap.EstTokens != 0 {
		t.Errorf("昨天的快照不该被恢复，得到 %+v", snap)
	}
}

func TestCost_SnapshotIsSorted(t *testing.T) {
	// 稳定输出：UI 上的行不该每次刷新都换位置，测试也需要确定的顺序。
	c, _ := atDay("2026-07-31 10:00")
	for _, id := range []int64{30, 10, 20} {
		c.AddL2(id, true, 1)
		c.AddL1(id, true)
	}
	snap := c.Snapshot()
	for i := 1; i < len(snap.Routes); i++ {
		if snap.Routes[i-1].RouteID > snap.Routes[i].RouteID {
			t.Errorf("Route 明细未按 ID 升序：%+v", snap.Routes)
			break
		}
	}
	for i := 1; i < len(snap.Upstreams); i++ {
		if snap.Upstreams[i-1].UpstreamID > snap.Upstreams[i].UpstreamID {
			t.Errorf("Upstream 明细未按 ID 升序：%+v", snap.Upstreams)
			break
		}
	}
}

func TestCost_SnapshotIsACopy(t *testing.T) {
	// Snapshot 返回的切片被改动不该影响内部状态 —— 它会被交给
	// JSON 序列化与 UI，任何一处误改都会污染计数。
	c, _ := atDay("2026-07-31 10:00")
	c.AddL2(10, true, 5)

	snap := c.Snapshot()
	snap.Routes[0].L2Count = 999

	if again := c.Snapshot(); again.L2Count != 1 {
		t.Errorf("外部改动污染了内部状态：L2Count = %d", again.L2Count)
	}
}

func TestEstimateL2Tokens_ScalesWithMaxTokens(t *testing.T) {
	// max_tokens 是输出上界，探活的开销主要由它决定 ——
	// 这正是「策略是否过激」要看的东西。
	small := estimateL2Tokens(&model.ModelName{ProbePrompt: "1+1=?", ProbeMaxTokens: 1})
	big := estimateL2Tokens(&model.ModelName{ProbePrompt: "1+1=?", ProbeMaxTokens: 100})
	if big <= small {
		t.Errorf("max_tokens 大的估算应更大：small=%d big=%d", small, big)
	}
	if big-small != 99 {
		t.Errorf("差值应等于 max_tokens 之差，得到 %d", big-small)
	}
}

func TestEstimateL2Tokens_UsesDefaultsForZeroValues(t *testing.T) {
	// 与 buildProbeBody 的兜底保持一致：prompt 空用 "1+1=?"，
	// max_tokens 为 0 用 1。两处不一致的话，估算的是一个
	// 根本没发出去的请求。
	got := estimateL2Tokens(&model.ModelName{})
	want := estimateL2Tokens(&model.ModelName{ProbePrompt: "1+1=?", ProbeMaxTokens: 1})
	if got != want {
		t.Errorf("零值应回落到与显式默认值相同的估算：%d vs %d", got, want)
	}
}

func TestEstimateL2Tokens_CountsRunesNotBytes(t *testing.T) {
	// 按字节算的话，中文 prompt 会被高估三倍（UTF-8 一个汉字 3 字节）。
	// 探活 prompt 用中文并不罕见。
	cn := estimateL2Tokens(&model.ModelName{ProbePrompt: "你好吗", ProbeMaxTokens: 1})
	en := estimateL2Tokens(&model.ModelName{ProbePrompt: "abc", ProbeMaxTokens: 1})
	if cn != en {
		t.Errorf("三个汉字与三个字母的估算应相同（都按 rune 数），得到 %d vs %d", cn, en)
	}
}

func TestCost_ConcurrentWritesDoNotRace(t *testing.T) {
	// 调度器会并发跑多个探活（全局 L2 闸默认 3），记账必须是并发安全的。
	// 这条测试在 -race 下才有全部价值，但即使不带 -race 也能抓到
	// map 并发写导致的 panic。
	c, _ := atDay("2026-07-31 10:00")
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(n int64) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 50; j++ {
				c.AddL1(n, j%2 == 0)
				c.AddL2(n, j%3 == 0, 4)
				c.Snapshot()
			}
		}(int64(i))
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if snap := c.Snapshot(); snap.L1Count != 400 || snap.L2Count != 400 {
		t.Errorf("并发累加丢数：L1=%d L2=%d，各期望 400", snap.L1Count, snap.L2Count)
	}
}
