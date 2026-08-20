package probe

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/store"
)

// 确定性复现 TestScheduler_CoalescesL1PerUpstream 的竞态（Issue #21）。
//
// 机制：tick 串行遍历同一站下的 N 条 Route，`beginL1` 在第 1 条上标记
// `inflightL1`。但 `endL1` 是 goroutine 的 `defer`，在 L1 **执行完**就清除。
// 若第一个 L1 goroutine 在 tick 遍历到下一条 Route 之前完成并 endL1，
// 后面的 Route 会再抢到一次 beginL1 —— 同一个站在同一个 tick 里被打多次。
//
// 原 flaky 只能靠 -race + mock 快慢碰运气。这里把竞态条件**显式化**：
// 每次 maybeProbe 后立即 wg.Wait()，精确模拟「第一个 L1 在下一条 Route
// 处理前已完成」。任何一次运行都必然触发，不依赖调度时序。
//
// 修复前（只靠 inflightL1，L1 完成即清除）：5 次 maybeProbe 全部拿到
// beginL1，transport 被调用 5 次。修复后（beginL1 加 l1Scheduled 闸，
// 收敛窗口 = 整个 tick）：只有第一次 maybeProbe 拿到，transport 调用 1 次。
func TestScheduler_CoalescesL1PerUpstream_RaceDeterministic(t *testing.T) {
	mn := &model.ModelName{ID: 1, Name: "claude-opus-5",
		Protocol: model.ProtoAnthropic, MatchMode: model.MatchExact, Enabled: true}
	mn.Defaults()

	up := &model.Upstream{ID: 10, Name: "shared", BaseURL: "http://127.0.0.1:1",
		APIKey: "sk-probe-key-abcdefgh", AuthStyle: model.AuthAuto,
		L1Path: "/v1/models", Enabled: true}

	routes := make([]*model.Route, 5)
	for i := range routes {
		routes[i] = &model.Route{
			ID: int64(100 + i), ModelNameID: 1, UpstreamID: 10,
			Priority: 1, Weight: 100, Enabled: true,
		}
	}

	track := newRecordingTracker()
	// 挡住 L2：本测试只关心 L1 收敛，L2 会让计数 transport 多计几次。
	track.l2Allowed = map[int64]bool{}
	gate := health.NewUpstreamGate()

	ct := &countingErrTransport{}
	sched := NewScheduler(&fakeCfg{state: store.StateRunning}, ct, track, gate, discardLogger()).WithTargets(testTargets(), nil)

	// 模拟一个 tick 内串行处理 5 条 Route，且每次 after-probe 都等到
	// goroutine 跑完 —— 正是「第一个 L1 在 tick 遍历完成前结束」的竞态。
	for _, rt := range routes {
		sched.maybeProbe(context.Background(), up, mn, rt, model.Settings{})
		sched.wg.Wait()
	}

	if n := ct.calls(); n != 1 {
		t.Errorf("同一站打了 %d 次 L1，期望 1 次（收敛窗口短于 tick 竞态未修）", n)
	}
}

// countingErrTransport 计数 TransportFor 调用，并立即返回错误。
//
// 返回错误让 runL1 立刻结束 —— goroutine 无需真实 HTTP 就能完成，
// 于是 endL1 会立即清除 inflightL1，竞态被确定性地触发。
type countingErrTransport struct {
	mu sync.Mutex
	n  int
}

func (c *countingErrTransport) TransportFor(*model.Upstream, outbound.Budget) (*outbound.Transport, error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return nil, errors.New("repro: 阻止真实 HTTP")
}

func (c *countingErrTransport) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}
