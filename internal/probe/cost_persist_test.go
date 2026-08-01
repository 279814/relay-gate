package probe

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// fakeCostStore 是内存版 CostStore。
type fakeCostStore struct {
	mu   sync.Mutex
	raw  string
	err  error
	errW error
}

func (f *fakeCostStore) GetProbeCostRaw() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.raw, f.err
}

func (f *fakeCostStore) SaveProbeCostRaw(raw string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errW != nil {
		return f.errW
	}
	f.raw = raw
	return nil
}

func (f *fakeCostStore) saved() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.raw
}

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestCostPersister_RoundTripPreservesCounts(t *testing.T) {
	// 这是落库存在的全部理由：让「今日」跨重启成立。
	// 往返一圈后数字必须一模一样，否则重启就等于篡改账目。
	st := &fakeCostStore{}
	c, _ := atDay("2026-07-31 10:00")
	c.AddL1(1, true)
	c.AddL1(1, false)
	c.AddL2(10, true, 12)
	c.AddL2(11, false, 8)

	NewCostPersister(c, st, discardLog()).flush()
	if st.saved() == "" {
		t.Fatal("flush 之后库里应有数据")
	}

	// 模拟重启：新的 Cost（时钟仍在同一天），从库里恢复。
	fresh, _ := atDay("2026-07-31 18:00")
	NewCostPersister(fresh, st, discardLog()).Restore()

	before, after := c.Snapshot(), fresh.Snapshot()
	if before.L1Count != after.L1Count || before.L1Failed != after.L1Failed {
		t.Errorf("L1 往返不一致：%+v vs %+v", before, after)
	}
	if before.L2Count != after.L2Count || before.L2Failed != after.L2Failed {
		t.Errorf("L2 往返不一致：%+v vs %+v", before, after)
	}
	if before.EstTokens != after.EstTokens {
		t.Errorf("EstTokens 往返不一致：%d vs %d", before.EstTokens, after.EstTokens)
	}
	if len(after.Routes) != 2 || len(after.Upstreams) != 1 {
		t.Errorf("明细数量不对：routes=%d ups=%d", len(after.Routes), len(after.Upstreams))
	}
}

func TestCostPersister_RestoreIgnoresYesterday(t *testing.T) {
	// 隔天重启：库里是昨天的账，今天必须从零开始。
	st := &fakeCostStore{}
	yesterday, _ := atDay("2026-07-31 23:00")
	yesterday.AddL2(10, true, 100)
	NewCostPersister(yesterday, st, discardLog()).flush()

	today, _ := atDay("2026-08-01 08:00")
	NewCostPersister(today, st, discardLog()).Restore()

	if snap := today.Snapshot(); snap.L2Count != 0 || snap.EstTokens != 0 {
		t.Errorf("昨天的账不该算到今天：%+v", snap)
	}
}

func TestCostPersister_RestoreToleratesGarbage(t *testing.T) {
	// 库里的值坏了（手改、版本降级）时从零开始，而不是让服务起不来。
	// 一个观测功能没有资格阻止网关启动。
	st := &fakeCostStore{raw: "{not json"}
	c, _ := atDay("2026-07-31 10:00")
	NewCostPersister(c, st, discardLog()).Restore() // 不应 panic

	if snap := c.Snapshot(); snap.L2Count != 0 {
		t.Errorf("坏数据不该被恢复：%+v", snap)
	}
	// 恢复失败之后仍然要能正常计数。
	c.AddL2(10, true, 5)
	if snap := c.Snapshot(); snap.L2Count != 1 {
		t.Errorf("恢复失败后计数应照常工作，得到 %+v", snap)
	}
}

func TestCostPersister_RestoreToleratesReadError(t *testing.T) {
	st := &fakeCostStore{err: context.DeadlineExceeded}
	c, _ := atDay("2026-07-31 10:00")
	NewCostPersister(c, st, discardLog()).Restore() // 不应 panic
	c.AddL1(1, true)
	if snap := c.Snapshot(); snap.L1Count != 1 {
		t.Errorf("读库失败后计数应照常工作，得到 %+v", snap)
	}
}

func TestCostPersister_FlushToleratesWriteError(t *testing.T) {
	// 落库失败只记日志：计数在内存里，写不进去不影响任何判断。
	st := &fakeCostStore{errW: context.DeadlineExceeded}
	c, _ := atDay("2026-07-31 10:00")
	c.AddL2(10, true, 5)
	NewCostPersister(c, st, discardLog()).flush() // 不应 panic

	if snap := c.Snapshot(); snap.L2Count != 1 {
		t.Errorf("落库失败不该影响内存计数，得到 %+v", snap)
	}
}

func TestCostPersister_FlushesOnShutdown(t *testing.T) {
	// 关闭前必须再刷一次，否则最后一个周期的计数会丢 ——
	// 而重启前那段时间恰好常是在排查问题、手动点探活的时候。
	st := &fakeCostStore{}
	c, _ := atDay("2026-07-31 10:00")
	c.AddL2(10, true, 42)

	p := NewCostPersister(c, st, discardLog())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); p.Run(ctx) }()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run 没有在 ctx 取消后退出")
	}

	if st.saved() == "" {
		t.Fatal("关闭时应刷一次，但库里是空的")
	}
	var snap CostSnapshot
	if err := json.Unmarshal([]byte(st.saved()), &snap); err != nil {
		t.Fatal(err)
	}
	if snap.EstTokens != 42 {
		t.Errorf("关闭时刷的数据不对：EstTokens = %d，期望 42", snap.EstTokens)
	}
}
