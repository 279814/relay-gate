package probe

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"
)

// costFlushInterval 是成本快照落库周期。
//
// 60 秒，比健康状态的 5 秒宽松得多：这个数据只用于「今天探了多少次」
// 这种回顾性判断，晚一分钟毫无影响。而 SQLite 只有一条连接，
// 与样本落库和健康快照共用 —— 没必要为一个粗粒度的计数器去挤它。
//
// 丢失至多一分钟的计数是可接受的：估算 token 本身就是量级判断（见
// estimateL2Tokens），少算几次不改变「策略是否过激」的结论。
const costFlushInterval = time.Minute

// CostStore 读写成本快照。由 store.Store 实现。
type CostStore interface {
	GetProbeCostRaw() (string, error)
	SaveProbeCostRaw(raw string) error
}

// CostPersister 定期把成本计数刷进库，让「今日」的语义跨重启成立。
type CostPersister struct {
	cost *Cost
	st   CostStore
	log  *slog.Logger
}

func NewCostPersister(cost *Cost, st CostStore, log *slog.Logger) *CostPersister {
	return &CostPersister{cost: cost, st: st, log: log}
}

// Restore 从库里恢复当日计数，供启动时调用一次。
//
// 失败只记日志：计数恢复不了就从零开始，那不该阻止服务启动 ——
// 一个观测功能没有资格让网关起不来。
func (p *CostPersister) Restore() {
	raw, err := p.st.GetProbeCostRaw()
	if err != nil {
		p.log.Error("读取探活成本快照失败，本次从零开始计数", "err", err)
		return
	}
	if raw == "" {
		return
	}
	var snap CostSnapshot
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		p.log.Error("探活成本快照不是合法 JSON，本次从零开始计数", "err", err)
		return
	}
	// 跨天时 Restore 自己会忽略（库里是昨天的数据，「今日」应从零开始）。
	p.cost.Restore(snap)
}

// Run 阻塞运行落库循环，直到 ctx 结束。退出前会再刷一次。
func (p *CostPersister) Run(ctx context.Context) {
	t := time.NewTicker(costFlushInterval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			// 关闭前再刷一次，否则最后一分钟的计数会丢 —— 而重启前的
			// 那段时间恰好常是在排查问题、手动点探活的时候。
			p.flush()
			return
		case <-t.C:
			p.flush()
		}
	}
}

func (p *CostPersister) flush() {
	snap := p.cost.Snapshot()
	b, err := json.Marshal(snap)
	if err != nil {
		p.log.Error("序列化探活成本快照失败", "err", err)
		return
	}
	if err := p.st.SaveProbeCostRaw(string(b)); err != nil {
		p.log.Error("探活成本快照落库失败", "err", err)
	}
}
