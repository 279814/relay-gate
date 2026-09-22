package probe

// P0-12 成本权威：保留窗内 probe_cost_daily；piggyback 经独立 event kind 幂等落库。
// 旧内存 Cost 仍作快速快照；Restore 优先从 daily rollup 加载。

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

const costFlushInterval = time.Minute

// CostStore 读写成本快照与 daily rollup。
type CostStore interface {
	GetProbeCostRaw() (string, error)
	SaveProbeCostRaw(raw string) error
}

// CostDailyStore 是可选的 daily rollup 面；Store 实现它。
type CostDailyStore interface {
	ListProbeCostDaily(ctx context.Context, filter model.ProbeCostFilter) (model.Page[*model.ProbeCostDaily], error)
	RecordProbePiggybackSaving(ctx context.Context, eventID string, value model.ProbeCostDaily) error
}

// CostPersister 定期把成本计数刷进库，并支持从 daily 恢复。
type CostPersister struct {
	cost *Cost
	st   CostStore
	log  *slog.Logger
}

func NewCostPersister(cost *Cost, st CostStore, log *slog.Logger) *CostPersister {
	return &CostPersister{cost: cost, st: st, log: log}
}

// Restore 从库恢复。优先 daily rollup（730 日权威），再回落旧 JSON 快照。
func (p *CostPersister) Restore() {
	if daily, ok := p.st.(CostDailyStore); ok {
		if p.restoreFromDaily(daily) {
			return
		}
	}
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
	p.cost.Restore(snap)
}

func (p *CostPersister) restoreFromDaily(daily CostDailyStore) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	today := time.Now().UTC().Format("2006-01-02")
	page, err := daily.ListProbeCostDaily(ctx, model.ProbeCostFilter{
		DayFrom: today, DayTo: today,
		PageRequest: model.PageRequest{Limit: 500},
	})
	if err != nil || len(page.Items) == 0 {
		return false
	}
	snap := CostSnapshot{Day: today}
	for _, item := range page.Items {
		if item == nil {
			continue
		}
		// 只把 synthetic trigger 计入探活成本；real_traffic 永不进入此表。
		snap.L1Count += item.Requests // 粗聚合；明细仍以 daily 为准
		snap.EstTokens += item.EstimatedInputTokens + item.ObservedOutputTokens
	}
	p.cost.Restore(snap)
	p.log.Info("已从 probe_cost_daily 恢复当日成本快照", "rows", len(page.Items))
	return true
}

// RecordPiggybackSkip 幂等记录一次 L2 piggyback 节省。
func (p *CostPersister) RecordPiggybackSkip(ctx context.Context, eventID string, value model.ProbeCostDaily) error {
	daily, ok := p.st.(CostDailyStore)
	if !ok {
		return fmt.Errorf("CostStore 不支持 RecordProbePiggybackSaving")
	}
	return daily.RecordProbePiggybackSaving(ctx, eventID, value)
}

// StablePiggybackEventID 为一次 skip 生成稳定 event ID（同日同维度幂等）。
func StablePiggybackEventID(dayUTC string, endpoint model.EndpointKind, routeID, upstreamID int64, token string) string {
	return fmt.Sprintf("piggyback_l2:%s:%s:%d:%d:%s", dayUTC, endpoint, routeID, upstreamID, token)
}

func (p *CostPersister) Run(ctx context.Context) {
	t := time.NewTicker(costFlushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
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
