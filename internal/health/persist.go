package health

import (
	"context"
	"log/slog"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

// flushInterval 是健康快照落库周期。
//
// 5 秒是「UI 够新」与「不磨磁盘」的折中。不做「每次状态变化就写」：
// 一个反复抖动的站每分钟能变十几次状态，而 SQLite 只有一条连接
// （store.Open 里 MaxOpenConns(1)），那些写入会与样本落库争这条连接 ——
// 而样本落库本身就已经在与选路的配置读取排队了。
//
// 落库延迟对正确性无影响：状态以内存为准（§2.4），选路读的是内存，
// 这张表只给 UI 看。
const flushInterval = 5 * time.Second

// SnapshotSource 提供当前的健康快照。由 Tracker 实现。
type SnapshotSource interface {
	AllStatus() []Status
}

// HealthWriter 落库健康快照。由 store.Store 实现。
type HealthWriter interface {
	SaveRouteHealth(list []*store.RouteHealth) error
}

// Persister 定期把内存里的健康状态刷进 route_health 表。
//
// 只写已捕获的状态与身份。启动恢复由独立的 current 校验完成，不能在
// flush 时给旧状态盖上新配置的身份。
type Persister struct {
	src SnapshotSource
	w   HealthWriter
	log *slog.Logger
}

func NewPersister(src SnapshotSource, w HealthWriter, log *slog.Logger) *Persister {
	return &Persister{src: src, w: w, log: log}
}

// Run 阻塞运行落库循环，直到 ctx 结束。退出前会再刷一次。
func (p *Persister) Run(ctx context.Context) {
	t := time.NewTicker(flushInterval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			// 关闭前再刷一次：崩溃/重启前那一刻的状态往往正是要查的现场。
			p.flush()
			return
		case <-t.C:
			p.flush()
		}
	}
}

func (p *Persister) flush() {
	all := p.src.AllStatus()
	if len(all) == 0 {
		return
	}

	rows := make([]*store.RouteHealth, 0, len(all))
	for _, st := range all {
		// Legacy recovery adds no new evidence to the already-durable row.
		// Rewriting it could revive a snapshot cleared by a later semantic
		// configuration transaction while this flush was waiting for SQLite.
		if st.Identity == nil && st.RecoverySource == "legacy_unverified" {
			continue
		}
		rows = append(rows, &store.RouteHealth{
			RouteID:         st.RouteID,
			State:           st.State,
			ConsecutiveOK:   st.ConsecutiveOK,
			ConsecutiveFail: st.ConsecutiveFail,
			LastOKAt:        st.LastOKAt,
			LastErrAt:       st.LastErrAt,
			LastError:       st.LastError,
			LastTTFTMS:      st.LastTTFTMS,
			CooldownUntil:   st.CooldownUntil, DeadSince: st.DeadSince,
			RecoveryRequired: st.State == model.StateDead || st.State == model.StateRecovering,
			Identity:         st.Identity,
		})
	}

	if err := p.w.SaveRouteHealth(rows); err != nil {
		// 只记日志。落库失败不影响选路（状态在内存里），
		// 而为此重试会让一条本就繁忙的 SQLite 连接更堵。
		p.log.Error("健康状态落库失败", "err", err, "routes", len(rows))
	}
}
