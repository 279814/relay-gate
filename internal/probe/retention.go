package probe

import (
	"context"
	"log/slog"
	"time"
)

// RetentionJanitor 小批清理 execution / calibration / cost 历史。
type RetentionJanitor struct {
	store RetentionStore
	log   *slog.Logger
	now   func() time.Time
}

// RetentionStore 是 Store 的窄清理面。
type RetentionStore interface {
	PruneProbeExecutions(ctx context.Context, nowUTC time.Time, limit int) (int, error)
	PruneProbeCostHistory(ctx context.Context, nowUTC time.Time, limit int) (int, error)
	PruneCalibrationHistory(ctx context.Context, nowUTC time.Time, limit int) (int, error)
}

// NewRetentionJanitor 构造 janitor。
func NewRetentionJanitor(store RetentionStore, log *slog.Logger) *RetentionJanitor {
	if log == nil {
		log = slog.Default()
	}
	return &RetentionJanitor{store: store, log: log, now: time.Now}
}

// Run 低优先级周期清理；失败只告警。
func (j *RetentionJanitor) Run(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	j.once(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			j.once(ctx)
		}
	}
}

func (j *RetentionJanitor) once(ctx context.Context) {
	if j == nil || j.store == nil {
		return
	}
	now := j.now().UTC()
	const batch = 500
	if n, err := j.store.PruneProbeExecutions(ctx, now, batch); err != nil {
		j.log.Warn("清理 probe execution 失败", "err", err)
	} else if n > 0 {
		j.log.Info("已清理 probe execution", "rows", n)
	}
	if n, err := j.store.PruneCalibrationHistory(ctx, now, batch); err != nil {
		j.log.Warn("清理 calibration 失败", "err", err)
	} else if n > 0 {
		j.log.Info("已清理 calibration", "rows", n)
	}
	if n, err := j.store.PruneProbeCostHistory(ctx, now, batch); err != nil {
		j.log.Warn("清理 probe cost 失败", "err", err)
	} else if n > 0 {
		j.log.Info("已清理 probe cost", "rows", n)
	}
}
