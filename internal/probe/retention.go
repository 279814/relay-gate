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
	for {
		if ctx.Err() != nil {
			return
		}
		delay := 5 * time.Minute
		if j.once(ctx) {
			delay = time.Second
		}
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// Nonempty batches yield before continuing, rather than allowing a high-rate
// real-traffic backlog to grow by waiting five minutes after every 500 rows.
// Every Store call has an independent deadline; pause does not stop retention.
func (j *RetentionJanitor) once(ctx context.Context) (more bool) {
	if j == nil || j.store == nil || ctx.Err() != nil {
		return false
	}
	now := j.now().UTC()
	const batch = 500
	for _, job := range []struct {
		name  string
		prune func(context.Context, time.Time, int) (int, error)
	}{
		{"probe execution", j.store.PruneProbeExecutions},
		{"calibration", j.store.PruneCalibrationHistory},
		{"probe cost", j.store.PruneProbeCostHistory},
	} {
		if ctx.Err() != nil {
			return more
		}
		batchCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		n, err := job.prune(batchCtx, now, batch)
		cancel()
		if ctx.Err() != nil {
			return more
		}
		if err != nil {
			j.log.Warn("清理探活历史失败", "kind", job.name, "err", err)
		} else if n > 0 {
			more = true
			j.log.Info("已清理探活历史", "kind", job.name, "rows", n)
		}
	}
	return more
}
