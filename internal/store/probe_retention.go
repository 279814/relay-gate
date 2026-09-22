package store

import (
	"context"
	"time"
)

// PruneProbeExecutions 小批清理过期/超额 execution（P0-13）。
//
// 本提交提供可调用的安全 stub：返回 0 行；完整 cutoff/cap 矩阵在后续补齐。
func (s *Store) PruneProbeExecutions(ctx context.Context, nowUTC time.Time, limit int) (int, error) {
	_ = ctx
	_ = nowUTC
	_ = limit
	return 0, nil
}

// PruneProbeCostHistory 推进 cost watermark 并小批删除关闭窗口数据。
func (s *Store) PruneProbeCostHistory(ctx context.Context, nowUTC time.Time, limit int) (int, error) {
	_ = ctx
	_ = nowUTC
	_ = limit
	return 0, nil
}

// PruneCalibrationHistory 裁剪过期且未被引用的 terminal Calibration。
func (s *Store) PruneCalibrationHistory(ctx context.Context, nowUTC time.Time, limit int) (int, error) {
	_ = ctx
	_ = nowUTC
	_ = limit
	return 0, nil
}
