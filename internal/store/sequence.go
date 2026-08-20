package store

import (
	"context"
	"fmt"
	"math"
)

const maximumObservationOrderBlock = 1_000_000

func (store *Store) ReserveObservationOrders(ctx context.Context, blockSize int64) (start, end int64, err error) {
	if blockSize < 1 || blockSize > maximumObservationOrderBlock {
		return 0, 0, fmt.Errorf("observation order block size 必须在 1..%d", maximumObservationOrderBlock)
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("开始 observation sequence 事务: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO observation_sequence(singleton, high_watermark) VALUES (1, 0)`); err != nil {
		return 0, 0, fmt.Errorf("初始化 observation sequence: %w", err)
	}
	var current int64
	if err = tx.QueryRowContext(ctx, `SELECT high_watermark FROM observation_sequence WHERE singleton=1`).Scan(&current); err != nil {
		return 0, 0, fmt.Errorf("读取 observation sequence: %w", err)
	}
	if current > math.MaxInt64-blockSize {
		return 0, 0, fmt.Errorf("observation sequence 已耗尽")
	}
	start = current + 1
	end = current + blockSize
	if _, err = tx.ExecContext(ctx, `UPDATE observation_sequence SET high_watermark=? WHERE singleton=1`, end); err != nil {
		return 0, 0, fmt.Errorf("推进 observation sequence: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("提交 observation sequence: %w", err)
	}
	return start, end, nil
}
