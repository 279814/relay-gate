package store

import (
	"database/sql"
	"errors"
)

// keyProbeCost 是探活成本快照在 setting 表里的键。
//
// 复用 setting 的 key-value 而不是新建一张表：这是**一行**数据（当日汇总
// 的 JSON），而它的形状会随 §5.2d 的展示需求变化。为它开一张宽表，
// 每加一个计数字段就要改一次 schema。
const keyProbeCost = "probe_cost_today"

// GetProbeCostRaw 读出探活成本快照的原始 JSON。
//
// 返回原始字节而不是解析好的结构：这个结构定义在 probe 包里
// （probe.CostSnapshot），而 store 不该 import probe —— 那会让存储层
// 依赖探活层。由调用方解析。
//
// 没有记录时返回空串且不算错：首次启动本就没有。
func (s *Store) GetProbeCostRaw() (string, error) {
	var raw string
	err := s.db.QueryRow(`SELECT value FROM setting WHERE key = ?`, keyProbeCost).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return raw, nil
}

// SaveProbeCostRaw 写入探活成本快照。
func (s *Store) SaveProbeCostRaw(raw string) error {
	_, err := s.db.Exec(`INSERT INTO setting (key, value, updated_at) VALUES (?,?,?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		keyProbeCost, raw, nowMS())
	return err
}
