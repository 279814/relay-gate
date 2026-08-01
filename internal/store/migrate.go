package store

import (
	"database/sql"
	"fmt"
)

// migrate 把 schema.sql 覆盖不到的变更补上。
//
// 为什么需要它：`CREATE TABLE IF NOT EXISTS` 对**已存在**的表是空操作，
// 加不了列。也就是说 schema.sql 只能让新库长对，老库会静默停在旧结构上 ——
// 而症状是「新字段读出来永远是零值」，不报错、不失败。
//
// 每一条都必须幂等：schema.sql 每次启动都跑一遍，这里也一样。
func migrate(db *sql.DB) error {
	// M6：样本挂上 req_id，与 request_log 同组。
	//
	// 方向是「sample 存 req_id」而不是「request_log 存 sample_id」：
	// 样本 id 由后台 writer 落库时才分配，而日志在转发路径上就要写出去 ——
	// 那一刻 sample_id 还不存在。req_id 是我们自己在请求开始时生成的，
	// 两边都同步可知。
	if err := addColumn(db, "sample", "req_id",
		`ALTER TABLE sample ADD COLUMN req_id TEXT NOT NULL DEFAULT ''`); err != nil {
		return err
	}
	// 老样本没有 req_id（空串），索引照建 —— 空串会挤在一起，
	// 但那部分数据本来就查不到组，不影响新数据的查询。
	if _, err := db.Exec(
		`CREATE INDEX IF NOT EXISTS idx_sample_req ON sample (req_id)`); err != nil {
		return fmt.Errorf("建 idx_sample_req: %w", err)
	}
	return nil
}

// addColumn 幂等地加一列：已存在就跳过。
//
// 先查 PRAGMA 再决定，而不是「无脑 ALTER 然后忽略错误」。后者会把**任何**
// 错误都当成「列已存在」咽掉 —— 磁盘满、库损坏、SQL 写错，全都变成静默跳过，
// 而后果是程序带着一个缺列的表继续跑。
func addColumn(db *sql.DB, table, column, ddl string) error {
	has, err := hasColumn(db, table, column)
	if err != nil {
		return err
	}
	if has {
		return nil
	}
	if _, err := db.Exec(ddl); err != nil {
		return fmt.Errorf("给 %s 加列 %s: %w", table, column, err)
	}
	return nil
}

// hasColumn 查表里有没有这一列。
func hasColumn(db *sql.DB, table, column string) (bool, error) {
	// PRAGMA 不接受参数绑定，表名只能拼进去。这里的表名全是代码里的字面量
	// （不来自用户输入），所以不构成注入面；真要传外部输入进来时必须先做白名单。
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return false, fmt.Errorf("读取 %s 的列信息: %w", table, err)
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}
