package store

import (
	"github.com/279814/relay-gate/internal/model"
)

// RouteHealth 是 route_health 表的一行：健康状态的持久化快照。
//
// **不是**权威来源。运行时状态以内存为准（§2.4），重启后一律回到 unknown，
// 绝不从这张表恢复 —— 恢复的话，一个进程崩溃前被判死的站会在重启后
// 继续被排除在选路之外，而它可能早就好了。这张表只服务两个用途：
// 管理界面展示「上次看到的状态」，以及故障回溯。
type RouteHealth struct {
	RouteID         int64             `json:"route_id"`
	State           model.HealthState `json:"state"`
	ConsecutiveOK   int               `json:"consecutive_ok"`
	ConsecutiveFail int               `json:"consecutive_fail"`
	LastOKAt        int64             `json:"last_ok_at"`
	LastErrAt       int64             `json:"last_err_at"`
	LastError       string            `json:"last_error"`
	LastTTFTMS      int64             `json:"last_ttft_ms"`
	UpdatedAt       int64             `json:"updated_at"`
}

const routeHealthCols = `route_id, state, consecutive_ok, consecutive_fail,
	last_ok_at, last_err_at, last_error, last_ttft_ms, updated_at`

// ListRouteHealth 读出全部健康快照，按 route_id 升序。
func (s *Store) ListRouteHealth() ([]*RouteHealth, error) {
	rows, err := s.db.Query(`SELECT ` + routeHealthCols +
		` FROM route_health ORDER BY route_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*RouteHealth{}
	for rows.Next() {
		var h RouteHealth
		if err := rows.Scan(&h.RouteID, &h.State, &h.ConsecutiveOK, &h.ConsecutiveFail,
			&h.LastOKAt, &h.LastErrAt, &h.LastError, &h.LastTTFTMS, &h.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, &h)
	}
	return out, rows.Err()
}

// SaveRouteHealth 写入一批健康快照。
//
// 整批走一个事务：SQLite 每个未显式包事务的写入都要自己 fsync 一次，
// N 个 Route 就是 N 次磁盘同步。而这些写入是**同一时刻**的状态快照，
// 拆开落库既慢又可能让 UI 读到半新半旧的一批。
//
// route_id 不存在时静默跳过（外键约束会拒绝）：Route 可能在快照采集
// 与落库之间被删掉，那不是错误。
func (s *Store) SaveRouteHealth(list []*RouteHealth) error {
	if len(list) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // 提交成功后 Rollback 是无操作

	// 用 UPDATE 而不是 upsert：route_health 行由 CreateRoute 建，
	// 这里只更新。Route 被删掉时对应行已随外键级联消失，
	// UPDATE 影响 0 行，正是想要的「静默跳过」。
	stmt, err := tx.Prepare(`UPDATE route_health SET
		state=?, consecutive_ok=?, consecutive_fail=?,
		last_ok_at=?, last_err_at=?, last_error=?, last_ttft_ms=?, updated_at=?
		WHERE route_id=?`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := nowMS()
	for _, h := range list {
		if _, err := stmt.Exec(h.State, h.ConsecutiveOK, h.ConsecutiveFail,
			h.LastOKAt, h.LastErrAt, h.LastError, h.LastTTFTMS, now, h.RouteID); err != nil {
			return err
		}
	}
	return tx.Commit()
}
