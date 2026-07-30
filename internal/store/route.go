package store

import (
	"database/sql"
	"errors"

	"github.com/279814/relay-gate/internal/model"
)

const routeCols = `id, model_name_id, upstream_id, priority, weight,
	upstream_model, max_concurrency, enabled, created_at, updated_at`

func scanRoute(sc interface{ Scan(...any) error }) (*model.Route, error) {
	var r model.Route
	if err := sc.Scan(&r.ID, &r.ModelNameID, &r.UpstreamID, &r.Priority, &r.Weight,
		&r.UpstreamModel, &r.MaxConcurrency, &r.Enabled, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	return &r, nil
}

// ListRoutes 列出全部 Route；modelNameID > 0 时只列该 ModelName 下的。
// 按 priority 升序（1 最高）返回，与选路顺序一致，便于 UI 直接展示。
func (s *Store) ListRoutes(modelNameID int64) ([]*model.Route, error) {
	q := `SELECT ` + routeCols + ` FROM route`
	args := []any{}
	if modelNameID > 0 {
		q += ` WHERE model_name_id = ?`
		args = append(args, modelNameID)
	}
	q += ` ORDER BY model_name_id, priority, id`

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*model.Route{}
	for rows.Next() {
		r, err := scanRoute(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetRoute(id int64) (*model.Route, error) {
	row := s.db.QueryRow(`SELECT `+routeCols+` FROM route WHERE id = ?`, id)
	r, err := scanRoute(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

func (s *Store) CreateRoute(r *model.Route) error {
	r.Defaults()
	if err := r.Validate(); err != nil {
		return err
	}
	r.CreatedAt = nowMS()
	r.UpdatedAt = r.CreatedAt

	res, err := s.db.Exec(`INSERT INTO route
		(model_name_id, upstream_id, priority, weight, upstream_model,
		 max_concurrency, enabled, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)`,
		r.ModelNameID, r.UpstreamID, r.Priority, r.Weight, r.UpstreamModel,
		r.MaxConcurrency, r.Enabled, r.CreatedAt, r.UpdatedAt)
	if err != nil {
		return wrapConstraint(err, "route")
	}
	if r.ID, err = res.LastInsertId(); err != nil {
		return err
	}
	// 建 health 行，让 UI 立刻能显示 unknown 而不是空白。
	_, err = s.db.Exec(`INSERT OR IGNORE INTO route_health (route_id, state, updated_at)
		VALUES (?, ?, ?)`, r.ID, model.StateUnknown, r.CreatedAt)
	return err
}

func (s *Store) UpdateRoute(r *model.Route) error {
	r.Defaults()
	if err := r.Validate(); err != nil {
		return err
	}
	r.UpdatedAt = nowMS()

	res, err := s.db.Exec(`UPDATE route SET
		model_name_id=?, upstream_id=?, priority=?, weight=?, upstream_model=?,
		max_concurrency=?, enabled=?, updated_at=? WHERE id=?`,
		r.ModelNameID, r.UpstreamID, r.Priority, r.Weight, r.UpstreamModel,
		r.MaxConcurrency, r.Enabled, r.UpdatedAt, r.ID)
	if err != nil {
		return wrapConstraint(err, "route")
	}
	return checkAffected(res)
}

func (s *Store) DeleteRoute(id int64) error {
	res, err := s.db.Exec(`DELETE FROM route WHERE id = ?`, id)
	if err != nil {
		return err
	}
	return checkAffected(res)
}
