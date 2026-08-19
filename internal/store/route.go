package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/279814/relay-gate/internal/model"
)

const routeCols = `id, model_name_id, upstream_id, priority, weight,
	upstream_model, max_concurrency, enabled, created_at, updated_at,revision,capability_revision`

func scanRoute(sc interface{ Scan(...any) error }) (*model.Route, error) {
	var r model.Route
	if err := sc.Scan(&r.ID, &r.ModelNameID, &r.UpstreamID, &r.Priority, &r.Weight,
		&r.UpstreamModel, &r.MaxConcurrency, &r.Enabled, &r.CreatedAt, &r.UpdatedAt,
		&r.Revision, &r.CapabilityRevision); err != nil {
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

// ListRoutesPage 按 id 分页，不沿用 ListRoutes 的 priority 排序：priority 可重复，
// 且没有覆盖 (model_name_id, priority, id) 的索引，用它做 keyset 既要三段 cursor
// 又得全表排序。管理端列表要的是「翻页不重不漏」，选路顺序由 ListRoutes 负责。
func (s *Store) ListRoutesPage(ctx context.Context, filter model.RouteFilter) (model.Page[*model.Route], error) {
	limit, err := normalizePageLimit(filter.Limit)
	if err != nil {
		return model.Page[*model.Route]{}, err
	}
	cursorFilter := filter
	cursorFilter.PageRequest = model.PageRequest{}
	keys, err := decodePageCursor(filter.Cursor, "routes", cursorFilter, 1)
	if err != nil {
		return model.Page[*model.Route]{}, err
	}
	conditions := []string{"1=1"}
	args := make([]any, 0, 5)
	if filter.ModelNameID > 0 {
		conditions = append(conditions, "model_name_id=?")
		args = append(args, filter.ModelNameID)
	}
	if filter.UpstreamID > 0 {
		conditions = append(conditions, "upstream_id=?")
		args = append(args, filter.UpstreamID)
	}
	if filter.Enabled != nil {
		conditions = append(conditions, "enabled=?")
		args = append(args, *filter.Enabled)
	}
	if len(keys) == 1 {
		id, cursorErr := cursorID(keys[0])
		if cursorErr != nil {
			return model.Page[*model.Route]{}, cursorErr
		}
		conditions = append(conditions, "id>?")
		args = append(args, id)
	}
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(ctx, `SELECT `+routeCols+` FROM route WHERE `+
		strings.Join(conditions, " AND ")+` ORDER BY id LIMIT ?`, args...)
	if err != nil {
		return model.Page[*model.Route]{}, err
	}
	defer rows.Close()
	items := make([]*model.Route, 0, limit+1)
	for rows.Next() {
		item, scanErr := scanRoute(rows)
		if scanErr != nil {
			return model.Page[*model.Route]{}, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return model.Page[*model.Route]{}, err
	}
	page := model.Page[*model.Route]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextCursor, err = encodePageCursor("routes", cursorFilter,
			strconv.FormatInt(page.Items[len(page.Items)-1].ID, 10))
		if err != nil {
			return model.Page[*model.Route]{}, err
		}
	}
	return page, nil
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
	r.Revision = 1
	r.CapabilityRevision = 1

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := validateRouteEndpointCompleteness(tx, r.UpstreamID); err != nil {
		return err
	}
	res, err := tx.Exec(`INSERT INTO route
		(model_name_id, upstream_id, priority, weight, upstream_model,
		 max_concurrency, enabled, created_at, updated_at,revision,capability_revision)
		 VALUES (?,?,?,?,?,?,?,?,?,1,1)`,
		r.ModelNameID, r.UpstreamID, r.Priority, r.Weight, r.UpstreamModel,
		r.MaxConcurrency, r.Enabled, r.CreatedAt, r.UpdatedAt)
	if err != nil {
		return wrapConstraint(err, "route")
	}
	if r.ID, err = res.LastInsertId(); err != nil {
		return err
	}
	// 建 health 行，让 UI 立刻能显示 unknown 而不是空白。
	_, err = tx.Exec(`INSERT OR IGNORE INTO route_health (route_id, state, updated_at)
		VALUES (?, ?, ?)`, r.ID, model.StateUnknown, r.CreatedAt)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UpdateRoute(r *model.Route) error {
	current, err := s.GetRoute(r.ID)
	if err != nil {
		return err
	}
	return s.UpdateRouteWithRevision(context.Background(), r, current.Revision)
}

func (s *Store) UpdateRouteWithRevision(ctx context.Context, value *model.Route, expectedRevision int64) (err error) {
	value.Defaults()
	if err := value.Validate(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	current, err := scanRoute(tx.QueryRowContext(ctx, `SELECT `+routeCols+` FROM route WHERE id=?`, value.ID))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if current.Revision != expectedRevision {
		return ErrRevisionConflict
	}
	if err := validateRouteEndpointCompleteness(tx, value.UpstreamID); err != nil {
		return err
	}
	semanticChanged := value.ModelNameID != current.ModelNameID || value.UpstreamID != current.UpstreamID ||
		value.UpstreamModel != current.UpstreamModel
	rowChanged := semanticChanged || value.Priority != current.Priority || value.Weight != current.Weight ||
		value.MaxConcurrency != current.MaxConcurrency || value.Enabled != current.Enabled
	if !rowChanged {
		value.Revision = current.Revision
		value.CapabilityRevision = current.CapabilityRevision
		value.CreatedAt = current.CreatedAt
		value.UpdatedAt = current.UpdatedAt
		return tx.Commit()
	}
	value.Revision = current.Revision + 1
	value.CapabilityRevision = current.CapabilityRevision
	if semanticChanged {
		value.CapabilityRevision++
	}
	value.CreatedAt = current.CreatedAt
	value.UpdatedAt = nowMS()
	result, err := tx.ExecContext(ctx, `UPDATE route SET model_name_id=?,upstream_id=?,priority=?,weight=?,
		upstream_model=?,max_concurrency=?,enabled=?,updated_at=?,revision=?,capability_revision=?
		WHERE id=? AND revision=?`, value.ModelNameID, value.UpstreamID, value.Priority, value.Weight,
		value.UpstreamModel, value.MaxConcurrency, value.Enabled, value.UpdatedAt, value.Revision,
		value.CapabilityRevision, value.ID, expectedRevision)
	if err != nil {
		return wrapConstraint(err, "route")
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrRevisionConflict
	}
	return tx.Commit()
}

func validateRouteEndpointCompleteness(query interface {
	QueryRow(string, ...any) *sql.Row
}, upstreamID int64) error {
	var upstreamExists int
	if err := query.QueryRow(`SELECT COUNT(*) FROM upstream WHERE id=?`, upstreamID).Scan(&upstreamExists); err != nil {
		return err
	}
	if upstreamExists != 1 {
		return model.WrapValidation("引用的 Upstream 不存在")
	}
	var total, migrationOnly int
	err := query.QueryRow(`SELECT COUNT(*),COALESCE(SUM(CASE WHEN url_mode='legacy_exact' OR auth_mode='legacy_auto_real_only' THEN 1 ELSE 0 END),0)
		FROM upstream_endpoint WHERE upstream_id=?`, upstreamID).Scan(&total, &migrationOnly)
	if err != nil {
		return err
	}
	if total != 5 && migrationOnly == 0 {
		return fmt.Errorf("%w: Upstream 必须先补齐五个 Endpoint", ErrDependencyConflict)
	}
	return nil
}

func (s *Store) DeleteRoute(id int64) error {
	res, err := s.db.Exec(`DELETE FROM route WHERE id = ?`, id)
	if err != nil {
		return err
	}
	return checkAffected(res)
}
