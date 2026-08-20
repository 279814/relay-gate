package store

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"

	"github.com/279814/relay-gate/internal/model"
)

const modelNameCols = `id, name, protocol, match_mode, is_fallback,
	probe_prompt, probe_max_tokens, enabled, created_at, updated_at,revision,capability_revision`

func scanModelName(sc interface{ Scan(...any) error }) (*model.ModelName, error) {
	var m model.ModelName
	if err := sc.Scan(&m.ID, &m.Name, &m.Protocol, &m.MatchMode, &m.IsFallback,
		&m.ProbePrompt, &m.ProbeMaxTokens, &m.Enabled, &m.CreatedAt, &m.UpdatedAt,
		&m.Revision, &m.CapabilityRevision); err != nil {
		return nil, err
	}
	return &m, nil
}

func (s *Store) ListModelNames() ([]*model.ModelName, error) {
	rows, err := s.db.Query(`SELECT ` + modelNameCols + ` FROM model_name ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*model.ModelName{}
	for rows.Next() {
		m, err := scanModelName(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) ListModelNamesPage(ctx context.Context, filter model.ModelNameFilter) (model.Page[*model.ModelName], error) {
	limit, err := normalizePageLimit(filter.Limit)
	if err != nil {
		return model.Page[*model.ModelName]{}, err
	}
	cursorFilter := filter
	cursorFilter.PageRequest = model.PageRequest{}
	keys, err := decodePageCursor(filter.Cursor, "model-names", cursorFilter, 1)
	if err != nil {
		return model.Page[*model.ModelName]{}, err
	}
	conditions := []string{"1=1"}
	args := make([]any, 0, 4)
	if filter.Enabled != nil {
		conditions = append(conditions, "enabled=?")
		args = append(args, *filter.Enabled)
	}
	if filter.Protocol != "" {
		if !filter.Protocol.Valid() {
			return model.Page[*model.ModelName]{}, model.WrapValidation("protocol filter 无效")
		}
		conditions = append(conditions, "protocol=?")
		args = append(args, filter.Protocol)
	}
	if len(keys) == 1 {
		id, cursorErr := cursorID(keys[0])
		if cursorErr != nil {
			return model.Page[*model.ModelName]{}, cursorErr
		}
		conditions = append(conditions, "id>?")
		args = append(args, id)
	}
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(ctx, `SELECT `+modelNameCols+` FROM model_name WHERE `+
		strings.Join(conditions, " AND ")+` ORDER BY id LIMIT ?`, args...)
	if err != nil {
		return model.Page[*model.ModelName]{}, err
	}
	defer rows.Close()
	items := make([]*model.ModelName, 0, limit+1)
	for rows.Next() {
		item, scanErr := scanModelName(rows)
		if scanErr != nil {
			return model.Page[*model.ModelName]{}, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return model.Page[*model.ModelName]{}, err
	}
	page := model.Page[*model.ModelName]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextCursor, err = encodePageCursor("model-names", cursorFilter,
			strconv.FormatInt(page.Items[len(page.Items)-1].ID, 10))
		if err != nil {
			return model.Page[*model.ModelName]{}, err
		}
	}
	return page, nil
}

func (s *Store) GetModelName(id int64) (*model.ModelName, error) {
	row := s.db.QueryRow(`SELECT `+modelNameCols+` FROM model_name WHERE id = ?`, id)
	m, err := scanModelName(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return m, err
}

func (s *Store) CreateModelName(m *model.ModelName) error {
	m.Defaults()
	if err := m.Validate(); err != nil {
		return err
	}
	m.CreatedAt = nowMS()
	m.UpdatedAt = m.CreatedAt
	m.Revision = 1
	m.CapabilityRevision = 1

	res, err := s.db.Exec(`INSERT INTO model_name
		(name, protocol, match_mode, is_fallback, probe_prompt, probe_max_tokens,
		 enabled, created_at, updated_at,revision,capability_revision) VALUES (?,?,?,?,?,?,?,?,?,1,1)`,
		m.Name, m.Protocol, m.MatchMode, m.IsFallback, m.ProbePrompt,
		m.ProbeMaxTokens, m.Enabled, m.CreatedAt, m.UpdatedAt)
	if err != nil {
		return wrapConstraint(err, "model_name")
	}
	m.ID, err = res.LastInsertId()
	return err
}

func (s *Store) UpdateModelName(m *model.ModelName) error {
	current, err := s.GetModelName(m.ID)
	if err != nil {
		return err
	}
	return s.UpdateModelNameWithRevision(context.Background(), m, current.Revision)
}

func (s *Store) UpdateModelNameWithRevision(ctx context.Context, value *model.ModelName, expectedRevision int64) (err error) {
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
	current, err := scanModelName(tx.QueryRowContext(ctx, `SELECT `+modelNameCols+` FROM model_name WHERE id=?`, value.ID))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if current.Revision != expectedRevision {
		return ErrRevisionConflict
	}
	semanticChanged := value.Name != current.Name || value.Protocol != current.Protocol ||
		value.ProbePrompt != current.ProbePrompt || value.ProbeMaxTokens != current.ProbeMaxTokens
	rowChanged := semanticChanged || value.MatchMode != current.MatchMode ||
		value.IsFallback != current.IsFallback || value.Enabled != current.Enabled
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
	result, err := tx.ExecContext(ctx, `UPDATE model_name SET name=?,protocol=?,match_mode=?,is_fallback=?,
		probe_prompt=?,probe_max_tokens=?,enabled=?,updated_at=?,revision=?,capability_revision=?
		WHERE id=? AND revision=?`, value.Name, value.Protocol, value.MatchMode, value.IsFallback,
		value.ProbePrompt, value.ProbeMaxTokens, value.Enabled, value.UpdatedAt, value.Revision,
		value.CapabilityRevision, value.ID, expectedRevision)
	if err != nil {
		return wrapConstraint(err, "model_name")
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrRevisionConflict
	}
	return tx.Commit()
}

func (s *Store) DeleteModelName(id int64) error {
	res, err := s.db.Exec(`DELETE FROM model_name WHERE id = ?`, id)
	if err != nil {
		return err
	}
	return checkAffected(res)
}
