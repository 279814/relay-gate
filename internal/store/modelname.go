package store

import (
	"database/sql"
	"errors"

	"github.com/279814/relay-gate/internal/model"
)

const modelNameCols = `id, name, protocol, match_mode, is_fallback,
	probe_prompt, probe_max_tokens, enabled, created_at, updated_at`

func scanModelName(sc interface{ Scan(...any) error }) (*model.ModelName, error) {
	var m model.ModelName
	if err := sc.Scan(&m.ID, &m.Name, &m.Protocol, &m.MatchMode, &m.IsFallback,
		&m.ProbePrompt, &m.ProbeMaxTokens, &m.Enabled, &m.CreatedAt, &m.UpdatedAt); err != nil {
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

	res, err := s.db.Exec(`INSERT INTO model_name
		(name, protocol, match_mode, is_fallback, probe_prompt, probe_max_tokens,
		 enabled, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)`,
		m.Name, m.Protocol, m.MatchMode, m.IsFallback, m.ProbePrompt,
		m.ProbeMaxTokens, m.Enabled, m.CreatedAt, m.UpdatedAt)
	if err != nil {
		return wrapConstraint(err, "model_name")
	}
	m.ID, err = res.LastInsertId()
	return err
}

func (s *Store) UpdateModelName(m *model.ModelName) error {
	m.Defaults()
	if err := m.Validate(); err != nil {
		return err
	}
	m.UpdatedAt = nowMS()

	res, err := s.db.Exec(`UPDATE model_name SET
		name=?, protocol=?, match_mode=?, is_fallback=?, probe_prompt=?,
		probe_max_tokens=?, enabled=?, updated_at=? WHERE id=?`,
		m.Name, m.Protocol, m.MatchMode, m.IsFallback, m.ProbePrompt,
		m.ProbeMaxTokens, m.Enabled, m.UpdatedAt, m.ID)
	if err != nil {
		return wrapConstraint(err, "model_name")
	}
	return checkAffected(res)
}

func (s *Store) DeleteModelName(id int64) error {
	res, err := s.db.Exec(`DELETE FROM model_name WHERE id = ?`, id)
	if err != nil {
		return err
	}
	return checkAffected(res)
}
