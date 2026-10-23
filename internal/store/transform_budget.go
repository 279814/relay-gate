package store

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/transform"
)

const transformBudgetSetting = "transform_budgets_v1"

func (s *Store) LoadTransformBudgets() (transform.BudgetLimits, int64, error) {
	var raw []byte
	var revision int64
	err := s.db.QueryRow(`SELECT value,revision FROM setting WHERE key=?`, transformBudgetSetting).Scan(&raw, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		return transform.BudgetLimits{RequestMs: transform.DefaultRequestBudgetMs, SSEEventMs: transform.DefaultSSEBudgetMs}, 1, nil
	}
	if err != nil {
		return transform.BudgetLimits{}, 0, err
	}
	var limits transform.BudgetLimits
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&limits); err != nil {
		return limits, 0, model.WrapValidation("持久转换预算无效")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return limits, 0, model.WrapValidation("持久转换预算无效")
	}
	if revision < 1 || limits.Validate() != nil {
		return limits, 0, model.WrapValidation("持久转换预算或版本无效")
	}
	return limits, revision, nil
}

func (s *Store) SaveTransformBudgets(limits transform.BudgetLimits, expected int64) (int64, error) {
	if expected < 1 || limits.Validate() != nil {
		return 0, model.WrapValidation("转换预算或版本无效")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var current int64
	err = tx.QueryRow(`SELECT revision FROM setting WHERE key=?`, transformBudgetSetting).Scan(&current)
	absent := errors.Is(err, sql.ErrNoRows)
	if absent {
		current = 1
	} else if err != nil {
		return 0, err
	}
	conflict := fmt.Errorf("%w: %w", ErrRevisionConflict, transform.ErrRevisionConflict)
	if current != expected {
		return 0, conflict
	}
	raw, err := json.Marshal(limits)
	if err != nil {
		return 0, err
	}
	var result sql.Result
	if absent {
		result, err = tx.Exec(`INSERT INTO setting(key,value,updated_at,revision) VALUES(?,?,?,?)`, transformBudgetSetting, string(raw), nowMS(), current+1)
	} else {
		result, err = tx.Exec(`UPDATE setting SET value=?,updated_at=?,revision=revision+1 WHERE key=? AND revision=?`, string(raw), nowMS(), transformBudgetSetting, current)
	}
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if affected != 1 {
		return 0, conflict
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return current + 1, nil
}
