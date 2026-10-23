package store

import (
	"context"
	"database/sql"
	"errors"
	"math"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/security"
)

func (s *Store) ReviewSecurityFinding(ctx context.Context, findingID, status string, expectedRevision int64) (security.FindingReview, error) {
	result := security.FindingReview{}
	if findingID == "" || len(findingID) > 256 || expectedRevision < 1 || expectedRevision == math.MaxInt64 || status != "open" && status != "false_positive" {
		return result, model.WrapValidation("安全发现审核状态或 revision 无效")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	var current int64
	err = tx.QueryRowContext(ctx, `SELECT COALESCE(r.revision,1) FROM security_finding f LEFT JOIN security_finding_review r ON r.finding_id=f.id WHERE f.id=?`, findingID).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrNotFound
	}
	if err != nil {
		return result, err
	}
	if current != expectedRevision {
		return result, ErrRevisionConflict
	}
	result = security.FindingReview{FindingID: findingID, Status: status, Revision: current + 1, UpdatedAtMS: nowMS()}
	written, err := tx.ExecContext(ctx, `INSERT INTO security_finding_review(finding_id,status,revision,updated_at_ms) VALUES (?,?,?,?)
		ON CONFLICT(finding_id) DO UPDATE SET status=excluded.status,revision=excluded.revision,updated_at_ms=excluded.updated_at_ms WHERE security_finding_review.revision=?`, findingID, result.Status, result.Revision, result.UpdatedAtMS, expectedRevision)
	if err != nil {
		return security.FindingReview{}, err
	}
	if err := requireSecurityRow(written); err != nil {
		return security.FindingReview{}, err
	}
	return result, tx.Commit()
}

func requireSecurityRow(result sql.Result) error {
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrRevisionConflict
	}
	return nil
}

const securityIgnoreColumns = `id,scope,rule_id,route_id,expires_at_ms,enabled,revision,created_at_ms,updated_at_ms`

func scanSecurityIgnore(row interface{ Scan(...any) error }) (security.IgnoreRule, error) {
	var r security.IgnoreRule
	err := row.Scan(&r.ID, &r.Scope, &r.RuleID, &r.RouteID, &r.ExpiresAtMS, &r.Enabled, &r.Revision, &r.CreatedAtMS, &r.UpdatedAtMS)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return r, err
}

func validateIgnoreTarget(ctx context.Context, tx *sql.Tx, rule security.IgnoreRule) error {
	var count int
	var err error
	if rule.Scope == "route" {
		err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM route WHERE id=?`, rule.RouteID).Scan(&count)
	} else {
		// Only an existing recorded rule identity can be copied into policy.
		// A caller-supplied secret/string cannot create a new rule namespace.
		err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM security_finding WHERE rule_id=?)`, rule.RuleID).Scan(&count)
	}
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) CreateSecurityIgnoreRule(ctx context.Context, rule security.IgnoreRule) (security.IgnoreRule, error) {
	if err := rule.Validate(nowMS()); err != nil {
		return security.IgnoreRule{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return security.IgnoreRule{}, err
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_ignore_rule`).Scan(&count); err != nil {
		return security.IgnoreRule{}, err
	}
	if count >= security.MaximumIgnoreRules {
		return security.IgnoreRule{}, model.WrapValidation("安全忽略规则已达1024条上限，请先删除不再需要的规则")
	}
	if err := validateIgnoreTarget(ctx, tx, rule); err != nil {
		return security.IgnoreRule{}, err
	}
	rule.Revision, rule.CreatedAtMS = 1, nowMS()
	rule.UpdatedAtMS = rule.CreatedAtMS
	result, err := tx.ExecContext(ctx, `INSERT INTO security_ignore_rule(scope,rule_id,route_id,expires_at_ms,enabled,revision,created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,1,?,?)`,
		rule.Scope, rule.RuleID, rule.RouteID, rule.ExpiresAtMS, rule.Enabled, rule.CreatedAtMS, rule.UpdatedAtMS)
	if err != nil {
		return security.IgnoreRule{}, err
	}
	if err := requireSecurityRow(result); err != nil {
		return security.IgnoreRule{}, err
	}
	rule.ID, err = result.LastInsertId()
	if err != nil {
		return security.IgnoreRule{}, err
	}
	return rule, tx.Commit()
}

func (s *Store) UpdateSecurityIgnoreRule(ctx context.Context, id, expectedRevision int64, rule security.IgnoreRule) (security.IgnoreRule, error) {
	if id < 1 || expectedRevision < 1 || expectedRevision == math.MaxInt64 {
		return security.IgnoreRule{}, model.WrapValidation("忽略规则 ID 或 revision 无效")
	}
	if err := rule.Validate(nowMS()); err != nil {
		return security.IgnoreRule{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return security.IgnoreRule{}, err
	}
	defer tx.Rollback()
	current, err := scanSecurityIgnore(tx.QueryRowContext(ctx, `SELECT `+securityIgnoreColumns+` FROM security_ignore_rule WHERE id=?`, id))
	if err != nil {
		return security.IgnoreRule{}, err
	}
	if current.Revision != expectedRevision {
		return security.IgnoreRule{}, ErrRevisionConflict
	}
	if current.Scope != rule.Scope || current.RuleID != rule.RuleID || current.RouteID != rule.RouteID {
		if err := validateIgnoreTarget(ctx, tx, rule); err != nil {
			return security.IgnoreRule{}, err
		}
	}
	rule.ID, rule.Revision, rule.CreatedAtMS, rule.UpdatedAtMS = id, expectedRevision+1, current.CreatedAtMS, max(nowMS(), current.UpdatedAtMS)
	result, err := tx.ExecContext(ctx, `UPDATE security_ignore_rule SET scope=?,rule_id=?,route_id=?,expires_at_ms=?,enabled=?,revision=?,updated_at_ms=? WHERE id=? AND revision=?`,
		rule.Scope, rule.RuleID, rule.RouteID, rule.ExpiresAtMS, rule.Enabled, rule.Revision, rule.UpdatedAtMS, id, expectedRevision)
	if err != nil {
		return security.IgnoreRule{}, err
	}
	if err := requireSecurityRow(result); err != nil {
		return security.IgnoreRule{}, err
	}
	return rule, tx.Commit()
}

func (s *Store) DeleteSecurityIgnoreRule(ctx context.Context, id, expectedRevision int64) error {
	if id < 1 || expectedRevision < 1 {
		return model.WrapValidation("忽略规则 ID 或 revision 无效")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var revision int64
	err = tx.QueryRowContext(ctx, `SELECT revision FROM security_ignore_rule WHERE id=?`, id).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if revision != expectedRevision {
		return ErrRevisionConflict
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM security_ignore_rule WHERE id=? AND revision=?`, id, expectedRevision)
	if err != nil {
		return err
	}
	if err := requireSecurityRow(result); err != nil {
		return err
	}
	return tx.Commit()
}
