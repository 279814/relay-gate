package store

import (
	"context"
	"database/sql"
	"strconv"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/security"
)

// The same metadata predicate serves admin pages and the background mailer.
// f is either an immutable finding row or a two-field VALUES identity.
const securityIgnoreMatch = `i.enabled=1 AND (i.expires_at_ms=0 OR i.expires_at_ms>evaluation.evaluated_at_ms)
	AND ((i.scope='rule' AND f.rule_id<>'' AND i.rule_id=f.rule_id) OR (i.scope='route' AND f.route_id>0 AND i.route_id=f.route_id))`

func (s *Store) SecurityFindingIgnored(ctx context.Context, f security.Finding, atMS int64) (bool, error) {
	if atMS < 1 {
		return false, model.WrapValidation("忽略策略判定时刻无效")
	}
	var ignored bool
	err := s.db.QueryRowContext(ctx, `WITH evaluation(evaluated_at_ms) AS (VALUES (?)), finding(rule_id,route_id) AS (VALUES (?,?))
		SELECT EXISTS(SELECT 1 FROM security_ignore_rule i WHERE `+securityIgnoreMatch+`) FROM finding f CROSS JOIN evaluation`, atMS, f.RuleID, f.RouteID).Scan(&ignored)
	return ignored, err
}

type SecurityIgnoreFilter struct {
	model.PageRequest
	Scope   string
	RuleID  string
	RouteID int64
	Active  *bool
}

type SecurityIgnorePage struct {
	Rules         []security.IgnoreRule `json:"rules"`
	Total         int64                 `json:"total"`
	NextCursor    string                `json:"next_cursor"`
	EvaluatedAtMS int64                 `json:"evaluated_at_ms"`
}

func (s *Store) ListSecurityIgnoreRules(ctx context.Context, f SecurityIgnoreFilter) (SecurityIgnorePage, error) {
	page := SecurityIgnorePage{Rules: []security.IgnoreRule{}}
	limit, err := normalizePageLimit(f.Limit)
	if err != nil {
		return page, err
	}
	if f.RouteID < 0 || f.Scope != "" && f.Scope != "rule" && f.Scope != "route" || f.RuleID != "" && !security.KnownRuleIdentity(f.RuleID) {
		return page, model.WrapValidation("忽略规则筛选无效")
	}
	filter := f
	filter.PageRequest = model.PageRequest{}
	keys, atMS, err := decodePageCursorAt(f.Cursor, "security-ignore-rules", filter, 1)
	if err != nil {
		return page, err
	}
	if atMS == 0 {
		atMS = nowMS()
	}
	page.EvaluatedAtMS = atMS
	where := "1=1"
	args := []any{atMS}
	if f.Scope != "" {
		where += " AND scope=?"
		args = append(args, f.Scope)
	}
	if f.RuleID != "" {
		where += " AND rule_id=?"
		args = append(args, f.RuleID)
	}
	if f.RouteID > 0 {
		where += " AND route_id=?"
		args = append(args, f.RouteID)
	}
	if f.Active != nil {
		where += " AND (enabled=1 AND (expires_at_ms=0 OR expires_at_ms>evaluation.evaluated_at_ms))=?"
		args = append(args, *f.Active)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return page, err
	}
	defer tx.Rollback()
	const prefix = "WITH evaluation(evaluated_at_ms) AS (VALUES (?)) "
	const from = " FROM security_ignore_rule CROSS JOIN evaluation WHERE "
	if err := tx.QueryRowContext(ctx, prefix+"SELECT COUNT(*)"+from+where, args...).Scan(&page.Total); err != nil {
		return page, err
	}
	if len(keys) > 0 {
		id, err := cursorID(keys[0])
		if err != nil {
			return page, err
		}
		where += " AND id<?"
		args = append(args, id)
	}
	args = append(args, limit+1)
	rows, err := tx.QueryContext(ctx, prefix+"SELECT "+securityIgnoreColumns+from+where+" ORDER BY id DESC LIMIT ?", args...)
	if err != nil {
		return page, err
	}
	for rows.Next() {
		rule, err := scanSecurityIgnore(rows)
		if err != nil {
			rows.Close()
			return page, err
		}
		page.Rules = append(page.Rules, rule)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return page, err
	}
	if len(page.Rules) > limit {
		page.Rules = page.Rules[:limit]
		page.NextCursor, err = encodePageCursorAt("security-ignore-rules", filter, atMS, strconv.FormatInt(page.Rules[len(page.Rules)-1].ID, 10))
		if err != nil {
			return page, err
		}
	}
	if err := tx.Commit(); err != nil {
		return page, err
	}
	return page, nil
}
