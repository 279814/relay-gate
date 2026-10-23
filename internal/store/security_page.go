package store

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/security"
)

type SecurityFindingFilter struct {
	model.PageRequest
	Severity     security.Severity
	UpstreamID   int64
	RouteID      int64
	RuleID       string
	ReviewStatus string
	Ignored      *bool
	Category     string
	FromMS       int64
	ToMS         int64
}

type SecurityFindingPage struct {
	Findings      []security.Finding `json:"findings"`
	Total         int64              `json:"total"`
	NextCursor    string             `json:"next_cursor"`
	EvaluatedAtMS int64              `json:"evaluated_at_ms"`
}

func (f SecurityFindingFilter) Validate() error {
	if f.UpstreamID < 0 || f.RouteID < 0 || f.FromMS < 0 || f.ToMS < 0 || (f.ToMS != 0 && f.FromMS > f.ToMS) || !findingSelector(f.Category) ||
		(f.RuleID != "" && f.RuleID != "unknown" && !security.KnownRuleIdentity(f.RuleID)) || (f.ReviewStatus != "" && f.ReviewStatus != "open" && f.ReviewStatus != "false_positive") {
		return model.WrapValidation("安全发现筛选无效")
	}
	switch f.Severity {
	case "", security.SeverityInfo, security.SeverityLow, security.SeverityMedium, security.SeverityHigh, security.SeverityCritical:
		return nil
	default:
		return model.WrapValidation("安全发现严重级别无效")
	}
}

func findingSelector(value string) bool {
	if len(value) > 64 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_.:-", c)) {
			return false
		}
	}
	return true
}

// ListSecurityFindingsPage obtains the filtered count and bounded keyset page
// from one SQLite snapshot. Durable read failures never fall back to a ring.
func (s *Store) ListSecurityFindingsPage(ctx context.Context, f SecurityFindingFilter) (SecurityFindingPage, error) {
	page := SecurityFindingPage{Findings: []security.Finding{}}
	limit, err := normalizePageLimit(f.Limit)
	if err != nil {
		return page, err
	}
	if err := f.Validate(); err != nil {
		return page, err
	}
	cursorFilter := f
	cursorFilter.PageRequest = model.PageRequest{}
	keys, evaluated, err := decodePageCursorAt(f.Cursor, "security-findings", cursorFilter, 2)
	if err != nil {
		return page, err
	}
	if evaluated == 0 {
		evaluated = nowMS()
	}
	page.EvaluatedAtMS = evaluated
	var beforeMS int64
	var beforeID string
	if len(keys) != 0 {
		beforeMS, err = strconv.ParseInt(keys[0], 10, 64)
		beforeID = keys[1]
		if err != nil || beforeMS < 0 || len(beforeID) == 0 || len(beforeID) > 256 {
			return page, ErrInvalidCursor
		}
	}
	where := "1=1"
	args := []any{evaluated}
	for _, match := range []struct {
		column string
		value  string
	}{{"severity", string(f.Severity)}, {"category", f.Category}} {
		if match.value != "" {
			where += " AND " + match.column + "=?"
			args = append(args, match.value)
		}
	}
	if f.UpstreamID > 0 {
		where += " AND upstream_id=?"
		args = append(args, f.UpstreamID)
	}
	if f.RuleID != "" {
		where += " AND rule_id=?"
		if f.RuleID == "unknown" {
			args = append(args, "")
		} else {
			args = append(args, f.RuleID)
		}
	}
	if f.ReviewStatus != "" {
		where += " AND COALESCE(r.status,'open')=?"
		args = append(args, f.ReviewStatus)
	}
	if f.Ignored != nil {
		where += " AND EXISTS(SELECT 1 FROM security_ignore_rule i WHERE " + securityIgnoreMatch + ")=?"
		args = append(args, *f.Ignored)
	}
	if f.RouteID > 0 {
		where += " AND route_id=?"
		args = append(args, f.RouteID)
	}
	if f.FromMS > 0 {
		where += " AND at_ms>=?"
		args = append(args, f.FromMS)
	}
	if f.ToMS > 0 {
		where += " AND at_ms<=?"
		args = append(args, f.ToMS)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return page, err
	}
	defer tx.Rollback()
	const evaluation = "WITH evaluation(evaluated_at_ms) AS (VALUES (?)) "
	const from = " FROM security_finding f CROSS JOIN evaluation LEFT JOIN security_finding_review r ON r.finding_id=f.id WHERE "
	if err := tx.QueryRowContext(ctx, evaluation+"SELECT COUNT(*)"+from+where, args...).Scan(&page.Total); err != nil {
		return page, err
	}
	if beforeID != "" {
		where += " AND (at_ms<? OR (at_ms=? AND id<?))"
		args = append(args, beforeMS, beforeMS, beforeID)
	}
	args = append(args, limit+1)
	rows, err := tx.QueryContext(ctx, evaluation+"SELECT "+securityFindingColumns+",COALESCE(r.status,'open'),COALESCE(r.revision,1),COALESCE(r.updated_at_ms,0),COALESCE((SELECT MIN(i.id) FROM security_ignore_rule i WHERE "+securityIgnoreMatch+"),0)"+from+where+" ORDER BY at_ms DESC,id DESC LIMIT ?", args...)
	if err != nil {
		return page, err
	}
	for rows.Next() {
		review := security.FindingReview{}
		var ignoredBy int64
		f, err := s.scanSecurityFinding(rows, &review.Status, &review.Revision, &review.UpdatedAtMS, &ignoredBy)
		if err != nil {
			rows.Close()
			return page, err
		}
		review.FindingID = f.ID
		f.Review, f.Ignored, f.IgnoreRuleID = &review, ignoredBy > 0, ignoredBy
		page.Findings = append(page.Findings, f)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return page, err
	}
	if len(page.Findings) > limit {
		page.Findings = page.Findings[:limit]
		last := page.Findings[len(page.Findings)-1]
		if len(last.ID) == 0 || len(last.ID) > 256 {
			return page, fmt.Errorf("安全发现身份无效")
		}
		page.NextCursor, err = encodePageCursorAt("security-findings", cursorFilter, evaluated, strconv.FormatInt(last.AtMS, 10), last.ID)
		if err != nil {
			return page, err
		}
	}
	if err := tx.Commit(); err != nil {
		return page, err
	}
	return page, nil
}
