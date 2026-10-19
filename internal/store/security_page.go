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
	Severity security.Severity
	RouteID  int64
	Category string
	FromMS   int64
	ToMS     int64
}

type SecurityFindingPage struct {
	Findings   []security.Finding `json:"findings"`
	Total      int64              `json:"total"`
	NextCursor string             `json:"next_cursor"`
}

func (f SecurityFindingFilter) Validate() error {
	if f.RouteID < 0 || f.FromMS < 0 || f.ToMS < 0 || (f.ToMS != 0 && f.FromMS > f.ToMS) || !findingSelector(f.Category) {
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
	keys, err := decodePageCursor(f.Cursor, "security-findings", cursorFilter, 2)
	if err != nil {
		return page, err
	}
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
	var args []any
	for _, match := range []struct {
		column string
		value  string
	}{{"severity", string(f.Severity)}, {"category", f.Category}} {
		if match.value != "" {
			where += " AND " + match.column + "=?"
			args = append(args, match.value)
		}
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
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM security_finding WHERE "+where, args...).Scan(&page.Total); err != nil {
		return page, err
	}
	if beforeID != "" {
		where += " AND (at_ms<? OR (at_ms=? AND id<?))"
		args = append(args, beforeMS, beforeMS, beforeID)
	}
	args = append(args, limit+1)
	rows, err := tx.QueryContext(ctx, "SELECT "+securityFindingColumns+" FROM security_finding WHERE "+where+" ORDER BY at_ms DESC,id DESC LIMIT ?", args...)
	if err != nil {
		return page, err
	}
	for rows.Next() {
		f, err := s.scanSecurityFinding(rows)
		if err != nil {
			rows.Close()
			return page, err
		}
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
		page.NextCursor, err = encodePageCursor("security-findings", cursorFilter, strconv.FormatInt(last.AtMS, 10), last.ID)
		if err != nil {
			return page, err
		}
	}
	if err := tx.Commit(); err != nil {
		return page, err
	}
	return page, nil
}
