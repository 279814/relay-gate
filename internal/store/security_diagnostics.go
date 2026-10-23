package store

import (
	"context"
	"database/sql"
	"strconv"
	"strings"

	"github.com/279814/relay-gate/internal/model"
)

type SecurityDiagnosticFilter struct {
	model.PageRequest
	Source     model.CanarySource
	Verdict    string
	UpstreamID int64
	RouteID    int64
}
type SecurityDiagnosticPage struct {
	Items      []*model.ProbeExecution `json:"items"`
	Total      int64                   `json:"total"`
	NextCursor string                  `json:"next_cursor"`
}

func validCanaryVerdict(v string) bool {
	switch v {
	case "", "passed", "violation", "incomplete", "canceled", "execution_failed", "not_sent":
		return true
	}
	return false
}

// ListSecurityDiagnostics reads only executions with persisted Canary14 facts.
// Count, keyset page and attached facts share one SQLite read snapshot.
func (s *Store) ListSecurityDiagnostics(ctx context.Context, f SecurityDiagnosticFilter) (SecurityDiagnosticPage, error) {
	page := SecurityDiagnosticPage{Items: []*model.ProbeExecution{}}
	if f.Source != "" && !f.Source.Valid() || !validCanaryVerdict(f.Verdict) || f.RouteID < 0 || f.UpstreamID < 0 {
		return page, model.WrapValidation("安全诊断筛选无效")
	}
	limit, err := normalizePageLimit(f.Limit)
	if err != nil {
		return page, err
	}
	cf := f
	cf.PageRequest = model.PageRequest{}
	keys, err := decodePageCursor(f.Cursor, "security-diagnostics", cf, 2)
	if err != nil {
		return page, err
	}
	where := "EXISTS(SELECT 1 FROM canary_execution c WHERE c.execution_id=probe_execution.id"
	args := []any{}
	if f.Source != "" {
		where += " AND c.source=?"
		args = append(args, f.Source)
	}
	if f.Verdict != "" {
		where += " AND c.verdict=?"
		args = append(args, f.Verdict)
	}
	where += ")"
	if f.RouteID > 0 {
		where += " AND route_id=?"
		args = append(args, f.RouteID)
	}
	if f.UpstreamID > 0 {
		where += " AND upstream_id=?"
		args = append(args, f.UpstreamID)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return page, err
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM probe_execution WHERE `+where, args...).Scan(&page.Total); err != nil {
		return page, err
	}
	if len(keys) > 0 {
		at, err := strconv.ParseInt(keys[0], 10, 64)
		if err != nil || at < 0 || keys[1] == "" || len(keys[1]) > 256 {
			return page, ErrInvalidCursor
		}
		where += " AND (sent_at_ms<? OR (sent_at_ms=? AND id<?))"
		args = append(args, at, at, keys[1])
	}
	args = append(args, limit+1)
	rows, err := tx.QueryContext(ctx, `SELECT `+probeExecutionCols+` FROM probe_execution WHERE `+where+` ORDER BY sent_at_ms DESC,id DESC LIMIT ?`, args...)
	if err != nil {
		return page, err
	}
	for rows.Next() {
		execution, err := scanProbeExecution(rows)
		if err != nil {
			rows.Close()
			return page, err
		}
		page.Items = append(page.Items, execution)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return page, err
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor, err = encodePageCursor("security-diagnostics", cf, strconv.FormatInt(last.SentAtMS, 10), last.ID)
		if err != nil {
			return page, err
		}
	}
	for _, execution := range page.Items {
		execution.Canary, err = loadCanaryExecution(ctx, tx, execution.ID)
		if err != nil {
			return page, err
		}
	}
	return page, tx.Commit()
}

// The regular execution detail reader remains the only decoding authority.
func (s *Store) GetSecurityDiagnostic(ctx context.Context, id string) (*model.ProbeExecution, error) {
	if strings.TrimSpace(id) == "" || len(id) > 256 {
		return nil, model.WrapValidation("安全诊断ID无效")
	}
	execution, err := s.GetProbeExecution(ctx, id)
	if err != nil {
		return nil, err
	}
	if execution.Canary == nil {
		return nil, ErrNotFound
	}
	return execution, nil
}
