package store

import (
	"context"
	"database/sql"
	"errors"
	"math"

	"github.com/279814/relay-gate/internal/model"
)

const canaryPolicyCols = "upstream_id,route_id,enabled,interval_sec,revision"

func scanCanaryPolicy(row interface{ Scan(...any) error }) (model.CanaryPolicy, error) {
	var policy model.CanaryPolicy
	err := row.Scan(&policy.UpstreamID, &policy.RouteID, &policy.Enabled, &policy.IntervalSec, &policy.Revision)
	return policy, err
}

func (s *Store) GetCanaryPolicy(ctx context.Context, upstreamID int64) (model.CanaryPolicy, error) {
	if upstreamID <= 0 {
		return model.CanaryPolicy{}, model.WrapValidation("Canary Upstream ID 无效")
	}
	policy, err := scanCanaryPolicy(s.db.QueryRowContext(ctx, `SELECT `+canaryPolicyCols+` FROM canary_policy WHERE upstream_id=?`, upstreamID))
	if !errors.Is(err, sql.ErrNoRows) {
		return policy, err
	}
	var exists bool
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM upstream WHERE id=?)`, upstreamID).Scan(&exists); err != nil {
		return policy, err
	}
	if !exists {
		return policy, ErrNotFound
	}
	return model.CanaryPolicy{UpstreamID: upstreamID, IntervalSec: 3600}, nil
}

func (s *Store) SaveCanaryPolicy(ctx context.Context, policy model.CanaryPolicy) (model.CanaryPolicy, error) {
	if policy.UpstreamID <= 0 || policy.RouteID <= 0 || policy.Revision < 0 || policy.Revision == math.MaxInt64 || policy.IntervalSec < 300 || policy.IntervalSec > 86400 {
		return model.CanaryPolicy{}, model.WrapValidation("Canary ID、revision 或周期无效（300–86400 秒）")
	}
	// Target validation and CAS are one statement. No read-then-write transaction
	// can upgrade an obsolete SQLite snapshot and report a spurious busy result.
	saved, err := scanCanaryPolicy(s.db.QueryRowContext(ctx, `INSERT INTO canary_policy(upstream_id,route_id,enabled,interval_sec,revision)
 SELECT u.id,r.id,?,?,1 FROM upstream u JOIN route r ON r.upstream_id=u.id JOIN model_name m ON m.id=r.model_name_id
 WHERE u.id=? AND r.id=? AND (?=0 OR (u.enabled=1 AND r.enabled=1 AND m.enabled=1 AND u.probe_mode='active'))
 AND (?=0 OR EXISTS(SELECT 1 FROM canary_policy WHERE upstream_id=u.id))
 ON CONFLICT(upstream_id) DO UPDATE SET route_id=excluded.route_id,enabled=excluded.enabled,interval_sec=excluded.interval_sec,revision=canary_policy.revision+1
 WHERE canary_policy.revision=? RETURNING `+canaryPolicyCols, policy.Enabled, policy.IntervalSec, policy.UpstreamID, policy.RouteID, policy.Enabled, policy.Revision, policy.Revision))
	if !errors.Is(err, sql.ErrNoRows) {
		return saved, err
	}
	current, readErr := s.GetCanaryPolicy(ctx, policy.UpstreamID)
	if readErr != nil {
		return saved, readErr
	}
	if current.Revision != policy.Revision {
		return saved, ErrRevisionConflict
	}
	return saved, model.WrapValidation("Canary Route 必须属于该 Upstream；周期仅允许启用的 Active 目标")
}

// Scheduler reads one bounded keyset page per existing tick; it never gathers
// every enabled policy or creates another queue.
func (s *Store) ListEnabledCanaryPolicies(ctx context.Context, afterUpstreamID int64, limit int) ([]model.CanaryPolicy, error) {
	if afterUpstreamID < 0 {
		return nil, model.WrapValidation("Canary policy keyset 无效")
	}
	limit, err := normalizePageLimit(limit)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+canaryPolicyCols+` FROM canary_policy WHERE enabled=1 AND upstream_id>? ORDER BY upstream_id LIMIT ?`, afterUpstreamID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	policies := make([]model.CanaryPolicy, 0, limit)
	for rows.Next() {
		policy, err := scanCanaryPolicy(rows)
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}
	return policies, rows.Err()
}
