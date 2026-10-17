package store

import (
	"context"

	"github.com/279814/relay-gate/internal/model"
)

// RouteIDsOfUpstream returns the complete invalidation target set. This command
// reads only identities through the FK index, not pageable display rows.
func (s *Store) RouteIDsOfUpstream(ctx context.Context, id int64) ([]int64, error) {
	return s.routeIDs(ctx, `SELECT id FROM route WHERE upstream_id=? ORDER BY id`, id)
}

// RouteIDsOfModelName returns identities before a parent mutation can remove
// them, without decrypting or default-filling configuration.
func (s *Store) RouteIDsOfModelName(ctx context.Context, id int64) ([]int64, error) {
	return s.routeIDs(ctx, `SELECT id FROM route WHERE model_name_id=? ORDER BY id`, id)
}

func (s *Store) routeIDs(ctx context.Context, query string, id int64) ([]int64, error) {
	if id < 1 {
		return nil, model.WrapValidation("route parent identity 必须为正数")
	}
	rows, err := s.db.QueryContext(ctx, query, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]int64, 0)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
