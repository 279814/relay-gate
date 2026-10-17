package store

import (
	"context"
	"database/sql"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

// LoadCurrentNegativeReachability reads recoverable negatives and their current
// identity in one transaction. The foreign key and hard-delete history guard
// preserve this association after executions are pruned; a timestamp alone is
// never treated as a replacement identity. Positives are intentionally omitted.
func (store *Store) LoadCurrentNegativeReachability(ctx context.Context) ([]*model.UpstreamReachability, error) {
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT r.upstream_id FROM upstream_reachability r
		JOIN upstream u ON u.id=r.upstream_id
		WHERE r.state=? AND r.observed_network_revision=u.network_revision
		AND u.created_at>0 AND r.last_error_at>u.created_at AND r.last_observation_order>0
		ORDER BY r.upstream_id`, model.ReachabilityUnreachable)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	result := make([]*model.UpstreamReachability, 0, len(ids))
	for _, id := range ids {
		row, err := loadReachability(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		revision, err := currentReachabilityRevisionForUpstream(ctx, tx, id, row.PolicySelector)
		if err != nil {
			return nil, err
		}
		if row.ObservedNetworkRevision != revision.NetworkRevision || row.SettingsFingerprint != revision.SettingsFingerprint ||
			row.ObservationToken == "" || row.ObservationToken != revisioncodec.NewReachabilityToken(revision) {
			continue
		}
		// Equal-millisecond evidence cannot distinguish a damaged imported row
		// from a reused ID whose revisions reset. Fail closed instead of giving
		// that row the new incarnation's CreatedAt.
		if row.LastErrorAt <= revision.CreatedAt {
			continue
		}
		row.ObservedCreatedAt = revision.CreatedAt
		result = append(result, row)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}
