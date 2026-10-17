package health

import (
	"context"

	"github.com/279814/relay-gate/internal/model"
)

// NegativeReachabilitySource supplies rows whose durable identity and current
// policy were verified in a single storage transaction.
type NegativeReachabilitySource interface {
	LoadCurrentNegativeReachability(context.Context) ([]*model.UpstreamReachability, error)
}

// RestoreNegatives retains current unreachable conclusions across restart.
// Positive history remains unknown. ApplyCommitted rechecks the published
// identity too, so a refresh between SQL reading and this call cannot revive it.
func (tracker *ReachabilityTracker) RestoreNegatives(ctx context.Context, source NegativeReachabilitySource) (int, error) {
	if tracker == nil || source == nil {
		return 0, nil
	}
	rows, err := source.LoadCurrentNegativeReachability(ctx)
	if err != nil {
		return 0, err
	}
	restored := 0
	for _, row := range rows {
		if row == nil || row.State != model.ReachabilityUnreachable || row.ObservedCreatedAt <= 0 || row.LastErrorAt <= row.ObservedCreatedAt {
			continue
		}
		tracker.ApplyCommitted(row)
		if tracker.Effective(row.UpstreamID, row.ObservedNetworkRevision) == model.ReachabilityUnreachable {
			restored++
		}
	}
	return restored, nil
}
