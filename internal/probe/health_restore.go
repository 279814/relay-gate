package probe

import (
	"context"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/revisioncodec"
	"github.com/279814/relay-gate/internal/store"
)

// RestoreRouteHealth runs before listeners and synthetic admission are opened.
func RestoreRouteHealth(ctx context.Context, tracker *health.Tracker, rows *store.Store, configs PublishedConfigSource) (int, error) {
	if tracker == nil || rows == nil || configs == nil {
		return 0, nil
	}
	if _, err := configs.Bundle(); err != nil {
		return 0, err
	}
	list, err := rows.LoadCurrentRouteHealth(ctx)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, row := range list {
		if proof := row.Identity; proof != nil {
			current := capabilityHealthCurrent
			if proof.RouteContextOnly {
				current = capabilityContextCurrent
			}
			if !current(configs, &proof.Route) {
				continue
			}
			if proof.Evidence != nil && !current(configs, proof.Evidence) {
				continue
			}
			if proof.Reachability != nil && !reachabilityHealthCurrent(configs, proof.Reachability) {
				continue
			}
			snap := healthSnapshot(configs)
			if snap == nil || proof.HealthSettingsFingerprint != revisioncodec.RouteHealthSettingsFingerprint(snap.Settings) {
				continue
			}
		}
		if tracker.RestoreVerified(row) {
			count++
		}
	}
	return count, nil
}
