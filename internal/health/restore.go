package health

import (
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

// RestoreVerified installs an already-current negative before admission opens.
// Store verifies SQL facts; the startup caller verifies the published Recipe
// identity. It never replaces live state or imports in-flight/schedule leases.
func (t *Tracker) RestoreVerified(row *store.RouteHealth) bool {
	if t == nil || row == nil || row.RouteID <= 0 || (row.Identity == nil && !row.LegacyUnverified) {
		return false
	}
	now := t.now()
	state := row.State
	if state == model.StateAlive {
		state = model.StateUnknown
	}
	if row.RecoveryRequired && state != model.StateDead {
		state = model.StateRecovering
	}
	if state != model.StateDead && state != model.StateRecovering && row.CooldownUntil <= now.UnixMilli() {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state[row.RouteID] != nil {
		return false
	}
	rs := t.get(row.RouteID)
	rs.state = state
	rs.identity = model.CloneRouteHealthIdentity(row.Identity)
	if row.LegacyUnverified {
		rs.state = model.StateRecovering
		rs.recoverySource = "legacy_unverified"
		return true
	}
	rs.consecutiveOK = max(0, row.ConsecutiveOK)
	rs.consecutiveFail = max(0, row.ConsecutiveFail)
	rs.lastOKAt = timeFromMS(row.LastOKAt)
	rs.lastErrAt = timeFromMS(row.LastErrAt)
	rs.lastError = row.LastError
	rs.lastTTFT = time.Duration(max(0, row.LastTTFTMS)) * time.Millisecond
	if state == model.StateDead {
		rs.deadSince = timeFromMS(row.DeadSince)
	}
	if row.CooldownUntil > now.UnixMilli() {
		rs.cooldownUntil = time.UnixMilli(row.CooldownUntil)
		rs.lastReason = VerdictRateLimited
	} else if row.LastError != "" {
		rs.lastReason = VerdictUnavailable
	}
	rs.recoverySource = "verified_snapshot"
	return true
}

func timeFromMS(ms int64) time.Time {
	if ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms)
}
