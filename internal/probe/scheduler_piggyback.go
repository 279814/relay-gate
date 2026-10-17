package probe

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
)

type PiggybackRecorder interface {
	RecordPiggybackSkip(string, model.ProbeCostDaily) bool
}

func (s *Scheduler) WithPiggybackRecorder(recorder PiggybackRecorder) *Scheduler {
	s.piggyback = recorder
	return s
}

func (s *Scheduler) tryPiggyback(routeID int64, generation uint64, now time.Time) bool {
	caps := s.ensureP012().capReg
	if caps == nil || s.track.State(routeID) == model.StateDead || s.track.State(routeID) == model.StateRecovering {
		return false
	}
	var snapshot *livecfg.ProbeSnapshot
	var err error
	if cached, ok := s.cfg.(interface {
		CachedProbeSnapshot() (*livecfg.ProbeSnapshot, error)
	}); ok {
		snapshot, err = cached.CachedProbeSnapshot()
	} else if source, ok := s.cfg.(ProbeSnapshotSource); ok {
		snapshot, err = source.ProbeSnapshot()
	}
	if err != nil || snapshot == nil || !snapshot.Settings.PiggybackEnabled {
		return false
	}
	route := snapshot.Routes[routeID]
	if route == nil {
		return false
	}
	name := snapshot.ModelNames[route.ModelNameID]
	if name == nil {
		return false
	}
	endpoint, ok := name.Protocol.Endpoint()
	if !ok {
		return false
	}
	row := caps.Snapshot(model.RecipeScopeRoute, routeID, endpoint)
	if row == nil || (row.State != model.CapabilitySupported && row.State != model.CapabilityUnknown) || row.LastRealOKAt <= 0 || row.LastRealOKToken == "" {
		return false
	}
	observed := time.UnixMilli(row.LastRealOKAt)
	seconds := snapshot.Settings.L2IntervalAliveSec
	if seconds <= 0 {
		seconds = 600
	}
	until := observed.Add(time.Duration(seconds) * time.Second)
	if now.Before(observed) || !now.Before(until) {
		return false
	}
	resolver := NewRecipeResolver(snapshotRecipeSource{snapshot}).WithNotFound(func(err error) bool { return errors.Is(err, errSnapshotRecipeNotFound) })
	recipe, err := resolver.Resolve(context.Background(), RecipeQuery{UpstreamID: route.UpstreamID, RouteID: routeID, Endpoint: endpoint})
	if err != nil {
		return false
	}
	_, _, expectation, _, err := buildRealExpectations(snapshot, &model.Upstream{ID: route.UpstreamID}, route, endpoint, recipe)
	if err != nil || expectation.ObservationToken != row.LastRealOKToken {
		return false
	}
	deferrer, ok := s.track.(interface {
		DeferL2Until(int64, uint64, time.Time) bool
	})
	if !ok || !deferrer.DeferL2Until(routeID, generation, until) {
		return false
	}
	if s.piggyback != nil {
		day := now.UTC().Format("2006-01-02")
		eventID := fmt.Sprintf("%s:%d", StablePiggybackEventID(day, endpoint, routeID, route.UpstreamID, row.LastRealOKToken), row.LastRealOKAt)
		s.piggyback.RecordPiggybackSkip(eventID, model.ProbeCostDaily{DayUTC: day, Trigger: model.TriggerScheduled, Origin: recipe.Identity.Origin, Endpoint: endpoint, RouteID: routeID, UpstreamID: route.UpstreamID})
	}
	return true
}
