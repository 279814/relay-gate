package probe

import (
	"context"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/router"
)

type CanaryPolicySource interface {
	GetCanaryPolicy(context.Context, int64) (model.CanaryPolicy, error)
	ListEnabledCanaryPolicies(context.Context, int64, int) ([]model.CanaryPolicy, error)
}

type canarySchedule struct {
	revision, routeID int64
	due               time.Time
	hold              uint64
}

// WithCanary configures the existing tick/lease lifecycle before Run starts.
func (s *Scheduler) WithCanary(service *Service, source CanaryPolicySource) *Scheduler {
	s.canary, s.canaryPolicies = service, source
	s.canaryDue = map[int64]canarySchedule{}
	return s
}

func (s *Scheduler) WithCanaryReporter(report func(model.ProbeExecution)) *Scheduler {
	s.canaryReport = report
	return s
}

func (s *Scheduler) tickCanaries(ctx context.Context, snapshot *router.Snapshot) {
	if s.canary == nil || s.canary.executor == nil || s.canaryPolicies == nil || snapshot == nil || s.currentRunState() != model.RunStateRunning {
		return
	}
	pageCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	policies, err := s.canaryPolicies.ListEnabledCanaryPolicies(pageCtx, s.canaryAfter, 200)
	cancel()
	if err != nil {
		s.log.Warn("Canary 策略读取未完成，本轮跳过")
		return
	}
	s.canaryAfter = 0
	if len(policies) == 200 {
		s.canaryAfter = policies[len(policies)-1].UpstreamID
	}
	s.mu.Lock()
	for id := range s.canaryDue {
		up := snapshot.Upstreams[id]
		if up == nil || !up.Enabled || up.ProbeMode != model.ProbeModeActive {
			delete(s.canaryDue, id)
		}
	}
	s.mu.Unlock()
	for _, policy := range policies {
		up := snapshot.Upstreams[policy.UpstreamID]
		route := findRoute(snapshot, policy.RouteID)
		if up == nil || !up.Enabled || up.ProbeMode != model.ProbeModeActive || route == nil || !route.Enabled || route.UpstreamID != up.ID {
			continue
		}
		name := findModelName(snapshot, route.ModelNameID)
		if name == nil || !name.Enabled {
			continue
		}
		now := s.canary.executor.clock.Now()
		s.mu.Lock()
		entry := s.canaryDue[up.ID]
		if entry.revision != policy.Revision || entry.routeID != policy.RouteID {
			entry = canarySchedule{revision: policy.Revision, routeID: policy.RouteID}
			s.canaryDue[up.ID] = entry
		}
		due := entry.hold == 0 && !now.Before(entry.due)
		s.mu.Unlock()
		if !due {
			continue
		}
		hold, ok := s.beginL2(up.ID, route.ID)
		if !ok {
			continue
		}
		s.mu.Lock()
		entry.hold = hold
		s.canaryDue[up.ID] = entry
		s.mu.Unlock()
		s.wg.Add(1)
		go func(policy model.CanaryPolicy, hold uint64) {
			defer s.wg.Done()
			defer s.endL2(policy.UpstreamID, policy.RouteID, hold)
			defer func() {
				s.mu.Lock()
				current := s.canaryDue[policy.UpstreamID]
				if current.hold == hold {
					current.hold = 0
					current.due = s.canary.executor.clock.Now().Add(time.Duration(policy.IntervalSec) * time.Second)
					s.canaryDue[policy.UpstreamID] = current
				}
				s.mu.Unlock()
			}()
			execution, err := s.canary.runCanary(ctx, policy.RouteID, model.CanaryPeriodic, policy.Revision)
			if err != nil {
				s.log.Warn("周期 Canary 未完成", "upstream_id", policy.UpstreamID)
				return
			}
			if s.canaryReport != nil {
				s.canaryReport(execution)
			}
		}(policy, hold)
	}
}
