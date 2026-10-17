package probe

import (
	"errors"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

// RouteHealth follows the same committed evidence as Capability. count_tokens
// never reports model health, and incomplete 2xx bodies provide no failure.
func (m *TrafficObserverManager) applyHealth(item trafficWrite, result model.ProbeApplyResult) {
	if m.tracker == nil || item.observation == nil {
		return
	}
	execution := item.observation.Execution
	if execution.Endpoint == model.EndpointCountTokens || execution.ErrorClass == model.ErrorIgnored ||
		execution.Capability == model.CapabilityConfigError || execution.Capability == model.CapabilityUnsupported ||
		execution.ErrorClass == model.ErrorAuthRejected {
		return
	}
	if execution.StatusCode > 0 && (result.Capability != model.ApplyCurrent || !capabilityHealthCurrent(m.cfg, item.observation.CapabilityExpectation)) {
		return
	}
	if execution.StatusCode == 0 && (result.Reachability != model.ApplyCurrent || !reachabilityHealthCurrent(m.cfg, item.observation.ReachabilityExpectation)) {
		return
	}
	if current, ok := m.tracker.(interface{ GenerationOf(int64) uint64 }); ok && current.GenerationOf(execution.RouteID) != item.target.HealthGeneration {
		return
	}
	verdict := health.VerdictUnavailable
	if execution.Success {
		if result.CommittedCapability == nil || result.CommittedCapability.State != model.CapabilitySupported {
			return
		}
		verdict = health.VerdictOK
	} else if execution.ErrorClass == model.ErrorRateLimited {
		verdict = health.VerdictRateLimited
	}
	var err error
	if verdict != health.VerdictOK {
		err = errors.New(string(execution.ErrorClass))
	}
	ttft := time.Duration(0)
	if execution.FirstSemanticAtMS >= execution.SentAtMS && execution.SentAtMS > 0 {
		ttft = time.Duration(execution.FirstSemanticAtMS-execution.SentAtMS) * time.Millisecond
	}
	retryAfter := time.Until(time.UnixMilli(execution.RetryAfterUntilMS))
	if execution.RetryAfterUntilMS == 0 || retryAfter < 0 {
		retryAfter = 0
	}
	m.tracker.Report(health.Report{RouteID: execution.RouteID, Generation: item.target.HealthGeneration, Source: health.SourceReal,
		Verdict: verdict, HalfOpen: item.finish.HalfOpen, Err: err, TTFT: ttft, RetryAfter: retryAfter})
	if verdict == health.VerdictOK {
		if m.sched != nil {
			m.sched.ObserveRealSuccess(ScheduleKey{ScopeType: model.RecipeScopeRoute, ScopeID: execution.RouteID, UpstreamID: execution.UpstreamID, Endpoint: execution.Endpoint}, time.UnixMilli(execution.DoneAtMS))
		}
	} else {
		m.tracker.TriggerL2(execution.RouteID)
	}
}
