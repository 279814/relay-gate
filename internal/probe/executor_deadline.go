package probe

import (
	"errors"
	"time"

	"github.com/279814/relay-gate/internal/outbound"
)

var (
	errProbeHeaderTimeout = errors.New("response_header_timeout")
	errProbeByteTimeout   = errors.New("first_byte_timeout")
	errProbeEventTimeout  = errors.New("first_event_timeout")
	errProbeIdleTimeout   = errors.New("idle_timeout")
	errProbeTotalTimeout  = errors.New("total_timeout")
)

func probeTimeoutReason(err error) string {
	for _, timeout := range []error{errProbeHeaderTimeout, errProbeByteTimeout, errProbeEventTimeout, ErrProbeSemanticTimeout, errProbeIdleTimeout, errProbeTotalTimeout} {
		if errors.Is(err, timeout) {
			if timeout == ErrProbeSemanticTimeout {
				return "semantic_timeout"
			}
			return timeout.Error()
		}
	}
	return ""
}

// All pending phases share one timer. The timestamps already recorded for the
// execution are also the completion flags; there is no second lifecycle state.
func nextExecutionDeadline(budget outbound.Budget, sentAt time.Time, timing *sendTiming, lastActivity time.Time) (time.Time, error) {
	deadline, cause := budget.TotalDeadline(sentAt), errProbeTotalTimeout
	consider := func(enabled bool, at time.Time, err error) {
		if enabled && at.Before(deadline) {
			deadline, cause = at, err
		}
	}
	consider(timing.responseHeaderAtMS == 0 && budget.ResponseHead > 0, budget.ResponseHeadDeadline(sentAt), errProbeHeaderTimeout)
	consider(timing.firstByteAtMS == 0 && budget.FirstByte > 0, budget.FirstByteDeadline(sentAt), errProbeByteTimeout)
	consider(timing.firstEventAtMS == 0 && budget.FirstEvent > 0, budget.FirstEventDeadline(sentAt), errProbeEventTimeout)
	consider(timing.firstSemanticAtMS == 0 && budget.FirstSemantic > 0, budget.FirstSemanticDeadline(sentAt), ErrProbeSemanticTimeout)
	consider(timing.firstSemanticAtMS != 0 && !lastActivity.IsZero(), lastActivity.Add(budget.IdleTimeout()), errProbeIdleTimeout)
	return deadline, cause
}

func resetExecutionTimer(timer Timer, clock Clock, deadline time.Time) Timer {
	duration := stageDuration(clock.Now(), deadline)
	if timer == nil {
		return clock.NewTimer(duration)
	}
	if !timer.Stop() {
		select {
		case <-timer.C():
		default:
		}
	}
	timer.Reset(duration)
	return timer
}
