package probe

import (
	"time"

	"github.com/279814/relay-gate/internal/health"
)

// Outcome is the RouteHealth projection of the shared Classifier's Decision.
// The execution and committed apply dispositions remain the durable evidence.
type Outcome struct {
	Verdict    health.Verdict
	Err        error
	TTFT       time.Duration
	RetryAfter time.Duration
	Status     int
	Sent       bool
	EstTokens  int
}

// Local preparation and pool configuration failures do not represent network
// evidence. Executor records their config_error without damaging RouteHealth.
func probeConfigOutcome(err error) Outcome {
	return Outcome{Verdict: health.VerdictIgnore, Err: err}
}
