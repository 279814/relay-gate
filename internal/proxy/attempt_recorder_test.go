package proxy

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/probe"
)

// Records the proxy/observer boundary. Persisted privacy is tested through the
// real TrafficObserverManager and SQLite in probe/traffic_privacy_test.go.
type attemptRecorder struct {
	mu       sync.Mutex
	attempts []*recordedAttempt
}

type observedAttempt struct {
	routeID     int64
	status      int
	errBody     []byte
	err         error
	halfOpen    bool
	configError bool
}

type recordedAttempt struct {
	mu    sync.Mutex
	value observedAttempt
}

func (recorder *attemptRecorder) PrepareAttempt(_ context.Context, target health.AttemptTarget, _ health.AttemptRequestView) health.AttemptInstrumentation {
	attempt := &recordedAttempt{value: observedAttempt{routeID: target.RouteID}}
	recorder.mu.Lock()
	recorder.attempts = append(recorder.attempts, attempt)
	recorder.mu.Unlock()
	return health.AttemptInstrumentation{Observer: attempt, Retry: probe.NewRetryDecider(target.Protocol), Trace: &outbound.AttemptTrace{}}
}

func (attempt *recordedAttempt) TryHeaders(status int, _ http.Header, _ time.Time) bool {
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	attempt.value.status = status
	return true
}

func (attempt *recordedAttempt) TryChunk(chunk []byte, _ time.Time) bool {
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	remaining := (64 << 10) - len(attempt.value.errBody)
	if len(chunk) > remaining {
		chunk = chunk[:remaining]
	}
	attempt.value.errBody = append(attempt.value.errBody, chunk...)
	return true
}

func (attempt *recordedAttempt) Finish(finish health.AttemptFinish) {
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	attempt.value.err, attempt.value.halfOpen = finish.ReadErr, finish.HalfOpen
	attempt.value.configError = finish.ConfigError
}

func (recorder *attemptRecorder) all() []observedAttempt {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	result := make([]observedAttempt, 0, len(recorder.attempts))
	for _, attempt := range recorder.attempts {
		attempt.mu.Lock()
		value := attempt.value
		value.errBody = append([]byte(nil), value.errBody...)
		attempt.mu.Unlock()
		result = append(result, value)
	}
	return result
}
