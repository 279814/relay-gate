package probe

import (
	"sync/atomic"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

// The existing full observer worker is the only semantic-progress writer.
// Admission failures are published by the producer without waiting for it.
type trafficProgress struct {
	state   atomic.Pointer[health.ResponseProgress]
	changes chan struct{}
}

func (p *trafficProgress) update(update func(*health.ResponseProgress)) {
	for {
		old := p.state.Load()
		next := health.ResponseProgress{}
		if old != nil {
			next = *old
		}
		update(&next)
		if p.state.CompareAndSwap(old, &next) {
			break
		}
	}
	select {
	case p.changes <- struct{}{}:
	default:
	}
}

func (p *trafficProgress) fail(reason model.ObserverIncompleteReason) {
	if reason == "" {
		return
	}
	p.update(func(state *health.ResponseProgress) {
		if state.Incomplete == "" {
			state.Incomplete = reason
		}
	})
}

func (p *trafficProgress) accept(event ProtocolEvent, at time.Time) {
	p.update(func(state *health.ResponseProgress) {
		if state.FirstEventAt.IsZero() {
			state.FirstEventAt = at
		}
		if !event.Semantic {
			return
		}
		if state.FirstSemanticAt.IsZero() {
			state.FirstSemanticAt = at
		}
		state.LastSemanticAt = at
	})
}

func (o *trafficObserver) ResponseProgress() health.ResponseProgress {
	if state := o.progress.state.Load(); state != nil {
		return *state
	}
	return health.ResponseProgress{}
}

func (o *trafficObserver) ProgressChanges() <-chan struct{} { return o.progress.changes }
