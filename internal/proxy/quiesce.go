package proxy

import (
	"context"
	"errors"
	"net/http"
	"sync"

	"github.com/279814/relay-gate/internal/model"
)

type admissionFence struct {
	mu     sync.Mutex
	frozen bool
	active int
	idle   chan struct{}
}

func (h *Handler) withAdmission(protocol model.Protocol, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		gate := &h.admission
		gate.mu.Lock()
		if gate.frozen {
			gate.mu.Unlock()
			w.Header().Set("Retry-After", "60")
			writeAPIError(w, http.StatusServiceUnavailable, protocol, "overloaded_error", "服务维护中")
			return
		}
		if gate.active == 0 {
			gate.idle = make(chan struct{})
		}
		gate.active++
		gate.mu.Unlock()
		defer func() {
			gate.mu.Lock()
			gate.active--
			if gate.active == 0 {
				close(gate.idle)
			}
			gate.mu.Unlock()
		}()
		next(w, r)
	}
}

// Quiesce closes admission before waiting for entire handlers, including those
// still reading a request body before routing. No lock spans the drain or I/O.
func (h *Handler) Quiesce(ctx context.Context) (func(), error) {
	gate := &h.admission
	gate.mu.Lock()
	if gate.frozen {
		gate.mu.Unlock()
		return nil, errors.New("proxy admission already quiesced")
	}
	gate.frozen = true
	idle, active := gate.idle, gate.active
	gate.mu.Unlock()
	var once sync.Once
	release := func() { once.Do(func() { gate.mu.Lock(); gate.frozen = false; gate.mu.Unlock() }) }
	if active == 0 {
		return release, nil
	}
	select {
	case <-idle:
		return release, nil
	case <-ctx.Done():
		release()
		return nil, ctx.Err()
	}
}
