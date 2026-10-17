package api

import (
	"context"
	"errors"
	"net/http"
	"sync"

	"github.com/279814/relay-gate/internal/runstate"
)

// mutationAdmission protects admission counts only. No holder keeps its mutex
// while a handler, a database call, or a rotation drain is running.
type mutationAdmission struct {
	mu      sync.Mutex
	closed  bool
	active  int
	drained chan struct{}
}

func (g *mutationAdmission) enter() (func(), bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil, false
	}
	if g.active == 0 {
		g.drained = make(chan struct{})
	}
	g.active++
	return func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.active--
		if g.active == 0 {
			close(g.drained)
		}
	}, true
}

func (g *mutationAdmission) freeze(ctx context.Context) (func(), error) {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil, errors.New("admin writes are already frozen")
	}
	g.closed = true
	drained := g.drained
	if g.active == 0 {
		drained = make(chan struct{})
		close(drained)
	}
	g.mu.Unlock()
	var once sync.Once
	release := func() { once.Do(func() { g.mu.Lock(); g.closed = false; g.mu.Unlock() }) }
	select {
	case <-ctx.Done():
		release()
		return nil, ctx.Err()
	case <-drained:
		return release, nil
	}
}

func (s *Server) guardMutations(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions ||
			r.URL.Path == "/admin/api/credentials/rotate-master" {
			next.ServeHTTP(w, r)
			return
		}
		if s.runState != nil && s.runState.InMaintenance() {
			writeJSON(w, http.StatusConflict, map[string]any{"code": runstate.MaintenanceActiveCode, "error": "maintenance 期间禁止管理写入"})
			return
		}
		leave, admitted := s.mutations.enter()
		if !admitted {
			writeJSON(w, http.StatusConflict, map[string]any{"code": runstate.MaintenanceActiveCode, "error": "管理写入正在等待安全轮换"})
			return
		}
		defer leave()
		next.ServeHTTP(w, r)
	})
}
