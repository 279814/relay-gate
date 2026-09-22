package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/runstate"
	"github.com/279814/relay-gate/internal/store"
)

// RunStateAdmin 是 /admin/api/state 的唯一写入口（§P0-12 / §13.5）。
type RunStateAdmin interface {
	Get(ctx context.Context) (runstate.Snapshot, error)
	Current() runstate.Snapshot
	Set(ctx context.Context, state model.RunState, expectedRevision int64) (runstate.Snapshot, error)
	EnterMaintenance(reason string) error
	ExitMaintenance() error
	InMaintenance() bool
}

// WithRunState 注入进程级 RunState Controller。
func (s *Server) WithRunState(ctrl RunStateAdmin) *Server {
	s.runState = ctrl
	return s
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	st, err := s.st.GetSettings()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"settings": st,
		"limits": map[string]int{
			"min_real_first_token_sec": model.MinRealFirstTokenSec,
			"max_retry_attempts":       model.MaxRetryAttempts,
		},
	})
}

func (s *Server) updateSettings(w http.ResponseWriter, r *http.Request) {
	cur, err := s.st.GetSettings()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if err := decodeJSON(r, &cur); err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.st.SaveSettings(cur); err != nil {
		s.writeErr(w, err)
		return
	}
	s.log.Info("更新全局设置", "real_first_token_sec", cur.RealFirstTokenSec,
		"sample_enabled", cur.SampleEnabled)
	writeJSON(w, http.StatusOK, cur)
}

// getState / setState 是服务总闸（§4.8 / §P0-12）。
func (s *Server) getState(w http.ResponseWriter, r *http.Request) {
	if s.runState == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"run state controller unavailable"})
		return
	}
	snap, err := s.runState.Get(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out := map[string]any{
		"state":      string(snap.State),
		"effective":  snap.Effective(),
		"revision":   snap.Revision,
		"maintenance": snap.Maintenance,
	}
	if snap.MaintenanceReason != "" {
		out["maintenance_reason"] = snap.MaintenanceReason
	}
	if snap.Warmup != nil {
		out["warmup"] = snap.Warmup
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) setState(w http.ResponseWriter, r *http.Request) {
	if s.runState == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"run state controller unavailable"})
		return
	}
	var body struct {
		State            string `json:"state"`
		ExpectedRevision *int64 `json:"expected_revision"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	state := model.RunState(body.State)
	if !state.Valid() {
		s.writeErr(w, model.WrapValidation("state 必须是 running 或 paused"))
		return
	}
	expected := int64(0)
	if body.ExpectedRevision != nil {
		expected = *body.ExpectedRevision
	} else {
		expected = s.runState.Current().Revision
	}
	snap, err := s.runState.Set(r.Context(), state, expected)
	if err != nil {
		var pending *runstate.TransitionPendingError
		if errors.As(err, &pending) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"code":         pending.Code,
				"persisted":    true,
				"state":        string(pending.Persisted.State),
				"new_revision": pending.Persisted.Revision,
				"error":        pending.Error(),
			})
			return
		}
		if runstate.RevisionConflict(err) || errors.Is(err, store.ErrRevisionConflict) {
			writeJSON(w, http.StatusConflict, errBody{"revision conflict"})
			return
		}
		s.writeErr(w, err)
		return
	}
	s.log.Info("切换服务状态", "state", snap.State, "revision", snap.Revision,
		"effective", snap.Effective())
	out := map[string]any{
		"state":       string(snap.State),
		"effective":   snap.Effective(),
		"revision":    snap.Revision,
		"maintenance": snap.Maintenance,
	}
	if snap.Warmup != nil {
		out["warmup"] = snap.Warmup
	}
	writeJSON(w, http.StatusOK, out)
}
