package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

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
	cur, revision, err := s.st.GetSettingsWithRevision()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	cur, err = decodeSettingsUpdate(r, cur)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if _, err := s.st.SaveSettingsWithRevision(cur, revision); err != nil {
		s.writeErr(w, err)
		return
	}
	// Settings live in the same livecfg PublishedConfig preamble reads
	// (timeouts, retry_policy, sample knobs). Without Invalidate+Refresh the
	// next new request can keep the pre-write values for up to DefaultTTL.
	if err := s.publishAfterSuccessfulWrite(); err != nil {
		s.writeErr(w, err)
		return
	}
	s.log.Info("更新全局设置", "real_first_token_sec", cur.RealFirstTokenSec,
		"sample_enabled", cur.SampleEnabled)
	writeJSON(w, http.StatusOK, cur)
}

// A partial update starts from one captured revision. Legacy aliases expand
// only when explicitly supplied, and explicit stage fields take precedence.
func decodeSettingsUpdate(r *http.Request, current model.Settings) (model.Settings, error) {
	var raw json.RawMessage
	if err := decodeJSON(r, &raw); err != nil {
		return current, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&current); err != nil {
		return current, model.WrapValidation("请求体不是合法 JSON")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return current, model.WrapValidation("请求体不是合法 JSON")
	}
	present := func(name string) bool {
		for key, value := range fields {
			// Match encoding/json's case-insensitive field names and its
			// existing null-as-no-change behavior for numeric Settings.
			if strings.EqualFold(key, name) && !bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return true
			}
		}
		return false
	}
	fillUnspecified := func(name string, target *int, value int) {
		if !present(name) {
			*target = value
		}
	}
	if present("real_first_token_sec") {
		fillUnspecified("real_response_header_sec", &current.RealResponseHeaderSec, current.RealFirstTokenSec)
		fillUnspecified("real_first_byte_sec", &current.RealFirstByteSec, current.RealFirstTokenSec)
		fillUnspecified("real_first_semantic_sec", &current.RealFirstSemanticSec, current.RealFirstTokenSec)
	}
	if present("l2_first_token_sec") {
		fillUnspecified("l2_response_header_sec", &current.L2ResponseHeaderSec, current.L2FirstTokenSec)
		fillUnspecified("l2_first_byte_sec", &current.L2FirstByteSec, current.L2FirstTokenSec)
		fillUnspecified("l2_first_event_sec", &current.L2FirstEventSec, current.L2FirstTokenSec)
		fillUnspecified("l2_first_semantic_sec", &current.L2FirstSemanticSec, current.L2FirstTokenSec)
	}
	if present("count_tokens_sec") {
		fillUnspecified("count_tokens_connect_sec", &current.CountTokensConnectSec, current.CountTokensSec)
		fillUnspecified("count_tokens_total_sec", &current.CountTokensTotalSec, current.CountTokensSec)
	}
	// Persisted settings omit aliases; match their canonical read-side values
	// in the unchanged Settings response as well.
	current.RealFirstTokenSec = current.RealFirstSemanticSec
	current.L2FirstTokenSec = current.L2FirstSemanticSec
	current.CountTokensSec = current.CountTokensTotalSec
	return current, nil
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
		"state":       string(snap.State),
		"effective":   snap.Effective(),
		"revision":    snap.Revision,
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
