package api

import (
	"context"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/security"
)

type CanaryRunner interface {
	RunCanary(context.Context, int64) (model.ProbeExecution, error)
}

func (s *Server) postSecurityCanary(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var body struct {
		RouteID    int64  `json:"route_id"`
		UpstreamID int64  `json:"upstream_id"`
		Note       string `json:"note"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	if body.RouteID <= 0 || body.UpstreamID < 0 {
		s.writeErr(w, model.WrapValidation("Canary 必须指定正数 route_id"))
		return
	}
	runner, ok := s.probeAdmin.(CanaryRunner)
	if !ok || s.st == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"Canary 执行器未装配，未发送诊断"})
		return
	}
	route, err := s.st.GetRoute(body.RouteID)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if body.UpstreamID != 0 && body.UpstreamID != route.UpstreamID {
		s.writeErr(w, model.WrapValidation("Canary Route 不属于指定 Upstream"))
		return
	}
	execution, err := runner.RunCanary(r.Context(), body.RouteID)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if execution.ID == "" || execution.Canary == nil || execution.Canary.ExecutionID != execution.ID {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"Canary 未提供持久诊断事实"})
		return
	}
	if s.security != nil {
		note := strings.TrimSpace(body.Note)
		if len(note) > maxFindingClientField {
			note = note[:maxFindingClientField]
		}
		for !utf8.ValidString(note) {
			note = note[:len(note)-1]
		}
		severity := security.SeverityInfo
		if execution.Canary.Verdict != "passed" {
			severity = security.SeverityMedium
		}
		s.security.Record(security.Finding{Severity: severity, Category: "canary_manual", Summary: "手动 Canary 已执行", Detail: note, Source: "canary", RouteID: route.ID})
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": true, "mode": "manual", "route_id": route.ID, "execution_id": execution.ID,
		"success": execution.Canary.Verdict == "passed", "probe_success": execution.Success, "status_code": execution.StatusCode, "error_class": execution.ErrorClass, "canary": execution.Canary})
}

func (s *Server) getCanaryPolicy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	policy, err := s.st.GetCanaryPolicy(r.Context(), id)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (s *Server) putCanaryPolicy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	var body struct {
		RouteID     int64  `json:"route_id"`
		Enabled     bool   `json:"enabled"`
		IntervalSec int    `json:"interval_sec"`
		Revision    *int64 `json:"revision"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	if body.Revision == nil {
		s.writeErr(w, model.WrapValidation("Canary policy 必须提供当前 revision"))
		return
	}
	policy, err := s.st.SaveCanaryPolicy(r.Context(), model.CanaryPolicy{UpstreamID: id, RouteID: body.RouteID, Enabled: body.Enabled, IntervalSec: body.IntervalSec, Revision: *body.Revision})
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}
