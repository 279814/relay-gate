package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/security"
)

// WithSecurityCenter injects the P3 Security Center.
func (s *Server) WithSecurityCenter(c *security.Center) *Server {
	s.security = c
	return s
}

func (s *Server) listSecurityFindings(w http.ResponseWriter, r *http.Request) {
	if s.security == nil {
		writeJSON(w, http.StatusOK, map[string]any{"findings": []any{}, "total": 0})
		return
	}
	sev := security.Severity(r.URL.Query().Get("severity"))
	limit, err := queryInt64(r.URL.Query().Get("limit"))
	if err != nil {
		s.writeErr(w, fmt.Errorf("%w: limit", model.ErrValidation))
		return
	}
	if r.URL.Query().Get("limit") == "" {
		limit = 50
	}
	list := s.security.List(sev, int(limit))
	writeJSON(w, http.StatusOK, map[string]any{
		"findings": list,
		"total":    s.security.Count(),
	})
}

// postSecurityScan runs a passive scan on caller-provided plain text (admin diagnostic).
// Never echoes HTML — response is JSON of findings; UI must render with x-text.
func (s *Server) postSecurityScan(w http.ResponseWriter, r *http.Request) {
	if s.security == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"security center unavailable"})
		return
	}
	var body struct {
		Text     string `json:"text"`
		Upstream string `json:"upstream"`
		ReqID    string `json:"req_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	found := security.ScanText(body.Text, "admin_scan")
	out := make([]security.Finding, 0, len(found))
	for _, f := range found {
		f.Upstream = body.Upstream
		f.ReqID = body.ReqID
		out = append(out, s.security.Record(f))
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": out, "count": len(out)})
}

// postSecurityCanary is a manual canary trigger gate (§14.4).
// Lazy upstreams are rejected; no model call is made in this PR (deferred SMTP/canary send).
func (s *Server) postSecurityCanary(w http.ResponseWriter, r *http.Request) {
	var body struct {
		UpstreamID int64  `json:"upstream_id"`
		ProbeMode  string `json:"probe_mode"`
		Note       string `json:"note"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	mode := model.ProbeMode(strings.ToLower(body.ProbeMode))
	if mode == model.ProbeModeLazy {
		writeJSON(w, http.StatusBadRequest, errBody{"Lazy Upstream 禁止周期/自动 canary；请先切 Active 或仅用被动扫描"})
		return
	}
	if s.security != nil {
		s.security.Record(security.Finding{
			Severity: security.SeverityInfo,
			Category: "canary_manual",
			Summary:  "手动 canary 已记录（本 PR 不发上游请求）",
			Detail:   strings.TrimSpace(body.Note),
			Source:   "canary",
			RouteID:  body.UpstreamID,
		})
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"accepted": true,
		"mode":     "manual_record_only",
		"note":     "主动 canary 上游调用与 SMTP 告警在 docs/07 Deferred",
	})
}
