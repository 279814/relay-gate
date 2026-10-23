package api

import (
	"net/http"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/security"
	"github.com/279814/relay-gate/internal/store"
)

func securityBooleanFilter(value string) (*bool, error) {
	if value == "" {
		return nil, nil
	}
	if value != "true" && value != "false" {
		return nil, model.WrapValidation("安全管理布尔筛选无效")
	}
	parsed := value == "true"
	return &parsed, nil
}

func (s *Server) listSecurityIgnoreRules(w http.ResponseWriter, r *http.Request) {
	if s.st == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"persistent security policy unavailable"})
		return
	}
	q := r.URL.Query()
	for name, values := range q {
		switch name {
		case "scope", "route_id", "rule_id", "active", "limit", "cursor":
		default:
			s.writeErr(w, model.WrapValidation("未知的忽略规则筛选字段"))
			return
		}
		if len(values) != 1 {
			s.writeErr(w, model.WrapValidation("忽略规则筛选字段不可重复"))
			return
		}
	}
	active, err := securityBooleanFilter(q.Get("active"))
	if err != nil {
		s.writeErr(w, err)
		return
	}
	limit, err := queryInt64(q.Get("limit"))
	if err != nil || limit < 0 || limit > store.MaximumPageLimit || len(q.Get("cursor")) > 4096 {
		s.writeErr(w, model.WrapValidation("忽略规则分页无效"))
		return
	}
	routeID, err := queryInt64(q.Get("route_id"))
	if err != nil {
		s.writeErr(w, model.WrapValidation("忽略规则 Route 无效"))
		return
	}
	page, err := s.st.ListSecurityIgnoreRules(r.Context(), store.SecurityIgnoreFilter{PageRequest: model.PageRequest{Limit: int(limit), Cursor: q.Get("cursor")},
		Scope: q.Get("scope"), RuleID: q.Get("rule_id"), RouteID: routeID, Active: active})
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) reviewSecurityFinding(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ExpectedRevision int64  `json:"expected_revision"`
		Status           string `json:"status"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	review, err := s.st.ReviewSecurityFinding(r.Context(), r.PathValue("id"), body.Status, body.ExpectedRevision)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, review)
}

func (s *Server) saveSecurityIgnoreRule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ExpectedRevision int64  `json:"expected_revision"`
		Scope            string `json:"scope"`
		RuleID           string `json:"rule_id"`
		RouteID          int64  `json:"route_id"`
		ExpiresAtMS      int64  `json:"expires_at_ms"`
		Enabled          *bool  `json:"enabled"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	rule := security.IgnoreRule{Scope: body.Scope, RuleID: body.RuleID, RouteID: body.RouteID, ExpiresAtMS: body.ExpiresAtMS, Enabled: true}
	if body.Enabled != nil {
		rule.Enabled = *body.Enabled
	}
	var err error
	status := http.StatusCreated
	if r.Method == http.MethodPost {
		rule, err = s.st.CreateSecurityIgnoreRule(r.Context(), rule)
	} else {
		var id int64
		id, err = pathID(r)
		if err == nil {
			rule, err = s.st.UpdateSecurityIgnoreRule(r.Context(), id, body.ExpectedRevision, rule)
		}
		status = http.StatusOK
	}
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, status, rule)
}

func (s *Server) deleteSecurityIgnoreRule(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	var body struct {
		ExpectedRevision int64 `json:"expected_revision"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.st.DeleteSecurityIgnoreRule(r.Context(), id, body.ExpectedRevision); err != nil {
		s.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getSecurityAlertStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.mailer == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"mailer unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, s.mailer.Status())
}
