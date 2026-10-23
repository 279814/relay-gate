package api

import (
	"net/http"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

func (s *Server) listSecurityDiagnostics(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for key, values := range q {
		switch key {
		case "source", "verdict", "upstream_id", "route_id", "cursor", "limit":
		default:
			s.writeErr(w, model.WrapValidation("未知安全诊断筛选"))
			return
		}
		if len(values) != 1 {
			s.writeErr(w, model.WrapValidation("重复安全诊断筛选"))
			return
		}
	}
	limit, err := queryInt64(q.Get("limit"))
	if err != nil || limit < 0 || limit > store.MaximumPageLimit || len(q.Get("cursor")) > 4096 {
		s.writeErr(w, model.WrapValidation("安全诊断分页无效"))
		return
	}
	upstream, err := queryInt64(q.Get("upstream_id"))
	if err != nil {
		s.writeErr(w, model.WrapValidation("安全诊断上游无效"))
		return
	}
	route, err := queryInt64(q.Get("route_id"))
	if err != nil {
		s.writeErr(w, model.WrapValidation("安全诊断Route无效"))
		return
	}
	page, err := s.st.ListSecurityDiagnostics(r.Context(), store.SecurityDiagnosticFilter{PageRequest: model.PageRequest{Limit: int(limit), Cursor: q.Get("cursor")}, Source: model.CanarySource(q.Get("source")), Verdict: q.Get("verdict"), UpstreamID: upstream, RouteID: route})
	if err != nil {
		s.writeErr(w, err)
		return
	}
	keys, ok := s.diagnosticKeys(w, r)
	if !ok {
		return
	}
	for _, execution := range page.Items {
		*execution = redactExecutionDetail(*execution, keys)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, page)
}
func (s *Server) getSecurityDiagnostic(w http.ResponseWriter, r *http.Request) {
	execution, err := s.st.GetSecurityDiagnostic(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeErr(w, err)
		return
	}
	keys, ok := s.diagnosticKeys(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, redactExecutionDetail(*execution, keys))
}
