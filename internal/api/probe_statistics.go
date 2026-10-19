package api

import (
	"net/http"

	"github.com/279814/relay-gate/internal/model"
)

func (s *Server) getProbeStatistics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	allowed := map[string]bool{"basis": true, "scope": true, "day_from": true, "day_to": true, "route_id": true, "upstream_id": true, "endpoint": true, "trigger": true, "origin": true, "storage": true, "recipe_id": true, "version_id": true, "profile_id": true, "template_id": true, "identity_revision": true, "limit": true, "cursor": true}
	q := &probeListQuery{r: r}
	for name, values := range r.URL.Query() {
		if !allowed[name] {
			q.reject("query")
		} else if len(values) != 1 {
			q.reject(name)
		}
	}
	filter := model.ProbeStatisticsFilter{PageRequest: q.page(), Basis: q.oneOf("basis", "executions", "daily"), Scope: q.oneOf("scope", "route", "upstream"), DayFrom: q.day("day_from"), DayTo: q.day("day_to"), RouteID: q.id("route_id"), UpstreamID: q.id("upstream_id"),
		Endpoint: probeEnum(q, "endpoint", model.EndpointKind.Valid), Trigger: probeEnum(q, "trigger", model.ProbeTrigger.Valid), Origin: probeEnum(q, "origin", model.RecipeSource.Valid), Storage: model.RecipeStorageKind(q.oneOf("storage", "db", "profile", "embedded")), RecipeID: q.id("recipe_id"), VersionID: q.id("version_id"), ProfileID: q.id("profile_id"), IdentityRevision: q.id("identity_revision"), TemplateID: q.text("template_id")}
	if q.err != nil {
		s.writeErr(w, q.err)
		return
	}
	page, err := s.st.ListProbeStatistics(r.Context(), filter)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}
