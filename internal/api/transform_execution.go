package api

import (
	"net/http"
	"strconv"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/transform"
)

func (s *Server) listTransformExecutions(w http.ResponseWriter, r *http.Request) {
	query, err := parseTransformQuery(r, "route_id", "endpoint_id", "version_id", "mode", "phase", "ok", "after_ms", "before_ms", "limit", "cursor")
	if err != nil {
		s.writeErr(w, err)
		return
	}
	page, err := transformPageRequest(query)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	filter := transform.ExecutionFilter{Mode: query.Get("mode"), Phase: query.Get("phase")}
	for _, field := range []struct {
		name   string
		target *int64
	}{{"route_id", &filter.RouteID}, {"endpoint_id", &filter.EndpointID}, {"version_id", &filter.VersionID}, {"after_ms", &filter.AfterMS}, {"before_ms", &filter.BeforeMS}} {
		value, e := optionalTransformID(query, field.name)
		if e != nil {
			s.writeErr(w, e)
			return
		}
		*field.target = value
	}
	if value, ok := query["ok"]; ok {
		if value[0] != "true" && value[0] != "false" {
			s.writeErr(w, model.WrapValidation("ok 必须为 true 或 false"))
			return
		}
		parsed, _ := strconv.ParseBool(value[0])
		filter.OK = &parsed
	}
	if filter.Mode != "" && filter.Mode != "preview" && filter.Mode != "published" && filter.Mode != "shadow" ||
		filter.Phase != "" && filter.Phase != "request" && filter.Phase != "response" && filter.Phase != "sse" ||
		filter.AfterMS > 0 && filter.BeforeMS > 0 && filter.AfterMS > filter.BeforeMS {
		s.writeErr(w, model.WrapValidation("执行诊断筛选无效"))
		return
	}
	registry := s.transforms
	if registry == nil {
		registry = transform.NewRegistry(1)
	}
	result, err := registry.ExecutionsPage(filter, page.Limit, page.Cursor)
	if err != nil {
		s.writeErr(w, model.WrapValidation("%s", err))
		return
	}
	writeJSON(w, http.StatusOK, result)
}
