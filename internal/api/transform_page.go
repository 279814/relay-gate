package api

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/279814/relay-gate/internal/model"
)

func parseTransformQuery(r *http.Request, allowed ...string) (url.Values, error) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, model.WrapValidation("转换查询参数无效")
	}
	for key, items := range values {
		known := false
		for _, name := range allowed {
			if key == name {
				known = true
				break
			}
		}
		if !known || len(items) != 1 {
			return nil, model.WrapValidation("转换查询包含未知或重复参数")
		}
	}
	return values, nil
}
func transformPageRequest(query url.Values) (model.PageRequest, error) {
	page := model.PageRequest{Cursor: query.Get("cursor")}
	if raw, ok := query["limit"]; ok {
		value, err := strconv.Atoi(raw[0])
		if err != nil || value < 1 || value > 200 {
			return page, model.WrapValidation("limit 必须为1–200")
		}
		page.Limit = value
	}
	return page, nil
}
func optionalTransformID(query url.Values, name string) (int64, error) {
	raw, ok := query[name]
	if !ok {
		return 0, nil
	}
	value, err := strconv.ParseInt(raw[0], 10, 64)
	if err != nil || value < 1 {
		return 0, model.WrapValidation("转换资源ID必须为正整数")
	}
	return value, nil
}
func (s *Server) listTransformVersions(w http.ResponseWriter, r *http.Request) {
	if s.st == nil || s.transforms == nil {
		writeJSON(w, 503, errBody{"transform store unavailable"})
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if _, err := s.transforms.GetSet(id); err != nil {
		s.writeErr(w, storeNotFound(err))
		return
	}
	query, err := parseTransformQuery(r, "mode", "limit", "cursor")
	if err != nil {
		s.writeErr(w, err)
		return
	}
	pageRequest, err := transformPageRequest(query)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	page, err := s.st.ListTransformVersionsPage(r.Context(), model.TransformVersionFilter{PageRequest: pageRequest, SetID: id, Mode: query.Get("mode")})
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"versions": page.Items, "total": page.Total, "next_cursor": page.NextCursor, "limit": page.Limit})
}
func (s *Server) getTransformVersion(w http.ResponseWriter, r *http.Request) {
	if s.st == nil {
		writeJSON(w, 503, errBody{"transform store unavailable"})
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	version, err := s.st.GetTransformVersion(r.Context(), id)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, 200, version)
}
