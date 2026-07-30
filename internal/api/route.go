package api

import (
	"net/http"
	"strconv"

	"github.com/279814/relay-gate/internal/model"
)

func (s *Server) listRoutes(w http.ResponseWriter, r *http.Request) {
	// ?model_name_id=N 过滤，便于 UI 在 ModelName 详情页只取相关 Route
	var mnID int64
	if v := r.URL.Query().Get("model_name_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			s.writeErr(w, model.WrapValidation("model_name_id 不合法"))
			return
		}
		mnID = n
	}
	list, err := s.st.ListRoutes(mnID)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) getRoute(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	rt, err := s.st.GetRoute(id)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rt)
}

func (s *Server) createRoute(w http.ResponseWriter, r *http.Request) {
	var rt model.Route
	rt.Enabled = true
	if err := decodeJSON(r, &rt); err != nil {
		s.writeErr(w, err)
		return
	}
	rt.ID = 0
	if err := s.st.CreateRoute(&rt); err != nil {
		s.writeErr(w, err)
		return
	}
	s.log.Info("新增 route", "id", rt.ID, "model_name_id", rt.ModelNameID,
		"upstream_id", rt.UpstreamID, "priority", rt.Priority)
	writeJSON(w, http.StatusCreated, rt)
}

func (s *Server) updateRoute(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	cur, err := s.st.GetRoute(id)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if err := decodeJSON(r, cur); err != nil {
		s.writeErr(w, err)
		return
	}
	cur.ID = id
	if err := s.st.UpdateRoute(cur); err != nil {
		s.writeErr(w, err)
		return
	}
	s.log.Info("更新 route", "id", id, "priority", cur.Priority)
	writeJSON(w, http.StatusOK, cur)
}

func (s *Server) deleteRoute(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.st.DeleteRoute(id); err != nil {
		s.writeErr(w, err)
		return
	}
	s.log.Info("删除 route", "id", id)
	w.WriteHeader(http.StatusNoContent)
}
