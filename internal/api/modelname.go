package api

import (
	"net/http"

	"github.com/279814/relay-gate/internal/model"
)

func (s *Server) listModelNames(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListModelNames()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) getModelName(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	m, err := s.st.GetModelName(id)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) createModelName(w http.ResponseWriter, r *http.Request) {
	var m model.ModelName
	m.Enabled = true
	if err := decodeJSON(r, &m); err != nil {
		s.writeErr(w, err)
		return
	}
	m.ID = 0
	if err := s.st.CreateModelName(&m); err != nil {
		s.writeErr(w, err)
		return
	}
	s.log.Info("新增 model_name", "id", m.ID, "name", m.Name, "protocol", m.Protocol)
	writeJSON(w, http.StatusCreated, m)
}

func (s *Server) updateModelName(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	cur, err := s.st.GetModelName(id)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if err := decodeJSON(r, cur); err != nil {
		s.writeErr(w, err)
		return
	}
	cur.ID = id
	if err := s.st.UpdateModelName(cur); err != nil {
		s.writeErr(w, err)
		return
	}
	s.log.Info("更新 model_name", "id", id, "name", cur.Name)
	writeJSON(w, http.StatusOK, cur)
}

func (s *Server) deleteModelName(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.st.DeleteModelName(id); err != nil {
		s.writeErr(w, err)
		return
	}
	// route 表对 model_name 是 ON DELETE CASCADE，绑定会一并消失。
	s.log.Info("删除 model_name（其 route 已级联删除）", "id", id)
	w.WriteHeader(http.StatusNoContent)
}
