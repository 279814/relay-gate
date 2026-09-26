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
	if err := s.publishAfterSuccessfulWrite(); err != nil {
		s.writeErr(w, err)
		return
	}
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
	before := *cur
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
	// §4.5：只有改了探活请求的内容才重探。protocol 也算 —— 它决定
	// 探活打哪个端点、body 用哪种参数名（§3.3.1）。
	if before.ProbePrompt != cur.ProbePrompt ||
		before.ProbeMaxTokens != cur.ProbeMaxTokens ||
		before.Protocol != cur.Protocol ||
		before.Name != cur.Name || // 不映射时 Name 就是发给上游的模型名
		(!before.Enabled && cur.Enabled) {
		s.invalidateModelName(id)
	}
	if err := s.publishAfterSuccessfulWrite(); err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cur)
}

func (s *Server) deleteModelName(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	// Snapshot child Route ids before CASCADE: SQL removes them with the
	// ModelName, but §9.2 Forget still needs the ids. Durable transform_binding
	// rows are dropped inside DeleteModelName's transaction; in-memory bindings
	// are detached around that call — never by bare id after commit.
	// Clear in-memory health only after DeleteModelName succeeds — otherwise a
	// store error would wipe RouteHealth while the rows remain.
	childRoutes := s.routeIDsOfModelName(id)
	var delErr error
	if s.transforms != nil {
		delErr = s.transforms.DetachRouteBindingsAround(childRoutes, func() error {
			return s.st.DeleteModelName(id)
		})
	} else {
		delErr = s.st.DeleteModelName(id)
	}
	if delErr != nil {
		s.writeErr(w, delErr)
		return
	}
	s.forgetRoutesSchedulerHolds(childRoutes)
	s.invalidateModelNameDeleted(id, childRoutes)
	if err := s.publishAfterSuccessfulWrite(); err != nil {
		s.writeErr(w, err)
		return
	}
	// route 表对 model_name 是 ON DELETE CASCADE；transform_binding 已在事务内卸绑。
	s.log.Info("删除 model_name（其 route 已级联删除）", "id", id)
	w.WriteHeader(http.StatusNoContent)
}
