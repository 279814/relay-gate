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
	writeJSON(w, http.StatusOK, cur)
}

func (s *Server) deleteModelName(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	// Collect child Route ids before CASCADE so §15 transform bindings can be
	// detached after a successful delete (SQL CASCADE does not touch
	// transform_binding; those rows are keyed only by numeric ids).
	var childRoutes []int64
	if s.transforms != nil {
		if routes, err := s.st.ListRoutes(id); err == nil {
			for _, rt := range routes {
				if rt != nil {
					childRoutes = append(childRoutes, rt.ID)
				}
			}
		}
	}
	// Invalidate before DELETE: RoutesOfModelName reads the live SQL table, and
	// ON DELETE CASCADE removes child Routes with the ModelName. After delete,
	// SemanticConfigInvalidator would see zero route IDs and leave their
	// RouteHealth / RecoveryGate / Capability in memory (§9.2).
	s.invalidateModelName(id)
	if err := s.st.DeleteModelName(id); err != nil {
		s.writeErr(w, err)
		return
	}
	for _, rid := range childRoutes {
		s.detachTransformBindingsForRoute(rid)
	}
	// route 表对 model_name 是 ON DELETE CASCADE；transform_binding 需显式卸绑。
	s.log.Info("删除 model_name（其 route 已级联删除）", "id", id)
	w.WriteHeader(http.StatusNoContent)
}
