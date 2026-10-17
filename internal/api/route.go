package api

import (
	"net/http"

	"github.com/279814/relay-gate/internal/model"
)

func (s *Server) listRoutes(w http.ResponseWriter, r *http.Request) {
	page, err := configPage(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	enabled, err := configEnabled(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	mnID, err := configIDFilter(r, "model_name_id")
	if err != nil {
		s.writeErr(w, err)
		return
	}
	upID, err := configIDFilter(r, "upstream_id")
	if err != nil {
		s.writeErr(w, err)
		return
	}
	list, err := s.configAdmin.ListRoutes(r.Context(), model.RouteFilter{PageRequest: page, Enabled: enabled, ModelNameID: mnID, UpstreamID: upID})
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
	rt, err := s.configAdmin.GetRoute(r.Context(), id)
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
	created, err := s.configAdmin.CreateRoute(r.Context(), rt)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	rt = created
	s.log.Info("新增 route", "id", rt.ID, "model_name_id", rt.ModelNameID,
		"upstream_id", rt.UpstreamID, "priority", rt.Priority)
	// §4.5：新建的 Route 立刻探一次。这是最该探的时刻 —— 用户刚配好，
	// 想知道的正是「这个映射到底通不通」。不探的话它会以 unknown 状态
	// 直接参与选路（乐观策略），真实请求撞上去才发现配错了。
	s.invalidateRoute(rt.ID)
	if !s.publishConfigResource(w, rt.ID, rt.Revision) {
		return
	}
	writeJSON(w, http.StatusCreated, rt)
}

func (s *Server) updateRoute(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	current, err := s.configAdmin.GetRoute(r.Context(), id)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	cur := &current
	before := *cur
	in := struct {
		*model.Route
		ExpectedRevision int64 `json:"expected_revision"`
	}{Route: cur}
	if err := decodeJSON(r, &in); err != nil {
		s.writeErr(w, err)
		return
	}
	if err := requireRevision(in.ExpectedRevision); err != nil {
		s.writeErr(w, err)
		return
	}
	cur.ID = id
	updated, err := s.configAdmin.UpdateRoute(r.Context(), id, in.ExpectedRevision, *cur)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	*cur = updated
	s.log.Info("更新 route", "id", id, "priority", cur.Priority)
	// §4.5：只有改了模型映射或指向的站才需要重探 —— 那两项决定探活
	// 打的是哪个模型、哪个站。改 priority / weight 只影响选路的偏好，
	// 探活结果一模一样，重探纯属浪费一次请求。
	// 仅把 Enabled 从 false 翻回 true：发布 livecfg，并 Forget 停用前留下的
	// dead/cooldown，但不调度合成探活或校准。
	if !before.Enabled && cur.Enabled {
		s.forgetHealthOnReEnableRoute(id)
	}
	if before.UpstreamModel != cur.UpstreamModel ||
		before.UpstreamID != cur.UpstreamID ||
		before.ModelNameID != cur.ModelNameID {
		s.invalidateRoute(id)
	}
	if !s.publishConfigResource(w, id, cur.Revision) {
		return
	}
	writeJSON(w, http.StatusOK, cur)
}

func (s *Server) deleteRoute(w http.ResponseWriter, r *http.Request) {
	revision, err := deleteRevision(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	// §15: durable transform_binding rows are dropped inside DeleteRoute's SQL
	// transaction. In-memory bindings are detached around that call and
	// restored if it fails — never by bare id after commit (id reuse race).
	var delErr error
	if s.transforms != nil {
		delErr = s.transforms.DetachRouteBindingsAround([]int64{id}, func() error {
			return s.configAdmin.DeleteRoute(r.Context(), id, revision)
		})
	} else {
		delErr = s.configAdmin.DeleteRoute(r.Context(), id, revision)
	}
	if delErr != nil {
		s.writeErr(w, delErr)
		return
	}
	// Drop L2 scheduler holds before InvalidateRoute: otherwise an in-flight
	// probe leaves inflightL2/pendingL2 set and a reused rowid is skipped.
	s.forgetRouteSchedulerHolds(id)
	// §9.2 / Forget：删掉 SQL 行不够。内存 RouteHealth / RecoveryGate /
	// Capability 仍按 id 索引；若不 Forget，调度器 RetainOnly 之前（或 id
	// 被复用时）新行会继承 StateDead / 旧 capability。
	s.invalidateRoute(id)
	if !s.publishConfigResource(w, id, revision) {
		return
	}
	s.log.Info("删除 route", "id", id)
	w.WriteHeader(http.StatusNoContent)
}
