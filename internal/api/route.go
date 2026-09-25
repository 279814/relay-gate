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
	// §4.5：新建的 Route 立刻探一次。这是最该探的时刻 —— 用户刚配好，
	// 想知道的正是「这个映射到底通不通」。不探的话它会以 unknown 状态
	// 直接参与选路（乐观策略），真实请求撞上去才发现配错了。
	s.invalidateRoute(rt.ID)
	if err := s.publishAfterSuccessfulWrite(); err != nil {
		s.writeErr(w, err)
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
	cur, err := s.st.GetRoute(id)
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
	if err := s.st.UpdateRoute(cur); err != nil {
		s.writeErr(w, err)
		return
	}
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
	if err := s.publishAfterSuccessfulWrite(); err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cur)
}

func (s *Server) deleteRoute(w http.ResponseWriter, r *http.Request) {
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
			return s.st.DeleteRoute(id)
		})
	} else {
		delErr = s.st.DeleteRoute(id)
	}
	if delErr != nil {
		s.writeErr(w, delErr)
		return
	}
	// §9.2 / Forget：删掉 SQL 行不够。内存 RouteHealth / RecoveryGate /
	// Capability 仍按 id 索引；若不 Forget，调度器 RetainOnly 之前（或 id
	// 被复用时）新行会继承 StateDead / 旧 capability。
	s.invalidateRoute(id)
	if err := s.publishAfterSuccessfulWrite(); err != nil {
		s.writeErr(w, err)
		return
	}
	s.log.Info("删除 route", "id", id)
	w.WriteHeader(http.StatusNoContent)
}
