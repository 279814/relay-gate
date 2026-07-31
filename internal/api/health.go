package api

import (
	"context"
	"net/http"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probe"
	"github.com/279814/relay-gate/internal/router"
)

// HealthView 暴露每个 Route 的健康状态。由 health.Tracker 实现。
type HealthView interface {
	AllStatus() []health.Status
	Status(routeID int64) health.Status
}

// GateView 暴露站级 L1 结论。由 health.UpstreamGate 实现。
type GateView interface {
	Status(upstreamID int64) health.UpstreamStatus
}

// Prober 执行手动探活。由 probe.Scheduler 实现。
type Prober interface {
	ProbeNow(ctx context.Context, snap *router.Snapshot,
		rt *model.Route) (l1, l2 probe.Outcome, err error)
}

// WithHealth 接上健康看板与手动探活。分成单独的 setter，理由同 WithRuntime：
// 这些属于探活链路，而 api.Server 的主职责是配置 CRUD。
func (s *Server) WithHealth(hv HealthView, gate GateView, prober Prober) *Server {
	s.healthView, s.gate, s.prober = hv, gate, prober
	return s
}

// healthRow 是看板上的一行：Route 配置 + 运行时状态 + 它所属站的 L1 结论。
//
// 三者合并成一行而不是让前端自己 join：判断「这个模型为什么不可用」需要
// 同时看这三处 —— Route 被停用、站的 L1 挂了、还是 L2 判死了。分开返回
// 的话，前端要做三次关联，而关联逻辑错了就会显示出误导性的原因。
type healthRow struct {
	RouteID     int64             `json:"route_id"`
	ModelNameID int64             `json:"model_name_id"`
	ModelName   string            `json:"model_name"`
	UpstreamID  int64             `json:"upstream_id"`
	Upstream    string            `json:"upstream"`
	Priority    int               `json:"priority"`
	Weight      int               `json:"weight"`
	Enabled     bool              `json:"enabled"`
	State       model.HealthState `json:"state"`

	// Selectable 是「现在这一刻选路会不会考虑它」的最终答案。
	//
	// 单独给一个字段，因为它不是 state 的同义词：state=unknown 是**可用**的
	// （乐观策略，§2.4），而 alive 的 Route 也可能因为 429 冷却或手动停用
	// 而选不上。只看 state 的界面会让人以为「unknown 就是有问题」。
	Selectable bool   `json:"selectable"`
	Reason     string `json:"reason,omitempty"`

	Health health.Status         `json:"health"`
	L1     health.UpstreamStatus `json:"l1"`
}

// getHealth 返回健康看板（§5.2d：探活状态与成本要可见）。
func (s *Server) getHealth(w http.ResponseWriter, r *http.Request) {
	if s.healthView == nil {
		writeJSON(w, http.StatusServiceUnavailable,
			errBody{"健康视图未接入（探活未启用）"})
		return
	}

	mns, err := s.st.ListModelNames()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	ups, err := s.st.ListUpstreams()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	routes, err := s.st.ListRoutes(0)
	if err != nil {
		s.writeErr(w, err)
		return
	}

	mnByID := make(map[int64]*model.ModelName, len(mns))
	for _, mn := range mns {
		mnByID[mn.ID] = mn
	}
	upByID := make(map[int64]*model.Upstream, len(ups))
	for _, up := range ups {
		upByID[up.ID] = up
	}

	rows := make([]healthRow, 0, len(routes))
	for _, rt := range routes {
		st := s.healthView.Status(rt.ID)
		row := healthRow{
			RouteID: rt.ID, ModelNameID: rt.ModelNameID, UpstreamID: rt.UpstreamID,
			Priority: rt.Priority, Weight: rt.Weight, Enabled: rt.Enabled,
			State: st.State, Health: st,
		}
		if mn := mnByID[rt.ModelNameID]; mn != nil {
			row.ModelName = mn.Name
		}
		up := upByID[rt.UpstreamID]
		if up != nil {
			row.Upstream = up.Name
		}
		if s.gate != nil {
			row.L1 = s.gate.Status(rt.UpstreamID)
		}
		row.Selectable, row.Reason = selectability(rt, up, st)
		rows = append(rows, row)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"routes": rows,
		"summary": map[string]int{
			"total":      len(rows),
			"selectable": countSelectable(rows),
		},
	})
}

// selectability 复述选路的排除条件（§3.4 步骤 4），给界面一个可读的原因。
//
// 必须与 router.viableBuckets 的判定保持一致。不一致的后果是界面说「可用」
// 而请求却 503 —— 那种矛盾会让人怀疑整个看板。
func selectability(rt *model.Route, up *model.Upstream,
	st health.Status) (bool, string) {

	switch {
	case !rt.Enabled:
		return false, "Route 已手动停用"
	case up == nil:
		return false, "Route 指向的 Upstream 已被删除"
	case !up.Enabled:
		return false, "Upstream 已手动停用"
	case st.State == model.StateDead:
		if st.Reason == "fatal" {
			// 分开说很重要：一个要用户去改配置，一个等它自己恢复。
			return false, "判死：配置或鉴权错误（" + st.LastError + "）"
		}
		return false, "判死：服务不可用（" + st.LastError + "）"
	case st.CooldownUntil > 0:
		return false, "限流冷却中"
	}
	return true, ""
}

func countSelectable(rows []healthRow) int {
	var n int
	for _, r := range rows {
		if r.Selectable {
			n++
		}
	}
	return n
}

// probeRoute 手动探活一个 Route（§4.5：UI 手动点「测试」，结果直接展示）。
//
// 同步返回结果。异步的话还得再设计一个「查询上次手动探活结果」的接口，
// 而用户点了按钮就是要立刻看到答案。
func (s *Server) probeRoute(w http.ResponseWriter, r *http.Request) {
	if s.prober == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"探活未启用"})
		return
	}
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

	mns, err := s.st.ListModelNames()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	ups, err := s.st.ListUpstreams()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	routes, err := s.st.ListRoutes(0)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	snap := router.BuildSnapshot(mns, ups, routes)

	// 给手动探活一个独立的时限。不用 r.Context()：浏览器可能在
	// L2 还没跑完时就超时断开，而我们仍然想把这次探活的结果写进状态机 ——
	// 那是用户点这个按钮的主要目的。
	ctx, cancel := context.WithTimeout(context.Background(), manualProbeTimeout)
	defer cancel()

	l1, l2, err := s.prober.ProbeNow(ctx, snap, rt)
	if err != nil {
		s.writeErr(w, model.WrapValidation("%v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"route_id": id,
		"l1":       outcomeJSON(l1),
		"l2":       outcomeJSON(l2),
		"state":    s.healthStateOf(id),
	})
}

// manualProbeTimeout 是手动探活的上限。
//
// 比 L2 的 150s 留一点余量：ProbeNow 是 L1 + L2 串行，两者各有自己的
// 超时，这个值只是防止整体挂住。
const manualProbeTimeout = 200 * time.Second

// outcomeJSON 把探活结果转成前端友好的形状。
func outcomeJSON(o probe.Outcome) map[string]any {
	m := map[string]any{
		"verdict": o.Verdict.String(),
		"status":  o.Status,
		"ttft_ms": o.TTFT.Milliseconds(),
	}
	if o.Err != nil {
		m["error"] = o.Err.Error()
	}
	if o.RetryAfter > 0 {
		m["retry_after_s"] = int(o.RetryAfter.Seconds())
	}
	return m
}

func (s *Server) healthStateOf(routeID int64) model.HealthState {
	if s.healthView == nil {
		return model.StateUnknown
	}
	return s.healthView.Status(routeID).State
}
