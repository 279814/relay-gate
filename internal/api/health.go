package api

import (
	"net/http"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probe"
)

// HealthView 暴露每个 Route 的健康状态。由 health.Tracker 实现。
type HealthView interface {
	AllStatus() []health.Status
	Status(routeID int64) health.Status
}

// ReachabilityView exposes committed evidence; it owns no legacy L1 status map.
type ReachabilityView interface {
	Snapshot(int64) *model.UpstreamReachability
	Effective(int64, int64) model.ReachabilityState
}

// CapabilityView exposes the same current endpoint evidence read by routing.
// A health page never substitutes a separately loaded UI capability page.
type CapabilityView interface {
	Effective(scope model.RecipeScope, scopeID int64,
		endpoint model.EndpointKind, expectedToken string) model.CapabilityState
}

var _ CapabilityView = (*probe.CapabilityRegistry)(nil)

// WithHealth 接上健康看板与手动探活。分成单独的 setter，理由同 WithRuntime：
// 这些属于探活链路，而 api.Server 的主职责是配置 CRUD。
func (s *Server) WithHealth(hv HealthView, reach ReachabilityView) *Server {
	s.healthView, s.reachability = hv, reach
	return s
}

func (s *Server) WithManualProbeRunner(runner ManualProbeRunner) *Server {
	s.manualRunner = runner
	return s
}

// WithCapabilities wires model and count_tokens observations from one registry.
// Missing wiring is represented by absent fields, rather than invented unknown.
func (s *Server) WithCapabilities(v CapabilityView) *Server {
	s.capabilities = v
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

	CountTokens model.CapabilityState `json:"count_tokens,omitempty"`
	Endpoint    model.EndpointKind    `json:"endpoint,omitempty"`
	Capability  model.CapabilityState `json:"capability,omitempty"`
	ProbeMode   model.ProbeMode       `json:"probe_mode"`

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
	modelID, err := configIDFilter(r, "model_name_id")
	if err != nil {
		s.writeErr(w, err)
		return
	}

	upstreamID, err := configIDFilter(r, "upstream_id")
	if err != nil {
		s.writeErr(w, err)
		return
	}
	metadata, err := s.configAdmin.ListRouteMetadata(r.Context(), model.RouteFilter{PageRequest: page, Enabled: enabled, ModelNameID: modelID, UpstreamID: upstreamID})
	if err != nil {
		s.writeErr(w, err)
		return
	}
	rows := make([]healthRow, 0, len(metadata.Items))
	for _, entry := range metadata.Items {
		rt := &entry.Route
		st := s.healthView.Status(rt.ID)
		row := healthRow{
			RouteID: rt.ID, ModelNameID: rt.ModelNameID, UpstreamID: rt.UpstreamID,
			Priority: rt.Priority, Weight: rt.Weight, Enabled: rt.Enabled,
			State: st.State, Health: st,
			ModelName: entry.ModelName, Upstream: entry.UpstreamName,
			ProbeMode: entry.UpstreamProbeMode,
		}
		row.Endpoint, _ = entry.ModelProtocol.Endpoint()
		var up *model.Upstream
		if entry.UpstreamExists {
			up = &model.Upstream{ID: rt.UpstreamID, Name: entry.UpstreamName, Enabled: entry.UpstreamEnabled, NetworkRevision: entry.UpstreamNetworkRevision}
		}
		row.L1 = health.UpstreamStatus{UpstreamID: rt.UpstreamID, OK: true}
		if s.reachability != nil && up != nil {
			state := s.reachability.Effective(up.ID, up.NetworkRevision)
			row.L1.OK = state != model.ReachabilityUnreachable
			row.L1.Probed = state != model.ReachabilityUnknown
			if evidence := s.reachability.Snapshot(up.ID); evidence != nil && row.L1.Probed {
				row.L1.LastError = evidence.LastError
				row.L1.LastAt = max(evidence.LastOKAt, evidence.LastErrorAt)
			}
		}
		row.Selectable, row.Reason = selectability(rt, up, st)
		if !entry.ModelExists {
			row.Selectable = false
			row.Reason = "ModelName 已不存在"
		} else if !entry.ModelEnabled {
			row.Selectable = false
			row.Reason = "ModelName 已手动停用"
		}
		if row.Selectable && !row.L1.OK {
			row.Selectable = false
			row.Reason = "Upstream 网络不可达"
		}
		if s.capabilities != nil {
			row.CountTokens = s.capabilities.Effective(model.RecipeScopeRoute, rt.ID,
				model.EndpointCountTokens, "")
			if row.Endpoint != "" {
				row.Capability = s.capabilities.Effective(model.RecipeScopeRoute, rt.ID, row.Endpoint, "")
			}
		}
		rows = append(rows, row)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"routes":      rows,
		"next_cursor": metadata.NextCursor,
		"summary": map[string]any{
			"total":      len(rows),
			"selectable": countSelectable(rows),
			"scope":      "page",
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

// probeRoute delegates exactly one manual execution to the configured service.
// The service owns the validated timeout profile, admission and persistence.
func (s *Server) probeRoute(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	runner := s.manualRunner
	if runner == nil && s.probeAdmin != nil {
		runner = s.probeAdmin
	}
	if runner == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"手动探活服务未装配"})
		return
	}
	execution, err := runner.RunManual(r.Context(), id)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	keys, ok := s.diagnosticKeys(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"execution_id": execution.ID, "execution": redactExecutionDetail(execution, keys), "ok": execution.Success})
}
