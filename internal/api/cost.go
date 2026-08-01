package api

import (
	"net/http"

	"github.com/279814/relay-gate/internal/probe"
)

// CostView 暴露探活成本快照。由 probe.Cost 实现。
type CostView interface {
	Snapshot() probe.CostSnapshot
}

// WithCost 接上探活成本视图（§5.2d）。
func (s *Server) WithCost(c CostView) *Server {
	s.cost = c
	return s
}

// getProbeCost 返回今日探活开销（§5.2d：L1/L2 次数、估算 token、各 Route 明细）。
//
// 附上当前的探活间隔配置：光看「今天探了 4300 次」无法判断这是否过激，
// 要同时知道间隔是多少、有几个 Route 在 dead 状态（dead 站的间隔短得多）。
// 让前端自己再拉一次 settings 也行，但那两个数字必须一起看才有意义，
// 分两次请求就给了它们不一致的机会。
func (s *Server) getProbeCost(w http.ResponseWriter, r *http.Request) {
	if s.cost == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"探活成本统计未接入（探活未启用）"})
		return
	}
	settings, err := s.st.GetSettings()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"cost": s.cost.Snapshot(),
		"intervals": map[string]int{
			"l1_alive_sec": settings.L1IntervalAliveSec,
			"l1_dead_sec":  settings.L1IntervalDeadSec,
			"l2_alive_sec": settings.L2IntervalAliveSec,
			"l2_dead_sec":  settings.L2IntervalDeadSec,
		},
		"probe_enabled":     settings.ProbeEnabled,
		"piggyback_enabled": settings.PiggybackEnabled,
	})
}
