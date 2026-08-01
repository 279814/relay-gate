package api

import (
	"github.com/279814/relay-gate/internal/model"
)

// ConfigInvalidator 在配置变更后立即触发相关 Route 的探活（§4.5 表格第 3 行）。
//
// 由 probe.Scheduler 实现。
type ConfigInvalidator interface {
	// InvalidateRoute 触发单个 Route 的 L1 + L2。
	InvalidateRoute(routeID int64)
	// InvalidateUpstream 触发某个 Upstream 下所有 Route 的 L1 + L2。
	// 改 key、改 base_url、改探活头都属于这一类：影响的是整站。
	InvalidateUpstream(upstreamID int64)
	// InvalidateModelName 触发某个 ModelName 下所有 Route 的 L2。
	// 改 probe_prompt / probe_max_tokens 只影响 L2 的内容，L1 与它无关。
	InvalidateModelName(modelNameID int64)
}

// WithInvalidator 接上配置变更钩子（§4.5）。
//
// ── 为什么这个钩子不违反 livecfg 的「不做写后失效」原则 ──
//
// livecfg/source.go 明确拒绝了写后失效通知，理由是「钩子漏一处就是
// 改了不生效」。那个判断没有变，这里也没有推翻它：
//
//   - 配置**生效**仍然只靠 livecfg 的 2s TTL。这个钩子一行配置都不刷新，
//     漏调它不会让任何配置失效延迟哪怕一毫秒。
//   - 钩子只做一件事：把探活的预占时间清零，让下一个 tick 立刻重探。
//     漏调的后果是「等下一个探活周期」—— 也就是退回到 M3/M4 的现状，
//     一个纯粹的时间差，不是错误状态。
//
// 两者的代价完全不对称，所以能挂钩子的地方就是这里、而不是缓存层。
func (s *Server) WithInvalidator(inv ConfigInvalidator) *Server {
	s.invalidator = inv
	return s
}

// 下面三个是各写入路径的调用点。集中在这里而不是散在
// upstream.go / route.go / modelname.go 里，是为了能一眼看全
// 「哪些变更会触发探活」—— 散开的话，判断「改这个字段会不会重探」
// 要翻三个文件。

func (s *Server) invalidateRoute(routeID int64) {
	if s.invalidator != nil {
		s.invalidator.InvalidateRoute(routeID)
	}
}

func (s *Server) invalidateUpstream(upstreamID int64) {
	if s.invalidator != nil {
		s.invalidator.InvalidateUpstream(upstreamID)
	}
}

func (s *Server) invalidateModelName(modelNameID int64) {
	if s.invalidator != nil {
		s.invalidator.InvalidateModelName(modelNameID)
	}
}

// probeAffectingUpstream 判断一次 Upstream 更新是否值得重探。
//
// 不是所有字段都影响探活结果：改个 name 只是标签，重探纯属浪费一次请求
// （而 §5.2d 刚刚才让这些请求变得可见）。只在真正影响「能不能连上、
// 鉴权过不过」的字段变化时才触发。
//
// enabled 不在这里判：它由调用方单独处理 —— 从停用变启用要探（那是
// 「刚配好，想知道通不通」的时刻），而启用变停用不必探（都停了）。
func probeAffectingUpstream(before, after *model.Upstream) bool {
	if before.BaseURL != after.BaseURL ||
		before.APIKey != after.APIKey ||
		before.AuthStyle != after.AuthStyle ||
		before.FullURLMode != after.FullURLMode ||
		before.ProxyURL != after.ProxyURL ||
		before.L1Path != after.L1Path {
		return true
	}
	return !sameHeaders(before.ProbeHeaders, after.ProbeHeaders)
}

func sameHeaders(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}
