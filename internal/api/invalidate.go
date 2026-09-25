package api

import (
	"github.com/279814/relay-gate/internal/model"
)

// ConfigInvalidator 在配置变更后立即触发相关 Route 的探活（§4.5 表格第 3 行）。
//
// 由 probe.Scheduler 实现；P1 起亦可由 SemanticInvalidator 包装，同时清
// RouteHealth / RecoveryGate / Capability / 学习引用（§9.2）。
type ConfigInvalidator interface {
	// InvalidateRoute 触发单个 Route 的 L1 + L2。
	InvalidateRoute(routeID int64)
	// InvalidateUpstream 触发某个 Upstream 下所有 Route 的 L1 + L2。
	// 改 key、改 base_url、改探活头都属于这一类：影响的是整站。
	InvalidateUpstream(upstreamID int64)
	// InvalidateModelName 清除该 ModelName 下所有 Route 的 §9.2 运行时状态，
	// 并触发 L2（改 Protocol / Name / probe_prompt 等；L1 与它无关）。
	InvalidateModelName(modelNameID int64)
}

// SemanticConfigInvalidator clears §9.2 runtime state then delegates schedule invalidation.
type SemanticConfigInvalidator struct {
	Semantic interface {
		InvalidateRoute(routeID int64)
		InvalidateUpstream(upstreamID int64, routeIDs []int64)
		InvalidateModelName(modelNameID int64, routeIDs []int64)
	}
	Inner             ConfigInvalidator
	RoutesOfUpstream  func(upstreamID int64) []int64
	RoutesOfModelName func(modelNameID int64) []int64
}

func (s *SemanticConfigInvalidator) InvalidateRoute(routeID int64) {
	if s == nil {
		return
	}
	if s.Semantic != nil {
		s.Semantic.InvalidateRoute(routeID)
	}
	if s.Inner != nil {
		s.Inner.InvalidateRoute(routeID)
	}
}

func (s *SemanticConfigInvalidator) InvalidateUpstream(upstreamID int64) {
	if s == nil {
		return
	}
	var routeIDs []int64
	if s.RoutesOfUpstream != nil {
		routeIDs = s.RoutesOfUpstream(upstreamID)
	}
	if s.Semantic != nil {
		s.Semantic.InvalidateUpstream(upstreamID, routeIDs)
	}
	if s.Inner != nil {
		s.Inner.InvalidateUpstream(upstreamID)
	}
}

func (s *SemanticConfigInvalidator) InvalidateModelName(modelNameID int64) {
	if s == nil {
		return
	}
	var routeIDs []int64
	if s.RoutesOfModelName != nil {
		routeIDs = s.RoutesOfModelName(modelNameID)
	}
	if s.Semantic != nil {
		s.Semantic.InvalidateModelName(modelNameID, routeIDs)
	}
	if s.Inner != nil {
		s.Inner.InvalidateModelName(modelNameID)
	}
}

// InvalidateUpstreamDeleted clears §9.2 state after a successful Upstream delete.
//
// routeIDs must be snapshotted before CASCADE — after DeleteUpstream the SQL
// rows are gone, so RoutesOfUpstream would return nil and leave dead RouteHealth.
func (s *SemanticConfigInvalidator) InvalidateUpstreamDeleted(upstreamID int64, routeIDs []int64) {
	if s == nil {
		return
	}
	if s.Semantic != nil {
		s.Semantic.InvalidateUpstream(upstreamID, routeIDs)
	}
	if s.Inner != nil {
		s.Inner.InvalidateUpstream(upstreamID)
	}
}

// InvalidateModelNameDeleted clears §9.2 state after a successful ModelName delete.
//
// routeIDs must be snapshotted before CASCADE — same id-reuse hole as Upstream.
func (s *SemanticConfigInvalidator) InvalidateModelNameDeleted(modelNameID int64, routeIDs []int64) {
	if s == nil {
		return
	}
	if s.Semantic != nil {
		s.Semantic.InvalidateModelName(modelNameID, routeIDs)
	}
	if s.Inner != nil {
		s.Inner.InvalidateModelName(modelNameID)
	}
}

// ConfigPublisher 发布 livecfg 同代 routing + Probe 快照（§4.9）。
//
// livecfg.Source 实现本接口。Upstream / ModelName / Route 的成功
// create/update/delete 必须在 SQL 成功后 Invalidate+Refresh，否则 2s TTL
// 内下一次 preamble/Select 仍可能看到旧 enabled、旧路由或已删行
// （docs/01 §6.4 候选须启用；§9.2 内存立即失效不等待 livecfg TTL）。
type ConfigPublisher interface {
	Invalidate()
	Refresh() error
}

// WithInvalidator 接上配置变更钩子（§4.5）。
//
// 本钩子只触发探活 / §9.2 健康失效，不刷新 livecfg routing 快照。
// routing 可见性由 ConfigPublisher（publishAfterSuccessfulWrite）负责：
// 漏调 invalidator 只是「等下一个探活周期」；漏调 publisher 则是
// 「写成功但新请求仍按旧快照选路」—— 那是错误状态。
func (s *Server) WithInvalidator(inv ConfigInvalidator) *Server {
	s.invalidator = inv
	return s
}

// WithConfigPublisher wires livecfg publish-after-write (§4.9 / docs/01 §6.4).
func (s *Server) WithConfigPublisher(p ConfigPublisher) *Server {
	s.publisher = p
	return s
}

// publishAfterSuccessfulWrite forces the next select/preamble snapshot to
// reflect rows just written to SQL. Only call after Create*/Update*/Delete*
// of Upstream / ModelName / Route succeeded.
//
// On Refresh failure the HTTP write must not return success: a failed
// Refresh stamps lastAttempt while leaving the pre-write routing pointer,
// so the next Snapshot() would keep serving the stale snapshot for another
// TTL window. Re-Invalidate keeps that window forced open for the next get().
func (s *Server) publishAfterSuccessfulWrite() error {
	if s == nil || s.publisher == nil {
		return nil
	}
	s.publisher.Invalidate()
	if err := s.publisher.Refresh(); err != nil {
		s.publisher.Invalidate()
		if s.log != nil {
			s.log.Error("写入后刷新配置快照失败", "err", err)
		}
		return err
	}
	return nil
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

// invalidateUpstreamDeleted runs only after DeleteUpstream succeeded, using
// route IDs collected before CASCADE removed the child rows.
func (s *Server) invalidateUpstreamDeleted(upstreamID int64, routeIDs []int64) {
	if s.invalidator == nil {
		return
	}
	if d, ok := s.invalidator.(interface {
		InvalidateUpstreamDeleted(upstreamID int64, routeIDs []int64)
	}); ok {
		d.InvalidateUpstreamDeleted(upstreamID, routeIDs)
		return
	}
	s.invalidator.InvalidateUpstream(upstreamID)
}

// invalidateModelNameDeleted runs only after DeleteModelName succeeded, using
// route IDs collected before CASCADE removed the child rows.
func (s *Server) invalidateModelNameDeleted(modelNameID int64, routeIDs []int64) {
	if s.invalidator == nil {
		return
	}
	if d, ok := s.invalidator.(interface {
		InvalidateModelNameDeleted(modelNameID int64, routeIDs []int64)
	}); ok {
		d.InvalidateModelNameDeleted(modelNameID, routeIDs)
		return
	}
	s.invalidator.InvalidateModelName(modelNameID)
}

// routeIDsOfUpstream lists live Route ids under an Upstream (pre-CASCADE snapshot).
func (s *Server) routeIDsOfUpstream(upstreamID int64) []int64 {
	routes, err := s.st.ListRoutes(0)
	if err != nil {
		return nil
	}
	var ids []int64
	for _, rt := range routes {
		if rt != nil && rt.UpstreamID == upstreamID {
			ids = append(ids, rt.ID)
		}
	}
	return ids
}

// routeIDsOfModelName lists live Route ids under a ModelName (pre-CASCADE snapshot).
func (s *Server) routeIDsOfModelName(modelNameID int64) []int64 {
	routes, err := s.st.ListRoutes(modelNameID)
	if err != nil {
		return nil
	}
	ids := make([]int64, 0, len(routes))
	for _, rt := range routes {
		if rt != nil {
			ids = append(ids, rt.ID)
		}
	}
	return ids
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
	// HostOverride / TLSServerName bump NetworkRevision (store.networkChanged) and
	// are §9.2 network-origin fields: must invalidate so RouteHealth is forgotten
	// for the new origin, not only BaseURL / ProxyURL / FullURLMode.
	if before.BaseURL != after.BaseURL ||
		before.APIKey != after.APIKey ||
		before.AuthStyle != after.AuthStyle ||
		before.FullURLMode != after.FullURLMode ||
		before.ProxyURL != after.ProxyURL ||
		before.HostOverride != after.HostOverride ||
		before.TLSServerName != after.TLSServerName ||
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
