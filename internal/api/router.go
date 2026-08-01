package api

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// Routes 注册管理端路由。用标准库 ServeMux 的方法模式路由（Go 1.22+），
// 不引 chi —— 路由就这些，一个依赖换不来什么。
func (s *Server) Routes(adminPW string) http.Handler {
	s.adminPW = adminPW
	mux := http.NewServeMux()

	mux.HandleFunc("GET /admin/api/upstreams", s.listUpstreams)
	mux.HandleFunc("POST /admin/api/upstreams", s.createUpstream)
	mux.HandleFunc("GET /admin/api/upstreams/{id}", s.getUpstream)
	mux.HandleFunc("PUT /admin/api/upstreams/{id}", s.updateUpstream)
	mux.HandleFunc("DELETE /admin/api/upstreams/{id}", s.deleteUpstream)

	mux.HandleFunc("GET /admin/api/model-names", s.listModelNames)
	mux.HandleFunc("POST /admin/api/model-names", s.createModelName)
	mux.HandleFunc("GET /admin/api/model-names/{id}", s.getModelName)
	mux.HandleFunc("PUT /admin/api/model-names/{id}", s.updateModelName)
	mux.HandleFunc("DELETE /admin/api/model-names/{id}", s.deleteModelName)

	mux.HandleFunc("GET /admin/api/routes", s.listRoutes)
	mux.HandleFunc("POST /admin/api/routes", s.createRoute)
	mux.HandleFunc("GET /admin/api/routes/{id}", s.getRoute)
	mux.HandleFunc("PUT /admin/api/routes/{id}", s.updateRoute)
	mux.HandleFunc("DELETE /admin/api/routes/{id}", s.deleteRoute)

	mux.HandleFunc("GET /admin/api/settings", s.getSettings)
	mux.HandleFunc("PUT /admin/api/settings", s.updateSettings)
	mux.HandleFunc("GET /admin/api/state", s.getState)
	mux.HandleFunc("POST /admin/api/state", s.setState)
	mux.HandleFunc("GET /admin/api/runtime", s.getRuntime)

	// 探活（§4）。健康看板是排查「为什么这个模型不可用」的主入口，
	// 手动探活对应 §4.5 的「UI 手动点测试」。
	mux.HandleFunc("GET /admin/api/health", s.getHealth)
	mux.HandleFunc("POST /admin/api/routes/{id}/probe", s.probeRoute)

	mux.HandleFunc("GET /admin/api/samples", s.listSamples)
	mux.HandleFunc("GET /admin/api/samples/{id}", s.getSample)
	mux.HandleFunc("POST /admin/api/samples/{id}/pin", s.pinSample)
	mux.HandleFunc("DELETE /admin/api/samples", s.clearSamples)
	// 从样本导出探活头模板（§3.6.4）。改探活指纹的正确方式是从真实样本导，
	// 而不是手写 —— 手写就又回到了 M0 证明会把活站判死的那种猜。
	mux.HandleFunc("GET /admin/api/samples/{id}/probe-headers", s.sampleProbeHeaders)

	// 探活成本（§5.2d）。没有它无法判断探活策略是否过激。
	mux.HandleFunc("GET /admin/api/probe-cost", s.getProbeCost)

	guarded := s.requireAdmin(mux)

	// 会话端点挂在鉴权**之外**。
	//
	// login 显然不能要鉴权（那就登不上了）；session 也不能 ——
	// 未登录时前端要能问「我登录了吗」并得到一个明确的 false 去渲染登录页，
	// 而不是收到 401。logout 放外面是因为它对未登录请求也该是成功的空操作。
	outer := http.NewServeMux()
	outer.Handle("/admin/api/", guarded)
	outer.HandleFunc("POST /admin/api/login", s.login)
	outer.HandleFunc("POST /admin/api/logout", s.logout)
	outer.HandleFunc("GET /admin/api/session", s.session)
	return outer
}

// requireAdmin 保护管理端点，接受两种凭据：会话 Cookie 或 Bearer 口令。
//
// 两条路径并存是刻意的：浏览器走 Cookie（M5 的 Web UI），
// 脚本与冒烟测试走 Bearer（scripts/smoke-*.ps1 一直这么用，
// 换掉的话那些验证脚本全要改，而它们是 §9.3 故障注入验证的载体）。
// 两者校验的是同一个口令，不存在「改了口令还有一条路认旧的」。
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authenticated(r) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="relay-gate admin"`)
			writeJSON(w, http.StatusUnauthorized, errBody{"未授权：需要管理口令"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// bearerOK 校验 Bearer / X-Admin-Password 口令。
//
// 定长比较，避免按字符逐位比较带来的时序侧信道。
//
// 口令为空时一律拒绝。这不是多余的判断：ConstantTimeCompare("", "") 返回
// **相等**，所以 adminPW 为空时，一个不带任何凭据的请求会被判为通过 ——
// 管理接口能读写所有上游 key（§5.2f），那等于全部公开。
//
// config.validate 要求 ADMIN_PASSWORD 至少 8 字符，所以生产路径上到不了
// 这里。但鉴权是这个项目里后果最重的判断，不该依赖「调用方一定先校验过」——
// 明天多一个绕过 config.Load 的装配路径（测试工具、嵌入式用法、新的 cmd），
// 这个默认放行就会静默生效，且不报任何错。
func (s *Server) bearerOK(r *http.Request) bool {
	if s.adminPW == "" {
		return false
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if got == "" {
		got = r.Header.Get("X-Admin-Password")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.adminPW)) == 1
}
