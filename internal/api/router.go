package api

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// Routes 注册管理端路由。用标准库 ServeMux 的方法模式路由（Go 1.22+），
// 不引 chi —— 路由就这些，一个依赖换不来什么。
func (s *Server) Routes(adminPW string) http.Handler {
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

	return s.requireAdmin(adminPW, mux)
}

// requireAdmin 用 Bearer 口令保护管理端点。
//
// M1 先做最简的口令校验，M5 上 Web UI 时再换成会话 Cookie。
// 但**现在就必须有鉴权**：管理接口能读写所有上游配置，
// 裸奔的话任何人都能拿到（写）你的 key。
func (s *Server) requireAdmin(pw string, next http.Handler) http.Handler {
	want := []byte(pw)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if got == "" {
			got = r.Header.Get("X-Admin-Password")
		}
		// 定长比较，避免按字符逐位比较带来的时序侧信道。
		if subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="relay-gate admin"`)
			writeJSON(w, http.StatusUnauthorized, errBody{"未授权：需要管理口令"})
			return
		}
		next.ServeHTTP(w, r)
	})
}
