// Package web 提供管理界面的静态资源与页面路由。
//
// 全部 go:embed 进二进制（§6）：这是自托管网关，很可能跑在内网或访问
// 外网不畅的环境里。首屏依赖外网 CDN 意味着「网关本身好好的，但管理界面
// 打不开」—— 而管理界面正是出问题时要用的东西。
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed static
var staticFS embed.FS

// Handler 返回管理界面的处理器，挂在 /admin/ 下。
//
// **刻意不鉴权。** 这里提供的只有 HTML/CSS/JS —— 纯前端代码，不含任何
// 配置或密钥，数据一律经 /admin/api/ 取（那边是要鉴权的）。
//
// 反过来说，静态资源**不能**要鉴权：登录页自己就是静态资源，
// 拦住它的话用户连输口令的地方都打不开。
func Handler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		// embed 的目录名是编译期常量，走到这里说明源码被改坏了。
		panic("web: 无法打开内嵌静态资源: " + err.Error())
	}
	files := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /admin 与 /admin/ 都给 index.html。少一个斜杠就 404
		// 是这类界面最没必要的挫折。
		path := strings.TrimPrefix(r.URL.Path, "/admin")
		path = strings.TrimPrefix(path, "/")

		if path == "" || path == "index.html" {
			// 不缓存 HTML：升级后用户不该还看着旧界面，而 index.html
			// 里带着与后端 API 契约相关的逻辑。静态资源（带版本的 js/css）
			// 由 FileServer 自己按 ETag 处理。
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			data, err := staticFS.ReadFile("static/index.html")
			if err != nil {
				http.Error(w, "界面资源缺失", http.StatusInternalServerError)
				return
			}
			_, _ = w.Write(data)
			return
		}

		r2 := r.Clone(r.Context())
		r2.URL.Path = "/" + path
		files.ServeHTTP(w, r2)
	})
}
