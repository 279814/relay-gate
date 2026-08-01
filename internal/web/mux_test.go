package web_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/api"
	"github.com/279814/relay-gate/internal/store"
	"github.com/279814/relay-gate/internal/web"
)

// TestMuxPrecedence_APIWinsOverUI 验证整个挂载方式的前提。
//
// main.go 把 web.Handler() 挂在 "/admin/"、把管理 API 挂在 "/admin/api/"，
// 依赖的是 ServeMux 的**最长前缀匹配**。如果这个假定不成立，所有 API
// 请求都会掉进界面处理器、拿到一份 HTML —— 而症状是「界面加载后一片空白，
// 控制台报 JSON 解析失败」，从表象很难定位到路由优先级。
//
// 所以这条测试装配的是与 main.go 相同的两条 Handle 调用，实测而非假定。
func TestMuxPrecedence_APIWinsOverUI(t *testing.T) {
	c, err := store.NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "mux.db"), c)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	mux := http.NewServeMux()
	mux.Handle("/admin/api/", api.New(st, log).Routes("test-admin-password"))
	mux.Handle("/admin/", web.Handler())

	cases := []struct {
		name, path, wantSub string
		wantCode            int
	}{
		{
			// 未带凭据的 API 请求要拿到 401 JSON，而不是 200 HTML。
			name: "API 端点归 api 包", path: "/admin/api/upstreams",
			wantCode: http.StatusUnauthorized, wantSub: `"error"`,
		},
		{
			// 会话端点在鉴权之外，应回 200 JSON。若被界面吞掉会回 HTML，
			// 前端就永远停在登录页（拿不到 authenticated 字段）。
			name: "会话端点归 api 包", path: "/admin/api/session",
			wantCode: http.StatusOK, wantSub: `"authenticated"`,
		},
		{
			name: "界面根路径归 web 包", path: "/admin/",
			wantCode: http.StatusOK, wantSub: "<!DOCTYPE html>",
		},
		{
			name: "静态资源归 web 包", path: "/admin/app.js",
			wantCode: http.StatusOK, wantSub: "function app()",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest("GET", tc.path, nil))
			if rec.Code != tc.wantCode {
				t.Errorf("%s → %d，期望 %d（body=%.120s）",
					tc.path, rec.Code, tc.wantCode, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantSub) {
				t.Errorf("%s 的响应里找不到 %q，实际前 120 字符：%.120s",
					tc.path, tc.wantSub, rec.Body.String())
			}
		})
	}
}

// TestMuxPrecedence_ProxyEndpointsUnaffected 确认界面挂载没有影响转发端点。
//
// web.Handler 只认 /admin 前缀，但它是用 TrimPrefix 实现的 —— 万一哪天
// 改成更宽松的匹配，/v1/messages 被界面吞掉就是「网关整个不工作」。
func TestMuxPrecedence_ProxyEndpointsUnaffected(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("/admin/", web.Handler())
	hit := false
	mux.HandleFunc("POST /v1/messages", func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/messages", nil))
	if !hit {
		t.Fatal("/v1/messages 没有到达转发处理器 —— 被界面吞掉了")
	}
}
