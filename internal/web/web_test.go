package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandler_ServesIndexAtBothPaths(t *testing.T) {
	// /admin 与 /admin/ 都要给 index.html。少一个斜杠就 404
	// 是这类界面最没必要的挫折。
	h := Handler()
	for _, path := range []string{"/admin", "/admin/", "/admin/index.html"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s 应 200，得到 %d", path, rec.Code)
			continue
		}
		if !strings.Contains(rec.Body.String(), "relay-gate") {
			t.Errorf("%s 返回的不像 index.html", path)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
			t.Errorf("%s 的 Content-Type = %q，应是 text/html", path, ct)
		}
	}
}

func TestHandler_ServesStaticAssets(t *testing.T) {
	h := Handler()
	for _, tc := range []struct{ path, wantType, wantBody string }{
		{"/admin/app.css", "text/css", "--bg"},
		{"/admin/app.js", "javascript", "function app()"},
		{"/admin/alpine.min.js", "javascript", ""},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", tc.path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s 应 200，得到 %d", tc.path, rec.Code)
			continue
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, tc.wantType) {
			t.Errorf("%s 的 Content-Type = %q，应含 %q", tc.path, ct, tc.wantType)
		}
		if tc.wantBody != "" && !strings.Contains(rec.Body.String(), tc.wantBody) {
			t.Errorf("%s 的内容里找不到 %q", tc.path, tc.wantBody)
		}
	}
}

func TestHandler_IndexIsNotCached(t *testing.T) {
	// 升级后用户不该还看着旧界面 —— index.html 里带着与后端 API 契约
	// 相关的逻辑，缓存住会让新旧混搭。
	h := Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/admin/", nil))
	if cc := rec.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("index.html 的 Cache-Control = %q，应为 no-cache", cc)
	}
}

func TestHandler_UnknownAssetIs404(t *testing.T) {
	h := Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/admin/nope.js", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("不存在的资源应 404，得到 %d", rec.Code)
	}
}

// TestHandler_PathPrefixEdges 钉住路径前缀处理的边界。
//
// Handler 用 TrimPrefix(path, "/admin") 剥前缀，而 TrimPrefix 对**不匹配**
// 的输入是原样返回的 —— 读代码时这看着像个隐患（"/adminfoo" 会被剥成
// "foo"）。实测下来不是问题：剥出来的路径在 static/ 里找不到，FileServer
// 给 404，与「本来就不该处理这个路径」的结果一致。
//
// 记下来是因为下次有人读到那个 TrimPrefix 会产生同样的疑虑，而结论
// （靠 FileServer 的 404 兜住，不需要显式校验前缀）值得省掉一次重复排查。
func TestHandler_PathPrefixEdges(t *testing.T) {
	h := Handler()
	cases := []struct {
		path string
		code int
	}{
		{"/admin", http.StatusOK},          // 少一个斜杠也要给 index
		{"/admin/", http.StatusOK},         //
		{"/admin/app.js", http.StatusOK},   // 正常资源
		{"/adminfoo", http.StatusNotFound}, // 前缀像但不是
		{"/other", http.StatusNotFound},    // 完全无关（正常挂载下到不了这里）
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", c.path, nil))
		if rec.Code != c.code {
			t.Errorf("%s → %d，期望 %d", c.path, rec.Code, c.code)
		}
	}
}

// TestEmbed_OnlyShipsWhatTheBrowserNeeds 守住内嵌资源的边界。
//
// go:embed static 会把该目录下的**所有**文件打进二进制并经 FileServer
// 对外可见。VENDOR.md（第三方来源与哈希记录）本来写在 static/ 下，
// 那会让它既进二进制又能被 HTTP 拿到 —— 没有泄密风险，但它是给维护者
// 看的文档，不是浏览器要的东西。
//
// 这条测试盯的是「日后又往 static/ 里塞了不该塞的东西」：README、
// 设计草稿、.map 文件都属于这一类。
func TestEmbed_OnlyShipsWhatTheBrowserNeeds(t *testing.T) {
	entries, err := staticFS.ReadDir("static")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"index.html":    true,
		"app.js":        true,
		"app.css":       true,
		"alpine.min.js": true,
	}
	for _, e := range entries {
		if !want[e.Name()] {
			t.Errorf("static/ 里多了 %q。浏览器不需要的文件（文档、草稿、"+
				".map）不该进二进制 —— 放到 internal/web/ 下即可", e.Name())
		}
		delete(want, e.Name())
	}
	for name := range want {
		t.Errorf("static/ 里缺了 %q", name)
	}
}

// TestHandler_DoesNotEscapeStaticDir 守住路径穿越。
//
// http.FS + fs.Sub 本身会挡掉 ../，但这是「界面挂在网关上」的直接后果：
// 真穿越出去就能读到进程能读的任何文件。值得一条测试钉住，而不是
// 依赖「标准库应该会处理」。
func TestHandler_DoesNotEscapeStaticDir(t *testing.T) {
	h := Handler()
	for _, path := range []string{
		"/admin/../web.go",
		"/admin/..%2fweb.go",
		"/admin/static/../../web.go",
	} {
		req := httptest.NewRequest("GET", path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "package web") {
			t.Errorf("%s 读到了静态目录之外的文件", path)
		}
	}
}
