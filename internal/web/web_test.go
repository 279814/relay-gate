package web

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandler_ServesIndex(t *testing.T) {
	h := Handler()
	for _, path := range []string{"/admin", "/admin/", "/admin/index.html"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s → %d", path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
			t.Errorf("%s 的 Content-Type = %q，应是 text/html", path, ct)
		}
		if !strings.Contains(rec.Body.String(), "relay-gate") {
			t.Errorf("%s 响应里没有标题", path)
		}
	}
}

func TestHandler_ServesStaticAssets(t *testing.T) {
	h := Handler()
	cases := []struct {
		path, wantType, wantSnippet string
	}{
		{"/admin/app.js", "javascript", "function app()"},
		{"/admin/alpine.min.js", "javascript", ""},
		{"/admin/app.css", "css", "--bg"},
		{"/admin/js/api.mjs", "javascript", "createApiClient"},
		{"/admin/js/probes.mjs", "javascript", "createProbeFeature"},
		{"/admin/js/modal.mjs", "javascript", "openModalLock"},
		{"/admin/js/boot.mjs", "javascript", "createProbeFeature"},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", tc.path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s → %d", tc.path, rec.Code)
			continue
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, tc.wantType) {
			t.Errorf("%s 的 Content-Type = %q，应含 %q", tc.path, ct, tc.wantType)
		}
		if tc.wantSnippet != "" && !strings.Contains(rec.Body.String(), tc.wantSnippet) {
			t.Errorf("%s 缺少片段 %q", tc.path, tc.wantSnippet)
		}
	}
}

func TestHandler_IndexIsNotCached(t *testing.T) {
	h := Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/admin/", nil))
	cc := rec.Header().Get("Cache-Control")
	if !strings.Contains(cc, "no-cache") {
		t.Errorf("index Cache-Control = %q，应含 no-cache", cc)
	}
}

func TestHandler_UnknownAsset404(t *testing.T) {
	h := Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/admin/nope.js", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("未知资源 → %d，want 404", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/admin/js/nope.mjs", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("未知 mjs → %d，want 404", rec.Code)
	}
}

func TestHandler_DoesNotRequireAuth(t *testing.T) {
	// 静态资源必须匿名可达，否则登录页自己打不开。
	h := Handler()
	cases := []struct {
		path string
		code int
	}{
		{"/admin/", http.StatusOK},
		{"/admin/app.js", http.StatusOK},
		{"/admin/js/boot.mjs", http.StatusOK},
		{"/admin/js/migration.mjs", http.StatusOK},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", tc.path, nil))
		if rec.Code != tc.code {
			t.Errorf("%s → %d，want %d", tc.path, rec.Code, tc.code)
		}
	}
}

// TestEmbed_OnlyShipsWhatTheBrowserNeeds 守住内嵌资源的边界（递归精确白名单）。
func TestEmbed_OnlyShipsWhatTheBrowserNeeds(t *testing.T) {
	want := map[string]bool{
		"static/index.html":         true,
		"static/app.js":             true,
		"static/app.css":            true,
		"static/alpine.min.js":      true,
		"static/js/api.mjs":         true,
		"static/js/probes.mjs":      true,
		"static/js/modal.mjs":       true,
		"static/js/boot.mjs":        true,
		"static/js/errors.mjs":      true,
		"static/js/migration.mjs":   true,
		"static/js/credentials.mjs": true,
	}
	err := fs.WalkDir(staticFS, "static", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !want[p] {
			t.Errorf("static/ 里多了 %q。浏览器不需要的文件不该进二进制", p)
		}
		delete(want, p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for name := range want {
		t.Errorf("static/ 里缺了 %q", name)
	}
}

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

func TestIndex_BootScriptOrder(t *testing.T) {
	data, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	appAt := strings.Index(html, `src="/admin/app.js"`)
	bootAt := strings.Index(html, `src="/admin/js/boot.mjs"`)
	alpineAt := strings.Index(html, `src="/admin/alpine.min.js"`)
	if appAt < 0 || bootAt < 0 || alpineAt < 0 {
		t.Fatal("index.html 缺少 app.js / boot.mjs / alpine.min.js")
	}
	if !(appAt < bootAt && bootAt < alpineAt) {
		t.Fatalf("script 顺序应为 app.js → boot.mjs → alpine，got app=%d boot=%d alpine=%d", appAt, bootAt, alpineAt)
	}
	if !strings.Contains(html, `type="module" src="/admin/js/boot.mjs"`) {
		t.Fatal("boot.mjs 必须以 type=module 加载")
	}
}
