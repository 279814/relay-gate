package api

import (
	"crypto/subtle"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/279814/relay-gate/internal/store"
)

// TestConstantTimeCompare_EmptyVsEmpty 记录一个标准库行为，它是下面两条
// 测试的前提：两个空切片长度相同、内容相同，所以 ConstantTimeCompare 返回 1。
//
// 单独立一条测试而不是写在注释里：这个前提若哪天不成立（或者我记错了），
// 下面两条测试的意义就变了，而那时能一眼看出是前提变了。
func TestConstantTimeCompare_EmptyVsEmpty(t *testing.T) {
	if subtle.ConstantTimeCompare([]byte(""), []byte("")) != 1 {
		t.Skip("标准库行为已变，下面两条测试的前提不再成立")
	}
}

// newServerWithPW 起一个指定口令的管理端，用于测空口令的边界。
func newServerWithPW(t *testing.T, pw string) http.Handler {
	t.Helper()
	c, err := store.NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "pw.db"), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st, slog.New(slog.NewTextHandler(io.Discard, nil))).Routes(pw)
}

// TestAuth_EmptyAdminPasswordDeniesEverything 是纵深防御。
//
// config.validate 要求 ADMIN_PASSWORD 至少 8 字符，所以生产路径上
// 口令不会是空的。但鉴权是这个项目里后果最重的一个判断 —— 管理接口
// 能读写所有上游 key（§5.2f）—— 而「空口令 + 无凭据 = 放行」是
// ConstantTimeCompare 的自然行为，不是需要犯错才会出现的东西。
//
// 换句话说：这里防的不是今天的 bug，是明天某个绕过了 config.Load 的
// 装配路径（测试工具、嵌入式用法、一个新的 cmd）。
func TestAuth_EmptyAdminPasswordDeniesEverything(t *testing.T) {
	h := newServerWithPW(t, "")

	// 无凭据
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/admin/api/upstreams", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("空口令时无凭据请求必须 401，得到 %d", rec.Code)
	}

	// 空 Bearer
	req := httptest.NewRequest("GET", "/admin/api/upstreams", nil)
	req.Header.Set("Authorization", "Bearer ")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("空口令时空 Bearer 必须 401，得到 %d", rec2.Code)
	}
}

// TestLogin_EmptyAdminPasswordCannotLogIn 同理，堵住登录端点这条路。
func TestLogin_EmptyAdminPasswordCannotLogIn(t *testing.T) {
	h := newServerWithPW(t, "")

	for _, body := range []string{`{"password":""}`, `{}`} {
		rec := do(t, h, "POST", "/admin/api/login", body, false)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("空口令时 %s 必须登录失败，得到 %d：%s",
				body, rec.Code, rec.Body.String())
		}
	}
}
