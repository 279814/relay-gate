package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── CSRF 面 ────────────────────────────────────────────────
//
// PR-B 引入浏览器界面之后，这组测试才真正有意义：在此之前管理接口只被
// 脚本用 Bearer 调，不存在「浏览器自动带上凭据」这回事。
//
// 现在的唯一防线是 Cookie 的 SameSite=Strict。下面几条把这条防线的
// **边界**钉住 —— 哪些攻击它挡得住、哪些挡不住、为什么剩下的可接受。

func TestCSRF_SessionCookieIsSameSiteStrict(t *testing.T) {
	// SameSite=Strict 是这里唯一的 CSRF 防线，且它挡的是浏览器**自动
	// 附带 Cookie** 这一步 —— 跨站发起的请求根本带不上会话，于是所有
	// 需要鉴权的写操作都会 401。
	//
	// 降级成 Lax 就会破功：Lax 允许顶层导航（含 GET 表单）携带 Cookie，
	// 而管理接口里有 GET 语义的读端点（/samples 含对话原文）。
	_, h := newTestServer(t)
	rec := do(t, h, "POST", "/admin/api/login",
		`{"password":"`+testAdminPW+`"}`, false)

	var sess *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			sess = c
		}
	}
	if sess == nil {
		t.Fatal("没拿到会话 Cookie")
	}
	if sess.SameSite != http.SameSiteStrictMode {
		t.Errorf("会话 Cookie 必须是 SameSite=Strict（当前 %v）—— "+
			"它是引入 Web 界面后唯一的 CSRF 防线", sess.SameSite)
	}
}

func TestCSRF_WriteEndpointsRejectUnauthenticated(t *testing.T) {
	// 纵深防御的第二层：即使 Cookie 因为某种原因被带上了（浏览器 bug、
	// 用户改了设置、未来某天换成 Lax），没有凭据的写请求仍然要被拒。
	//
	// 逐个列出来而不是抽样：漏掉的那个就是唯一能被打穿的口子。
	_, h := newTestServer(t)
	writes := []struct{ method, path, body string }{
		{"POST", "/admin/api/upstreams", `{"name":"x","base_url":"https://a.com"}`},
		{"PUT", "/admin/api/upstreams/1", `{"name":"x"}`},
		{"DELETE", "/admin/api/upstreams/1", ""},
		{"POST", "/admin/api/model-names", `{"name":"m","protocol":"anthropic"}`},
		{"PUT", "/admin/api/model-names/1", `{"name":"m"}`},
		{"DELETE", "/admin/api/model-names/1", ""},
		{"POST", "/admin/api/routes", `{"model_name_id":1,"upstream_id":1}`},
		{"PUT", "/admin/api/routes/1", `{"priority":1}`},
		{"DELETE", "/admin/api/routes/1", ""},
		{"PUT", "/admin/api/settings", `{}`},
		{"POST", "/admin/api/state", `{"state":"paused"}`},
		{"POST", "/admin/api/routes/1/probe", ""},
		{"POST", "/admin/api/samples/1/pin", `{"pinned":true}`},
		{"DELETE", "/admin/api/samples", ""},
	}
	for _, w := range writes {
		rec := do(t, h, w.method, w.path, w.body, false)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s 未鉴权时应 401，得到 %d", w.method, w.path, rec.Code)
		}
	}
}

func TestCSRF_ReadEndpointsRejectUnauthenticated(t *testing.T) {
	// 读端点同样要拦。/samples 里是完整的对话原文与代码（§3.6），
	// 泄露它比改坏一个配置更糟。
	_, h := newTestServer(t)
	for _, p := range []string{
		"/admin/api/upstreams", "/admin/api/model-names", "/admin/api/routes",
		"/admin/api/settings", "/admin/api/state", "/admin/api/runtime",
		"/admin/api/health", "/admin/api/probe-cost",
		"/admin/api/samples", "/admin/api/samples/1",
		"/admin/api/samples/1/probe-headers",
	} {
		rec := do(t, h, "GET", p, "", false)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s 未鉴权时应 401，得到 %d", p, rec.Code)
		}
	}
}

// TestCSRF_LoginAcceptsNonJSONContentType 记录一个**已知且可接受**的缺口。
//
// decodeJSON 不校验 Content-Type，所以跨站的 HTML 表单（只能发
// text/plain、application/x-www-form-urlencoded、multipart）理论上能把
// 一段 JSON 当 text/plain 提交到 /login。
//
// 为什么可接受：
//   - 攻击者要构造这个表单，就得**已经知道管理口令** —— 而知道口令的话
//     直接登录即可，不需要绕
//   - 登录成功的响应是 Set-Cookie，跨站页面读不到（HttpOnly + 跨源），
//     所以攻击者拿不到会话
//   - 唯一的效果是「让受害者的浏览器登入攻击者知道的那个账号」
//     （login CSRF）。这个网关只有一个账号、只有一份数据，
//     「登入攻击者的账号」和「登入自己的账号」是同一件事
//
// 若哪天引入多账号或多租户，这条就不再成立，那时要加 CSRF token 或
// 校验 Content-Type + Origin。这条测试就是那个提醒。
func TestCSRF_LoginAcceptsNonJSONContentType(t *testing.T) {
	_, h := newTestServer(t)
	req := httptest.NewRequest("POST", "/admin/api/login",
		strings.NewReader(`{"password":"`+testAdminPW+`"}`))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Skipf("行为已变（现在 %d）—— 若是刻意加了 Content-Type 校验，"+
			"删掉这条测试并更新 §10.6 的说明", rec.Code)
	}
	// 关键断言：即便如此，攻击者也拿不到会话内容 —— Cookie 是 HttpOnly。
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && !c.HttpOnly {
			t.Error("会话 Cookie 不是 HttpOnly —— 跨站脚本能直接读走它")
		}
	}
}
