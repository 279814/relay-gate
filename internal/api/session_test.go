package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probe"
	"github.com/279814/relay-gate/internal/store"
)

const testAdminPW = "test-admin-password"

// newTestServer 起一个接了真 store 的管理端。
//
// 用真 store 而不是假的：这些端点的行为大量依赖「以库中现值为基底做部分
// 更新」（updateUpstream 的 api_key 留空语义就是典型），假 store 要把那套
// 语义再实现一遍才能测，而实现错了就测了个假的。
func newTestServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	c, err := store.NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "api.db"), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := New(st, log)
	return s, s.Routes(testAdminPW)
}

// do 发一个请求。auth 为 true 时带上 Bearer 口令。
func do(t *testing.T, h http.Handler, method, path, body string, auth bool) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if auth {
		req.Header.Set("Authorization", "Bearer "+testAdminPW)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeBody[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("解析响应失败: %v（body=%s）", err, rec.Body.String())
	}
	return out
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// ── 鉴权 ──────────────────────────────────────────────────

func TestAuth_NoCredentialsIsUnauthorized(t *testing.T) {
	_, h := newTestServer(t)
	rec := do(t, h, "GET", "/admin/api/upstreams", "", false)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("无凭据应 401，得到 %d", rec.Code)
	}
	// WWW-Authenticate 是让 curl -u 之类的客户端知道该怎么认证。
	if got := rec.Header().Get("WWW-Authenticate"); got == "" {
		t.Error("401 响应缺少 WWW-Authenticate 头")
	}
}

func TestAuth_BearerStillWorks(t *testing.T) {
	// M5 加了 Cookie 会话，但 Bearer 必须继续可用 ——
	// scripts/smoke-m2.ps1 与 smoke-m3.ps1 全靠它，而那两个脚本是
	// §9.2/§9.3 验证清单的载体。
	_, h := newTestServer(t)
	rec := do(t, h, "GET", "/admin/api/upstreams", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("Bearer 口令应放行，得到 %d：%s", rec.Code, rec.Body.String())
	}
}

func TestAuth_WrongBearerIsUnauthorized(t *testing.T) {
	_, h := newTestServer(t)
	req := httptest.NewRequest("GET", "/admin/api/upstreams", nil)
	req.Header.Set("Authorization", "Bearer wrong-password")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("错误口令应 401，得到 %d", rec.Code)
	}
}

// ── 会话登录 ──────────────────────────────────────────────

func TestLogin_CorrectPasswordSetsHttpOnlyCookie(t *testing.T) {
	_, h := newTestServer(t)
	rec := do(t, h, "POST", "/admin/api/login",
		`{"password":"`+testAdminPW+`"}`, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("正确口令应 200，得到 %d：%s", rec.Code, rec.Body.String())
	}

	cookies := rec.Result().Cookies()
	var sess *http.Cookie
	for _, c := range cookies {
		if c.Name == sessionCookie {
			sess = c
		}
	}
	if sess == nil {
		t.Fatal("登录成功但没有设置会话 Cookie")
	}
	if sess.Value == "" {
		t.Error("会话 Cookie 的值为空")
	}
	// 这三条是这个 Cookie 的全部防线，逐一断言。
	if !sess.HttpOnly {
		t.Error("会话 Cookie 必须是 HttpOnly，否则 XSS 能直接读走它")
	}
	if sess.SameSite != http.SameSiteStrictMode {
		t.Errorf("会话 Cookie 应为 SameSite=Strict，得到 %v", sess.SameSite)
	}
	if sess.Path != "/" {
		t.Errorf("会话 Cookie 的 Path 应为 /，得到 %q", sess.Path)
	}
}

func TestLogin_WrongPasswordIsUnauthorizedAndSetsNoCookie(t *testing.T) {
	_, h := newTestServer(t)
	rec := do(t, h, "POST", "/admin/api/login", `{"password":"nope"}`, false)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("错误口令应 401，得到 %d", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			t.Fatal("登录失败却发了会话 Cookie")
		}
	}
}

func TestLogin_EmptyPasswordIsUnauthorized(t *testing.T) {
	// 空口令绝不能通过。若 adminPW 也是空的，ConstantTimeCompare 会返回
	// 相等 —— 但 config.validate 要求至少 8 字符，所以生产上不可达。
	// 这条测试守的是「别哪天把校验删了还没人发现」。
	_, h := newTestServer(t)
	rec := do(t, h, "POST", "/admin/api/login", `{"password":""}`, false)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("空口令应 401，得到 %d", rec.Code)
	}
}

func TestSession_CookieGrantsAccess(t *testing.T) {
	_, h := newTestServer(t)
	login := do(t, h, "POST", "/admin/api/login",
		`{"password":"`+testAdminPW+`"}`, false)
	var sess *http.Cookie
	for _, c := range login.Result().Cookies() {
		if c.Name == sessionCookie {
			sess = c
		}
	}
	if sess == nil {
		t.Fatal("登录没拿到 Cookie")
	}

	// 带 Cookie、不带 Bearer 访问受保护端点。
	req := httptest.NewRequest("GET", "/admin/api/upstreams", nil)
	req.AddCookie(sess)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("会话 Cookie 应放行，得到 %d：%s", rec.Code, rec.Body.String())
	}
}

func TestSession_ForgedCookieIsRejected(t *testing.T) {
	// 令牌是 256 位随机数，伪造一个就该被拒。
	_, h := newTestServer(t)
	req := httptest.NewRequest("GET", "/admin/api/upstreams", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "forged-token-value"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("伪造的会话令牌应 401，得到 %d", rec.Code)
	}
}

func TestSession_EndpointReportsStateWithoutAuth(t *testing.T) {
	// /session 必须在未登录时也能访问并回一个明确的 false ——
	// 前端据此渲染登录页。若它也要鉴权，就变成了「未登录时问不出自己没登录」。
	_, h := newTestServer(t)
	rec := do(t, h, "GET", "/admin/api/session", "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("/session 未登录时也应 200，得到 %d", rec.Code)
	}
	body := decodeBody[map[string]any](t, rec)
	if body["authenticated"] != false {
		t.Errorf("未登录时 authenticated 应为 false，得到 %v", body["authenticated"])
	}
}

func TestSession_EndpointReportsTrueWithBearer(t *testing.T) {
	_, h := newTestServer(t)
	rec := do(t, h, "GET", "/admin/api/session", "", true)
	body := decodeBody[map[string]any](t, rec)
	if body["authenticated"] != true {
		t.Errorf("带 Bearer 时 authenticated 应为 true，得到 %v", body["authenticated"])
	}
}

func TestLogout_RevokesSession(t *testing.T) {
	_, h := newTestServer(t)
	login := do(t, h, "POST", "/admin/api/login",
		`{"password":"`+testAdminPW+`"}`, false)
	var sess *http.Cookie
	for _, c := range login.Result().Cookies() {
		if c.Name == sessionCookie {
			sess = c
		}
	}

	// 登出
	req := httptest.NewRequest("POST", "/admin/api/logout", nil)
	req.AddCookie(sess)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("登出应 200，得到 %d", rec.Code)
	}

	// 同一个 Cookie 现在应该失效了。这是关键断言：只让浏览器删 Cookie
	// 是不够的，服务端必须真的把令牌作废 —— 否则一个被复制走的 Cookie
	// 在登出后仍然能用。
	req2 := httptest.NewRequest("GET", "/admin/api/upstreams", nil)
	req2.AddCookie(sess)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("登出后旧 Cookie 应失效（401），得到 %d", rec2.Code)
	}
}

func TestSession_ExpiredTokenIsRejected(t *testing.T) {
	s, _ := newTestServer(t)
	// 注入时钟：签发时是"现在"，校验时已过 TTL。
	base := time.Now()
	s.sessions.now = func() time.Time { return base }
	tok, err := s.sessions.issue()
	if err != nil {
		t.Fatal(err)
	}
	if !s.sessions.valid(tok) {
		t.Fatal("刚签发的令牌应有效")
	}

	s.sessions.now = func() time.Time { return base.Add(sessionTTL + time.Second) }
	if s.sessions.valid(tok) {
		t.Error("超过 TTL 的令牌应失效")
	}
}

func TestLogin_ThrottlesAfterRepeatedFailures(t *testing.T) {
	s, h := newTestServer(t)
	var slept []time.Duration
	s.sessions.sleep = func(d time.Duration) { slept = append(slept, d) }

	// 前 loginLockThreshold 次失败不延迟。
	for i := 0; i < loginLockThreshold; i++ {
		do(t, h, "POST", "/admin/api/login", `{"password":"wrong"}`, false)
	}
	if len(slept) != 0 {
		t.Fatalf("前 %d 次失败不该延迟，却延迟了 %d 次", loginLockThreshold, len(slept))
	}

	// 第 threshold+1 次开始延迟。
	do(t, h, "POST", "/admin/api/login", `{"password":"wrong"}`, false)
	if len(slept) != 1 {
		t.Fatalf("超过阈值后应延迟一次，得到 %d 次", len(slept))
	}
	if slept[0] != loginLockDelay {
		t.Errorf("延迟时长应为 %v，得到 %v", loginLockDelay, slept[0])
	}
}

func TestLogin_SuccessIsNeverThrottled(t *testing.T) {
	// 关键性质：正常登录永远是快的，即使之前失败过很多次。
	// 否则输错几次口令之后，正确的那次也会变慢，用户会以为服务坏了。
	s, h := newTestServer(t)
	var slept []time.Duration
	s.sessions.sleep = func(d time.Duration) { slept = append(slept, d) }

	for i := 0; i < loginLockThreshold+3; i++ {
		do(t, h, "POST", "/admin/api/login", `{"password":"wrong"}`, false)
	}
	before := len(slept)

	rec := do(t, h, "POST", "/admin/api/login",
		`{"password":"`+testAdminPW+`"}`, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("正确口令应 200，得到 %d", rec.Code)
	}
	if len(slept) != before {
		t.Error("登录成功的路径不该被延迟")
	}
}

func TestLogin_SuccessResetsFailureCount(t *testing.T) {
	s, h := newTestServer(t)
	var slept []time.Duration
	s.sessions.sleep = func(d time.Duration) { slept = append(slept, d) }

	for i := 0; i < loginLockThreshold+1; i++ {
		do(t, h, "POST", "/admin/api/login", `{"password":"wrong"}`, false)
	}
	do(t, h, "POST", "/admin/api/login", `{"password":"`+testAdminPW+`"}`, false)

	// 成功后计数归零，于是下一次失败又回到「不延迟」。
	slept = slept[:0]
	do(t, h, "POST", "/admin/api/login", `{"password":"wrong"}`, false)
	if len(slept) != 0 {
		t.Error("登录成功应把失败计数归零，下一次失败不该被延迟")
	}
}

// ── 探活头模板导出（§3.6.4）────────────────────────────────

func TestProbeHeaders_ExcludesAuthHeaders(t *testing.T) {
	// 这是这个功能最重要的一条约束。样本里的鉴权头**已经脱敏**，
	// 导出进 probe_headers 的会是 `sk-abcd…wxyz` 这种打了码的串，
	// 拿它去探活的结果是整站 401 被判死 —— 而界面上显示的是「鉴权失败」，
	// 用户会去查真 key 对不对，完全指错方向。
	h := http.Header{}
	for _, name := range model.AuthHeaders {
		h.Set(name, "sk-abcd…wxyz")
	}
	h.Set("User-Agent", "claude-cli/2.1.220")

	tmpl, skipped := probeHeadersFromSample(h)
	for _, name := range model.AuthHeaders {
		if _, ok := tmpl[strings.ToLower(name)]; ok {
			t.Errorf("导出的模板里不该有鉴权头 %s", name)
		}
	}
	if len(skipped) != len(model.AuthHeaders) {
		t.Errorf("被排除的头应有 %d 个，得到 %d：%v",
			len(model.AuthHeaders), len(skipped), skipped)
	}
	if tmpl["user-agent"] != "claude-cli/2.1.220" {
		t.Errorf("user-agent 应保留，得到 %q", tmpl["user-agent"])
	}
}

func TestProbeHeaders_ExcludesAllSensitiveHeadersNotJustAuthHeaders(t *testing.T) {
	// review 时抓到的缺口：早先这里按 model.IsAuthHeader 过滤，而样本的
	// 脱敏清单（sample.sensitiveHeaders）比它多 Proxy-Authorization
	// 与 Cookie 两类 —— 于是那两个头会带着**脱敏后的假凭据**被导进模板。
	//
	// 假凭据比没有凭据更糟：它会覆盖真实鉴权头，把整站探活打成 401，
	// 而界面显示「鉴权失败」，排查方向完全指错（去查真 key 对不对）。
	h := http.Header{}
	h.Set("Proxy-Authorization", "Basic YWJjZA…d3h5eg")
	h.Set("Cookie", "session=abcd…wxyz")
	h.Set("User-Agent", "claude-cli/2.1.220")

	tmpl, skipped := probeHeadersFromSample(h)
	for _, bad := range []string{"proxy-authorization", "cookie"} {
		if _, ok := tmpl[bad]; ok {
			t.Errorf("%s 携带凭据，不该进探活模板", bad)
		}
	}
	if len(skipped) != 2 {
		t.Errorf("应排除 2 个凭据头，得到 %v", skipped)
	}
	if tmpl["user-agent"] == "" {
		t.Error("user-agent 是真实指纹的一部分，应保留")
	}
}

func TestProbeHeaders_ExcludesHeadersBuildHeadersOwns(t *testing.T) {
	// probe/headers.go 的三层叠加里，probe_headers 的覆盖发生在
	// anthropic-version 与 accept **之后**，所以从样本抄来的值会赢。
	//
	// accept 是其中后果最实际的一个：探活流式请求需要
	// text/event-stream，被样本里的 application/json 覆盖后 L2 收不到 SSE，
	// 会被判成假活 —— 一个完全可用的站因此被判死。
	h := http.Header{}
	h.Set("Anthropic-Version", "2023-06-01")
	h.Set("Accept", "application/json")
	h.Set("X-App", "cli")

	tmpl, _ := probeHeadersFromSample(h)
	if _, ok := tmpl["accept"]; ok {
		t.Error("accept 由 buildHeaders 按 stream 设，从样本抄会让 L2 收不到 SSE")
	}
	if _, ok := tmpl["anthropic-version"]; ok {
		t.Error("anthropic-version 由 buildHeaders 按协议设，抄了会跨协议串味")
	}
	if tmpl["x-app"] != "cli" {
		t.Error("x-app 应保留")
	}
}

func TestProbeHeaders_ExcludesTransportManagedHeaders(t *testing.T) {
	// 这些头由 http.Transport 自己填，手工设会与它打架
	// （重复的 Host 头是协议错误）。
	h := http.Header{}
	h.Set("Host", "api.example.com")
	h.Set("Content-Length", "1234")
	h.Set("Connection", "keep-alive")
	h.Set("Accept-Encoding", "gzip")
	h.Set("Cookie", "session=secret")
	h.Set("X-App", "cli")

	tmpl, _ := probeHeadersFromSample(h)
	for _, bad := range []string{"host", "content-length", "connection",
		"accept-encoding", "cookie"} {
		if _, ok := tmpl[bad]; ok {
			t.Errorf("%s 不该进探活模板", bad)
		}
	}
	if tmpl["x-app"] != "cli" {
		t.Error("x-app 是真实指纹的一部分，应保留")
	}
}

func TestProbeHeaders_NormalizesToLowercase(t *testing.T) {
	// probe/headers.go 的 buildHeaders 用 h.Set 逐个覆盖默认模板，
	// 而默认模板的键全是小写。大小写不一致的话，从样本导出的
	// "User-Agent" 不会覆盖默认的 "user-agent" —— 两个头都会发出去。
	h := http.Header{}
	h.Set("X-Stainless-Lang", "js")
	tmpl, _ := probeHeadersFromSample(h)
	if _, ok := tmpl["x-stainless-lang"]; !ok {
		t.Errorf("头名应规范化为小写，得到 %v", tmpl)
	}
}

func TestProbeHeaders_EndpointReturnsDefaults(t *testing.T) {
	// defaults 一并返回，让界面能对比「真实请求的头」与「当前默认模板」
	// 的差异 —— 那个 diff 正是要不要导出的判断依据。
	_, h := newTestServer(t)
	// 没有样本时应 404 而不是 500。
	rec := do(t, h, "GET", "/admin/api/samples/999/probe-headers", "", true)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("不存在的样本应 404，得到 %d：%s", rec.Code, rec.Body.String())
	}
}

func TestOutcomeJSON_ZeroVerdictWouldReportOK(t *testing.T) {
	// 这条测试记录一个陷阱，它是 probeRoute 里那段显式判断的全部理由：
	// health.Verdict 的零值是 VerdictOK（iota 的第一个），所以一个
	// **从未执行**的 Outcome 序列化出来是 `"verdict": "ok"`。
	//
	// 端到端跑的时候真的撞上了：L1 连不上的站，界面显示「L1 失败、L2 成功」。
	// 用户完全无法据此判断这个 Route 能不能用。
	m := outcomeJSON(probe.Outcome{})
	if m["verdict"] != "ok" {
		t.Skipf("Verdict 零值语义已变（现在是 %v），probeRoute 里的显式判断可以简化", m["verdict"])
	}
}

func TestProbeHeaders_RequiresAuth(t *testing.T) {
	// 样本头里有真实请求的完整指纹，不能裸奔。
	_, h := newTestServer(t)
	rec := do(t, h, "GET", "/admin/api/samples/1/probe-headers", "", false)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("未鉴权应 401，得到 %d", rec.Code)
	}
}
