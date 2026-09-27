package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/credential"
	"github.com/279814/relay-gate/internal/store"
)

// loginSession 用 testAdminPW 登录并返回会话 Cookie。
func loginSession(t *testing.T, h http.Handler) *http.Cookie {
	t.Helper()
	rec := do(t, h, "POST", "/admin/api/login", `{"password":"`+testAdminPW+`"}`, false)
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			return c
		}
	}
	t.Fatalf("login did not issue session cookie: %d %s", rec.Code, rec.Body.String())
	return nil
}

// doSession 带会话 Cookie 发请求，不带 Bearer。
func doSession(t *testing.T, h http.Handler, method, path, body string, sess *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.AddCookie(sess)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

var sensitiveCredentialRoutes = []string{
	"/admin/api/credentials/reveal-master",
	"/admin/api/credentials/reveal-relay",
	"/admin/api/credentials/rotate-relay",
	"/admin/api/credentials/revoke-relay-grace",
	"/admin/api/credentials/reset-admin",
	"/admin/api/credentials/rotate-master",
}

// TestSensitiveCredentials_RejectBearerWithoutSession pins §12.9: sensitive
// reveal/rotate accepts only a Cookie session plus the per-request admin
// password; Bearer or X-Admin-Password, even with the password in the body,
// must be rejected with the admin auth 401.
func TestSensitiveCredentials_RejectBearerWithoutSession(t *testing.T) {
	_, h := newTestServer(t)
	body := `{"password":"` + testAdminPW + `","new_master":"new-master-at-least-16-chars"}`
	for _, p := range sensitiveCredentialRoutes {
		rec := do(t, h, "POST", p, body, true)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Bearer-only POST %s want 401, got %d body=%s", p, rec.Code, rec.Body.String())
		}

		req := httptest.NewRequest("POST", p, strings.NewReader(body))
		req.Header.Set("X-Admin-Password", testAdminPW)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("X-Admin-Password-only POST %s want 401, got %d body=%s", p, rec.Code, rec.Body.String())
		}
	}

	if rec := do(t, h, "GET", "/admin/api/credentials", "", true); rec.Code == http.StatusUnauthorized {
		t.Fatalf("ordinary admin GET must still accept Bearer, got 401")
	}
}

// TestSensitiveCredentials_SessionNeedsPerRequestPassword: a Cookie session
// alone does not reveal; the session plus the password does.
func TestSensitiveCredentials_SessionNeedsPerRequestPassword(t *testing.T) {
	c, err := store.NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "api.db"), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	const raw = "rk_session_reveal_value_32bytes"
	creds := credential.New().WithEnvelope(c)
	if err := creds.SetActiveRelayKey(raw); err != nil {
		t.Fatal(err)
	}
	s := New(st, slog.New(slog.NewTextHandler(io.Discard, nil))).WithCredentials(creds, nil)
	h := s.Routes(testAdminPW)
	sess := loginSession(t, h)

	bearer := do(t, h, "POST", "/admin/api/credentials/reveal-relay",
		`{"password":"`+testAdminPW+`"}`, true)
	if bearer.Code != http.StatusUnauthorized || strings.Contains(bearer.Body.String(), raw) {
		t.Fatalf("Bearer + password without session must be 401, got %d body=%s", bearer.Code, bearer.Body.String())
	}

	for _, body := range []string{`{}`, `{"password":""}`} {
		rec := doSession(t, h, "POST", "/admin/api/credentials/reveal-relay", body, sess)
		if rec.Code == http.StatusOK || strings.Contains(rec.Body.String(), raw) {
			t.Fatalf("session without password must not reveal, got %d body=%s", rec.Code, rec.Body.String())
		}
	}

	ok := doSession(t, h, "POST", "/admin/api/credentials/reveal-relay",
		`{"password":"`+testAdminPW+`"}`, sess)
	if ok.Code != http.StatusOK || !strings.Contains(ok.Body.String(), raw) {
		t.Fatalf("session + password want 200 with key, got %d body=%s", ok.Code, ok.Body.String())
	}
}
