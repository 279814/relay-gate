package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/edge"
)

func TestLogin_DirectTLSUsesSecureSessionCookie(t *testing.T) {
	_, handler := newTestServer(t)
	request := httptest.NewRequest(http.MethodPost, "https://203.0.113.50/admin/api/login", strings.NewReader(`{"password":"`+testAdminPW+`"}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("TLS login failed: %d", response.Code)
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == sessionCookie {
			if !cookie.Secure {
				t.Fatal("HTTPS login issued an insecure session cookie")
			}
			return
		}
	}
	t.Fatal("TLS login did not issue a session cookie")
}

func publicAPIRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, "http://backend.internal"+path, strings.NewReader(body))
	request.RemoteAddr = "172.30.187.2:45000"
	request.Header.Set("X-Forwarded-For", "198.51.100.7")
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("Origin", "https://203.0.113.50")
	return request
}

func publicAPIHandler(t *testing.T, handler http.Handler) http.Handler {
	t.Helper()
	policy, err := edge.NewPolicy("172.30.187.2", "https://203.0.113.50")
	if err != nil {
		t.Fatal(err)
	}
	return policy.Wrap(handler)
}

func TestLogin_TrustedEdgeKeepsClientFailureBucketsSeparate(t *testing.T) {
	s, handler := newTestServer(t)
	handler = publicAPIHandler(t, handler)
	for _, ip := range []string{"198.51.100.7", "198.51.100.8"} {
		request := publicAPIRequest(http.MethodPost, "/admin/api/login", `{"password":"wrong"}`)
		request.Header.Set("X-Forwarded-For", ip)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("wrong password status=%d", response.Code)
		}
	}
	s.sessions.mu.Lock()
	first, second, edgeBucket := s.sessions.ipFailures["198.51.100.7"], s.sessions.ipFailures["198.51.100.8"], s.sessions.ipFailures["172.30.187.2"]
	s.sessions.mu.Unlock()
	if first != 1 || second != 1 || edgeBucket != 0 {
		t.Fatalf("trusted client buckets=%d/%d edge=%d", first, second, edgeBucket)
	}
	request := publicAPIRequest(http.MethodPost, "/admin/api/login", `{"password":"`+testAdminPW+`"}`)
	request.RemoteAddr = "172.30.187.20:45000"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || len(response.Result().Cookies()) != 0 {
		t.Fatalf("nearby but untrusted peer was accepted: %d", response.Code)
	}
}

func TestPublicAdmin_RejectsCrossOriginBeforeMutatingStorage(t *testing.T) {
	s, handler := newTestServer(t)
	handler = publicAPIHandler(t, handler)
	login := httptest.NewRecorder()
	handler.ServeHTTP(login, publicAPIRequest(http.MethodPost, "/admin/api/login", `{"password":"`+testAdminPW+`"}`))
	var session *http.Cookie
	for _, cookie := range login.Result().Cookies() {
		if cookie.Name == sessionCookie {
			session = cookie
		}
	}
	if session == nil || !session.Secure {
		t.Fatal("trusted HTTPS login did not issue a secure cookie")
	}
	request := publicAPIRequest(http.MethodPost, "/admin/api/upstreams", `{"name":"cross-origin-write","base_url":"https://fixture.example","api_key":"sk-cross-origin-fixture"}`)
	request.AddCookie(session)
	request.Header.Set("Origin", "https://attacker.example")
	request.Host = "attacker.example"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-origin session write status=%d", response.Code)
	}
	values, err := s.st.ListUpstreams()
	if err != nil || len(values) != 0 {
		t.Fatalf("cross-origin write reached database: count=%d err=%v", len(values), err)
	}
	request = publicAPIRequest(http.MethodPost, "/admin/api/upstreams", `{"name":"same-origin-write","base_url":"https://fixture.example","api_key":"sk-same-origin-fixture"}`)
	request.AddCookie(session)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("same-origin session write failed: %d", response.Code)
	}
	request = publicAPIRequest(http.MethodPost, "/admin/api/upstreams", `{"name":"explicit-cli-write","base_url":"https://fixture.example","api_key":"sk-explicit-cli-fixture"}`)
	request.Header.Del("Origin")
	request.Header.Set("Authorization", "Bearer "+testAdminPW)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("explicit CLI credentials stopped working: %d", response.Code)
	}
}

func TestPublicAdmin_SessionCookieRemainsSecureOnLogoutAndPasswordReset(t *testing.T) {
	for _, path := range []string{"/admin/api/logout", "/admin/api/credentials/reset-admin"} {
		t.Run(path, func(t *testing.T) {
			_, handler := newTestServer(t)
			handler = publicAPIHandler(t, handler)
			login := httptest.NewRecorder()
			handler.ServeHTTP(login, publicAPIRequest(http.MethodPost, "/admin/api/login", `{"password":"`+testAdminPW+`"}`))
			var session *http.Cookie
			for _, cookie := range login.Result().Cookies() {
				if cookie.Name == sessionCookie {
					session = cookie
				}
			}
			if session == nil {
				t.Fatal("login failed")
			}
			request := publicAPIRequest(http.MethodPost, path, `{"password":"`+testAdminPW+`"}`)
			request.AddCookie(session)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("credential action status=%d", response.Code)
			}
			found := false
			for _, cookie := range response.Result().Cookies() {
				if cookie.Name == sessionCookie {
					found = true
					if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
						t.Fatal("credential action downgraded session cookie flags")
					}
				}
			}
			if !found {
				t.Fatal("credential action did not set its replacement/deletion cookie")
			}
		})
	}
}

func TestLogin_DefaultHTTPDoesNotTrustSpoofedForwardingHeaders(t *testing.T) {
	s, handler := newTestServer(t)
	for _, forged := range []string{"203.0.113.7", "203.0.113.8"} {
		request := httptest.NewRequest(http.MethodPost, "/admin/api/login", strings.NewReader(`{"password":"wrong"}`))
		request.RemoteAddr = "198.51.100.9:45200"
		request.Header.Set("X-Forwarded-For", forged)
		request.Header.Set("X-Forwarded-Proto", "https")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("wrong password accepted: %d", response.Code)
		}
	}
	s.sessions.mu.Lock()
	count, size := s.sessions.ipFailures["198.51.100.9"], len(s.sessions.ipFailures)
	s.sessions.mu.Unlock()
	if count != 2 || size != 1 {
		t.Fatalf("forwarded metadata changed login failure buckets: count=%d buckets=%d", count, size)
	}
	request := httptest.NewRequest(http.MethodPost, "/admin/api/login", strings.NewReader(`{"password":"`+testAdminPW+`"}`))
	request.Header.Set("X-Forwarded-Proto", "https")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == sessionCookie && cookie.Secure {
			t.Fatal("untrusted X-Forwarded-Proto changed the default HTTP cookie")
		}
	}
}
