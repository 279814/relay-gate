package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPolicyRejectsBroadOrIncompleteTrustConfiguration(t *testing.T) {
	for _, value := range []struct{ peers, origin string }{
		{"0.0.0.0/0", "https://203.0.113.50"}, {"::/0", "https://203.0.113.50"},
		{"0.0.0.0", "https://203.0.113.50"}, {"::", "https://203.0.113.50"},
		{"172.30.187.2", ""}, {"", "https://203.0.113.50"},
		{"172.30.187.2", "http://203.0.113.50"}, {"172.30.187.2", "https://user@203.0.113.50"},
		{"172.30.187.2", "https://203.0.113.50/path"}, {"172.30.187.2", "https://203.0.113.50?private=value"},
		{"172.30.187.2", "https://203.0.113.50:0"}, {"172.30.187.2", "https://203.0.113.50:65536"},
	} {
		if _, err := NewPolicy(value.peers, value.origin); err == nil {
			t.Errorf("accepted unsafe edge configuration peers=%q origin=%q", value.peers, value.origin)
		}
	}
	if policy, err := NewPolicy("", ""); err != nil || policy != nil {
		t.Fatal("default HTTP configuration must remain disabled")
	}
}

func trustedRequest(method, path string) *http.Request {
	request := httptest.NewRequest(method, path, nil)
	request.RemoteAddr = "172.30.187.2:45000"
	request.Header.Set("X-Forwarded-For", "198.51.100.7")
	request.Header.Set("X-Forwarded-Proto", "https")
	return request
}

func TestPolicyRequiresExactPeerAndUnambiguousMetadata(t *testing.T) {
	policy, err := NewPolicy("172.30.187.2", "https://203.0.113.50")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []struct {
		name   string
		modify func(*http.Request)
		status int
	}{
		{"trusted", func(*http.Request) {}, 200},
		{"untrusted", func(r *http.Request) { r.RemoteAddr = "198.51.100.8:45000" }, 403},
		{"missing IP", func(r *http.Request) { r.Header.Del("X-Forwarded-For") }, 400},
		{"IP chain", func(r *http.Request) { r.Header.Set("X-Forwarded-For", "198.51.100.7, 203.0.113.9") }, 400},
		{"duplicate IP", func(r *http.Request) { r.Header.Add("X-Forwarded-For", "203.0.113.9") }, 400},
		{"IP with port", func(r *http.Request) { r.Header.Set("X-Forwarded-For", "198.51.100.7:80") }, 400},
		{"case duplicate", func(r *http.Request) { r.Header["x-forwarded-for"] = []string{"203.0.113.9"} }, 400},
		{"missing HTTPS", func(r *http.Request) { r.Header.Del("X-Forwarded-Proto") }, 400},
		{"plaintext", func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "http") }, 400},
		{"proto chain", func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "https,http") }, 400},
		{"duplicate proto", func(r *http.Request) { r.Header.Add("X-Forwarded-Proto", "https") }, 400},
	} {
		t.Run(value.name, func(t *testing.T) {
			request := trustedRequest(http.MethodPost, "/v1/messages")
			request.Header.Set("Forwarded", "for=private-client;proto=http")
			request.Header.Set("X-Forwarded-Host", "attacker.example")
			request.Header.Set("User-Agent", "fixture-native-client")
			value.modify(request)
			called := false
			handler := policy.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				if ip, ok := ClientIP(r); !ok || ip != "198.51.100.7" || !IsHTTPS(r) {
					t.Fatal("trusted metadata was not authenticated")
				}
				for name := range r.Header {
					if IsForwardingHeader(name) {
						t.Fatalf("raw forwarding metadata remained visible: %s", name)
					}
				}
				if r.Header.Get("User-Agent") != "fixture-native-client" {
					t.Fatal("ordinary header changed")
				}
				w.WriteHeader(http.StatusOK)
			}))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != value.status || called != (value.status == 200) {
				t.Fatalf("status=%d handler_called=%v", response.Code, called)
			}
		})
	}
}

func TestPolicyEnforcesFixedOriginForCookieWrites(t *testing.T) {
	policy, err := NewPolicy("172.30.187.2", "https://203.0.113.50")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []struct {
		name, origin, referer string
		cookie                bool
		status                int
	}{
		{"same origin", "https://203.0.113.50", "", true, 200},
		{"canonical HTTPS port", "https://203.0.113.50:443", "", true, 200},
		{"cross origin", "https://attacker.example", "", true, 403},
		{"same IP different port", "https://203.0.113.50:4444", "", true, 403},
		{"same IP plaintext origin", "http://203.0.113.50", "", true, 403},
		{"opaque origin", "null", "", true, 403},
		{"origin credentials", "https://private@203.0.113.50", "", true, 403},
		{"same referer", "", "https://203.0.113.50/admin/", true, 200},
		{"cross referer", "", "https://attacker.example/admin/", true, 403},
		{"missing browser origin", "", "", true, 403},
		{"CLI without ambient cookie", "", "", false, 200},
		{"cross origin login", "https://attacker.example", "", false, 403},
	} {
		t.Run(value.name, func(t *testing.T) {
			request := trustedRequest(http.MethodPost, "/admin/api/login")
			request.Host = "attacker.example" // The request Host cannot redefine the allowed public origin.
			if value.origin != "" {
				request.Header.Set("Origin", value.origin)
			}
			if value.referer != "" {
				request.Header.Set("Referer", value.referer)
			}
			if value.cookie {
				request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "fixture-session"})
			}
			response := httptest.NewRecorder()
			policy.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })).ServeHTTP(response, request)
			if response.Code != value.status {
				t.Fatalf("status=%d want %d", response.Code, value.status)
			}
		})
	}
}

func TestPolicyLeavesUnauthenticatedLocalHealthAvailable(t *testing.T) {
	policy, err := NewPolicy("172.30.187.2", "https://203.0.113.50")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	request.RemoteAddr = "127.0.0.1:45000"
	response := httptest.NewRecorder()
	policy.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, trusted := ClientIP(r); trusted || IsHTTPS(r) {
			t.Fatal("local health forged edge identity")
		}
		w.WriteHeader(200)
	})).ServeHTTP(response, request)
	if response.Code != 200 {
		t.Fatalf("health status=%d", response.Code)
	}
}

func TestPolicyCanonicalizesIPv6OriginAndClientAddress(t *testing.T) {
	policy, err := NewPolicy("fd00::2", "https://[2001:db8::50]")
	if err != nil {
		t.Fatal(err)
	}
	request := trustedRequest(http.MethodPost, "/admin/api/login")
	request.RemoteAddr = "[fd00::2]:45000"
	request.Header.Set("X-Forwarded-For", "2001:0db8:0:0:0:0:0:7")
	request.Header.Set("Origin", "https://[2001:0db8::50]:443")
	response := httptest.NewRecorder()
	policy.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ip, trusted := ClientIP(r); !trusted || ip != "2001:db8::7" || !IsHTTPS(r) {
			t.Fatal("IPv6 edge identity was not normalized")
		}
		w.WriteHeader(200)
	})).ServeHTTP(response, request)
	if response.Code != 200 {
		t.Fatalf("IPv6 HTTPS status=%d", response.Code)
	}
}
