package edge

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Policy is opt-in: forwarding metadata has authority only when both the
// transport peer and the fixed public HTTPS origin were configured at startup.
type Policy struct {
	trusted map[netip.Addr]struct{}
	origin  string
}

func NewPolicy(trustedIPsCSV, publicOrigin string) (*Policy, error) {
	trustedIPsCSV, publicOrigin = strings.TrimSpace(trustedIPsCSV), strings.TrimSpace(publicOrigin)
	if trustedIPsCSV == "" && publicOrigin == "" {
		return nil, nil
	}
	if trustedIPsCSV == "" || publicOrigin == "" {
		return nil, errors.New("RELAY_TRUSTED_PROXY_IPS and RELAY_PUBLIC_ORIGIN must be configured together")
	}
	origin, err := canonicalOrigin(publicOrigin, false)
	if err != nil {
		return nil, errors.New("RELAY_PUBLIC_ORIGIN must be one HTTPS IP origin without credentials, path or query")
	}
	policy := &Policy{trusted: map[netip.Addr]struct{}{}, origin: origin}
	for _, raw := range strings.Split(trustedIPsCSV, ",") {
		address, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil || address.Zone() != "" {
			return nil, errors.New("RELAY_TRUSTED_PROXY_IPS requires exact internal IP addresses, never CIDR ranges")
		}
		address = address.Unmap()
		if address.IsUnspecified() || (!address.IsPrivate() && !address.IsLoopback()) {
			return nil, errors.New("RELAY_TRUSTED_PROXY_IPS requires explicit private or loopback edge addresses")
		}
		policy.trusted[address] = struct{}{}
	}
	return policy, nil
}

// Wrap keeps the public backend behind its edge. Health remains available to
// the container's local probe; all business requests require authenticated edge
// metadata. Request Host and external Forwarded headers never define trust.
func (p *Policy) Wrap(next http.Handler) http.Handler {
	if p == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			next.ServeHTTP(w, r)
			return
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		peer, parseErr := netip.ParseAddr(host)
		if err != nil || parseErr != nil || peer.Zone() != "" {
			reject(w, http.StatusForbidden, "请求必须经过已配置的 HTTPS 边缘")
			return
		}
		if _, trusted := p.trusted[peer.Unmap()]; !trusted {
			reject(w, http.StatusForbidden, "请求必须经过已配置的 HTTPS 边缘")
			return
		}
		forwarded := headerValues(r.Header, "X-Forwarded-For")
		proto := headerValues(r.Header, "X-Forwarded-Proto")
		if len(forwarded) != 1 || len(proto) != 1 || strings.TrimSpace(proto[0]) != "https" {
			reject(w, http.StatusBadRequest, "HTTPS 边缘元数据缺失或不唯一")
			return
		}
		clientIP, err := netip.ParseAddr(strings.TrimSpace(forwarded[0]))
		if err != nil || clientIP.Zone() != "" || clientIP.IsUnspecified() || clientIP.IsMulticast() {
			reject(w, http.StatusBadRequest, "HTTPS 边缘来源地址无效")
			return
		}
		if (r.URL.Path == "/admin/api" || strings.HasPrefix(r.URL.Path, "/admin/api/")) && !p.sameOrigin(r) {
			reject(w, http.StatusForbidden, "管理请求必须来自已配置的 HTTPS 同源页面")
			return
		}
		request := r.Clone(context.WithValue(r.Context(), requestContextKey{}, requestMetadata{clientIP: clientIP.Unmap().String()}))
		StripForwardingHeaders(request.Header)
		next.ServeHTTP(w, request)
	})
}

func (p *Policy) sameOrigin(request *http.Request) bool {
	origins := headerValues(request.Header, "Origin")
	if len(origins) > 0 {
		if len(origins) != 1 {
			return false
		}
		origin, err := canonicalOrigin(origins[0], false)
		return err == nil && origin == p.origin
	}
	if request.Method == http.MethodGet || request.Method == http.MethodHead || request.Method == http.MethodOptions {
		return true
	}
	referers := headerValues(request.Header, "Referer")
	if len(referers) > 0 {
		if len(referers) != 1 {
			return false
		}
		origin, err := canonicalOrigin(referers[0], true)
		return err == nil && origin == p.origin
	}
	// Scripts with explicit credentials remain supported. Browser writes that
	// automatically carry an existing session must prove their same origin.
	cookie, err := request.Cookie(SessionCookieName)
	return err != nil || cookie.Value == ""
}

func canonicalOrigin(raw string, referer bool) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" {
		return "", errors.New("invalid HTTPS origin")
	}
	if !referer && (parsed.Path != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "") {
		return "", errors.New("origin contains non-origin components")
	}
	address, err := netip.ParseAddr(parsed.Hostname())
	if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
		return "", errors.New("origin must identify one IP address")
	}
	host := address.Unmap().String()
	if address.Unmap().Is6() {
		host = "[" + host + "]"
	}
	port := parsed.Port()
	if port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return "", errors.New("invalid origin port")
		}
		if value != 443 {
			host = net.JoinHostPort(address.Unmap().String(), strconv.Itoa(value))
		}
	} else if strings.HasSuffix(parsed.Host, ":") {
		return "", errors.New("empty origin port")
	}
	return "https://" + host, nil
}

func headerValues(headers http.Header, wanted string) []string {
	var values []string
	for name, items := range headers {
		if strings.EqualFold(name, wanted) {
			values = append(values, items...)
		}
	}
	return values
}

func reject(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
