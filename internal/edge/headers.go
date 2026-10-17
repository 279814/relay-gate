// Package edge authenticates metadata from the explicitly configured HTTPS edge.
package edge

import (
	"net/http"
	"strings"
)

const SessionCookieName = "relay_session"

// IsForwardingHeader identifies edge metadata, never an upstream business header.
func IsForwardingHeader(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	return name == "forwarded" || name == "x-real-ip" || strings.HasPrefix(name, "x-forwarded-")
}

func StripForwardingHeaders(headers http.Header) {
	for name := range headers {
		if IsForwardingHeader(name) {
			delete(headers, name)
		}
	}
}
