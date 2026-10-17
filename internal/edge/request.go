package edge

import "net/http"

type requestContextKey struct{}

type requestMetadata struct {
	clientIP string
}

// ClientIP returns only metadata authenticated by Policy.Wrap, never a raw
// forwarding header supplied by the caller.
func ClientIP(request *http.Request) (string, bool) {
	metadata, ok := request.Context().Value(requestContextKey{}).(requestMetadata)
	return metadata.clientIP, ok
}

func IsHTTPS(request *http.Request) bool {
	_, trusted := ClientIP(request)
	return trusted || request.TLS != nil
}
