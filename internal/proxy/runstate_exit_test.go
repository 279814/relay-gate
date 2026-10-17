package proxy

import (
	"net/http"
	"sync/atomic"
	"testing"
)

func TestForwardingWithoutControllerFailsClosed(t *testing.T) {
	var hits atomic.Int32
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(200) })
	hs.h.WithRunState(nil)
	for _, path := range []string{"/v1/messages", "/v1/responses", "/v1/chat/completions", "/v1/messages/count_tokens"} {
		r := hs.anthropicRequest(`{"model":"claude-opus-5","messages":[],"max_tokens":1}`)
		r.URL.Path = path
		response := hs.serve(r)
		if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") == "" || hits.Load() != 0 {
			t.Fatalf("path=%s missing Controller admitted request: status=%d hits=%d body=%s", path, response.Code, hits.Load(), response.Body.String())
		}
	}
}
