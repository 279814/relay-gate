package proxy

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/router"
)

const compressedReqBody = `{"max_tokens":1,"model":"claude-opus-5","messages":[{"role":"user","content":"x"}]}`

func gzipRequestBody(t *testing.T, plain string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(plain)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func (hs *harness) encodedRequest(path, encoding string, body []byte) *http.Request {
	r := httptest.NewRequest("POST", path, bytes.NewReader(body))
	r.Header = claudeCodeHeaders()
	r.Header.Set("X-Api-Key", hs.relayPW)
	r.Header.Set("Content-Encoding", encoding)
	return r
}

// setMappingRoutes installs one Route per entry; mappings[i] is that Route's
// upstream_model ("" = no mapping). Route i has priority i+1 and its own
// Upstream (ID 10+i) keyed so the mock can tell which one was hit.
func (hs *harness) setMappingRoutes(mappings ...string) {
	mn := &model.ModelName{ID: 1, Name: "claude-opus-5",
		Protocol: model.ProtoAnthropic, MatchMode: model.MatchExact, Enabled: true}
	var ups []*model.Upstream
	var routes []*model.Route
	for i, m := range mappings {
		ups = append(ups, &model.Upstream{ID: int64(10 + i), Name: "up", BaseURL: hs.up.URL,
			APIKey: routeKey(i), AuthStyle: model.AuthBearer, Enabled: true})
		routes = append(routes, &model.Route{ID: int64(100 + i), ModelNameID: 1,
			UpstreamID: int64(10 + i), Priority: i + 1, Weight: 100, Enabled: true, UpstreamModel: m})
	}
	hs.cfg.snap = router.BuildSnapshot([]*model.ModelName{mn}, ups, routes)
}

func routeKey(i int) string { return "sk-compressed-route-key-" + string(rune('a'+i)) }

func hitsByRoute(hits []*atomic.Int32) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for i := range hits {
			if r.Header.Get("Authorization") == "Bearer "+routeKey(i) {
				hits[i].Add(1)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"msg_1","type":"message"}`))
	}
}

// §6.7: a compressed request on a Route that maps the model is 415 in strict
// mode, with no upstream contact and a fixed body (no gzip bytes or error).
func TestCompressedRequest_MappingRouteReturns415WithoutUpstream(t *testing.T) {
	hits := []*atomic.Int32{{}}
	hs := newHarness(t, hitsByRoute(hits))
	hs.setMappingRoutes("glm-4.6")
	gz := gzipRequestBody(t, compressedReqBody)

	rec := hs.serve(hs.encodedRequest("/v1/messages", "gzip", gz))
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415; body=%s", rec.Code, rec.Body.String())
	}
	if n := hits[0].Load(); n != 0 {
		t.Fatalf("upstream hits = %d, want 0", n)
	}
	body := rec.Body.String()
	if !strings.Contains(body, msgCompressedNeedsMapping) {
		t.Fatalf("415 body = %s, want fixed phrase %q", body, msgCompressedNeedsMapping)
	}
	if bytes.Contains(rec.Body.Bytes(), gz[:10]) || strings.Contains(body, "gzip:") {
		t.Fatalf("415 body echoes compressed bytes or decoder error: %s", body)
	}
	if _, open, _ := hs.health.stats(); open != 0 {
		t.Fatalf("concurrency slots leaked: open = %d", open)
	}
}

// §6.7: no mapping → original compressed bytes and Content-Encoding forwarded.
func TestCompressedRequest_NoMappingPassesThroughUnchanged(t *testing.T) {
	hits := []*atomic.Int32{{}}
	hs := newHarness(t, hitsByRoute(hits))
	hs.setMappingRoutes("")
	gz := gzipRequestBody(t, compressedReqBody)

	rec := hs.serve(hs.encodedRequest("/v1/messages", "gzip", gz))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(hs.gotReq.body, gz) {
		t.Fatalf("upstream body changed: got %d bytes, want the original %d gzip bytes",
			len(hs.gotReq.body), len(gz))
	}
	if got := hs.gotReq.headers.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("upstream Content-Encoding = %q, want gzip", got)
	}
}

// Mapping is per Route: skip the mapping Route (no contact) and pass the
// original bytes through the later Route that has no mapping.
func TestCompressedRequest_SkipsMappingRouteForUnmappedRoute(t *testing.T) {
	hits := []*atomic.Int32{{}, {}}
	hs := newHarness(t, hitsByRoute(hits))
	hs.setMappingRoutes("glm-4.6", "")
	hs.cfg.settings.RetryMaxAttempts = 1
	gz := gzipRequestBody(t, compressedReqBody)

	rec := hs.serve(hs.encodedRequest("/v1/messages", "gzip", gz))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 from the unmapped Route; body=%s", rec.Code, rec.Body.String())
	}
	if n := hits[0].Load(); n != 0 {
		t.Fatalf("mapping Route hits = %d, want 0", n)
	}
	if n := hits[1].Load(); n != 1 {
		t.Fatalf("unmapped Route hits = %d, want 1", n)
	}
	if !bytes.Equal(hs.gotReq.body, gz) {
		t.Fatal("unmapped Route must receive the original gzip bytes")
	}
}

// Every eligible Route maps the model → one 415, nothing sent.
func TestCompressedRequest_AllRoutesMapReturns415(t *testing.T) {
	hits := []*atomic.Int32{{}, {}}
	hs := newHarness(t, hitsByRoute(hits))
	hs.setMappingRoutes("glm-4.6", "glm-4.5")
	gz := gzipRequestBody(t, compressedReqBody)

	rec := hs.serve(hs.encodedRequest("/v1/messages", "gzip", gz))
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415; body=%s", rec.Code, rec.Body.String())
	}
	if n := hits[0].Load() + hits[1].Load(); n != 0 {
		t.Fatalf("upstream hits = %d, want 0", n)
	}
}

// Uncompressed JSON with a mapping still rewrites only the model bytes (§6.3).
func TestCompressedRequest_UncompressedMappingStillRewrites(t *testing.T) {
	hits := []*atomic.Int32{{}}
	hs := newHarness(t, hitsByRoute(hits))
	hs.setMappingRoutes("glm-4.6")

	rec := hs.serve(hs.anthropicRequest(compressedReqBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	want := strings.Replace(compressedReqBody, `"claude-opus-5"`, `"glm-4.6"`, 1)
	if string(hs.gotReq.body) != want {
		t.Fatalf("upstream body =\n%s\nwant\n%s", hs.gotReq.body, want)
	}
}

// §6.7: unsupported Content-Encoding is 415 before routing.
func TestCompressedRequest_UnsupportedEncodingReturns415(t *testing.T) {
	hits := []*atomic.Int32{{}}
	hs := newHarness(t, hitsByRoute(hits))
	hs.setMappingRoutes("")

	for _, enc := range []string{"deflate", "zstd", "gzip, br"} {
		rec := hs.serve(hs.encodedRequest("/v1/messages", enc, []byte(compressedReqBody)))
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("%s: status = %d, want 415; body=%s", enc, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), msgUnsupportedBodyEncoding) {
			t.Fatalf("%s: body = %s, want fixed phrase", enc, rec.Body.String())
		}
	}
	if n := hits[0].Load(); n != 0 {
		t.Fatalf("upstream hits = %d, want 0", n)
	}
}

// A body that claims gzip but is not decodable is a fixed-text 400, not sent.
func TestCompressedRequest_CorruptGzipIs400(t *testing.T) {
	hits := []*atomic.Int32{{}}
	hs := newHarness(t, hitsByRoute(hits))
	hs.setMappingRoutes("")

	rec := hs.serve(hs.encodedRequest("/v1/messages", "gzip", []byte(compressedReqBody)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "gzip:") || strings.Contains(rec.Body.String(), "claude-opus-5") {
		t.Fatalf("400 body echoes decoder error or body: %s", rec.Body.String())
	}
	if n := hits[0].Load(); n != 0 {
		t.Fatalf("upstream hits = %d, want 0", n)
	}
}

// count_tokens never sends a compressed body to a mapping Route; with no
// other Route it answers from the local estimate over the decoded copy.
func TestCompressedRequest_CountTokensMappingRouteFallsBackLocal(t *testing.T) {
	hits := []*atomic.Int32{{}}
	hs := newHarness(t, hitsByRoute(hits))
	hs.setMappingRoutes("glm-4.6")
	gz := gzipRequestBody(t, compressedReqBody)

	rec := hs.serve(hs.encodedRequest("/v1/messages/count_tokens", "gzip", gz))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 local estimate; body=%s", rec.Code, rec.Body.String())
	}
	if n := hits[0].Load(); n != 0 {
		t.Fatalf("upstream hits = %d, want 0", n)
	}
	if n := decodeInputTokens(t, rec.Body.String()); n <= 0 {
		t.Fatalf("input_tokens = %d, want > 0 from the decoded body", n)
	}
}
