package proxy

import (
	"bytes"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/279814/relay-gate/internal/transform"
)

var modelRewriteRules = []transform.Rule{
	{Kind: transform.KindReplaceBytes, From: `"model":"claude-opus-5"`, To: `"model":"rewritten"`},
}

// publishRequestTransform binds rules to routeID on the harness Endpoint (ID 1).
func (hs *harness) publishRequestTransform(t *testing.T, routeID int64, rules []transform.Rule) {
	t.Helper()
	reg := transform.NewRegistry(8)
	set, err := reg.CreateSet("compressed-req")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, routeID, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)
}

// §6.7: original compressed bytes pass only with no mapping and no request
// body transform. A body transform is refused like a mapping: 415, fixed
// phrase, nothing sent, the transform never sees the gzip bytes.
func TestCompressedRequest_BodyTransformRouteReturns415WithoutUpstream(t *testing.T) {
	hits := []*atomic.Int32{{}}
	hs := newHarness(t, hitsByRoute(hits))
	hs.setMappingRoutes("")
	hs.publishRequestTransform(t, 100, modelRewriteRules)
	gz := gzipRequestBody(t, compressedReqBody)

	rec := hs.serve(hs.encodedRequest("/v1/messages", "gzip", gz))
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415; body=%s", rec.Code, rec.Body.String())
	}
	if n := hits[0].Load(); n != 0 {
		t.Fatalf("upstream hits = %d, want 0", n)
	}
	body := rec.Body.String()
	if !strings.Contains(body, msgCompressedNeedsTransform) {
		t.Fatalf("415 body = %s, want fixed phrase %q", body, msgCompressedNeedsTransform)
	}
	if bytes.Contains(rec.Body.Bytes(), gz[:10]) || strings.Contains(body, "gzip:") {
		t.Fatalf("415 body echoes compressed bytes or decoder error: %s", body)
	}
	if _, open, _ := hs.health.stats(); open != 0 {
		t.Fatalf("concurrency slots leaked: open = %d", open)
	}
}

// Per Route: skip the transform Route and pass the original bytes through a
// later Route with no mapping and no transform.
func TestCompressedRequest_SkipsBodyTransformRouteForPlainRoute(t *testing.T) {
	hits := []*atomic.Int32{{}, {}}
	hs := newHarness(t, hitsByRoute(hits))
	hs.setMappingRoutes("", "")
	hs.cfg.settings.RetryMaxAttempts = 1
	hs.publishRequestTransform(t, 100, modelRewriteRules)
	gz := gzipRequestBody(t, compressedReqBody)

	rec := hs.serve(hs.encodedRequest("/v1/messages", "gzip", gz))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 from the plain Route; body=%s", rec.Code, rec.Body.String())
	}
	if n := hits[0].Load(); n != 0 {
		t.Fatalf("transform Route hits = %d, want 0", n)
	}
	if n := hits[1].Load(); n != 1 {
		t.Fatalf("plain Route hits = %d, want 1", n)
	}
	if !bytes.Equal(hs.gotReq.body, gz) {
		t.Fatal("plain Route must receive the original gzip bytes")
	}
	if got := hs.gotReq.headers.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("upstream Content-Encoding = %q, want gzip", got)
	}
}

// A header-only request transform is not a body transform: the compressed
// bytes and Content-Encoding still pass, and the header rule applies.
func TestCompressedRequest_HeaderOnlyTransformPassesOriginalBytes(t *testing.T) {
	hits := []*atomic.Int32{{}}
	hs := newHarness(t, hitsByRoute(hits))
	hs.setMappingRoutes("")
	hs.publishRequestTransform(t, 100, []transform.Rule{
		{Kind: transform.KindSetHeader, Name: "X-Demo", Value: "yes"},
	})
	gz := gzipRequestBody(t, compressedReqBody)

	rec := hs.serve(hs.encodedRequest("/v1/messages", "gzip", gz))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(hs.gotReq.body, gz) {
		t.Fatal("header-only transform must leave the original gzip bytes")
	}
	if got := hs.gotReq.headers.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("upstream Content-Encoding = %q, want gzip", got)
	}
	if got := hs.gotReq.headers.Get("X-Demo"); got != "yes" {
		t.Fatalf("upstream X-Demo = %q, want yes", got)
	}
}

// The same body transform still rewrites an uncompressed body.
func TestCompressedRequest_UncompressedBodyTransformStillApplies(t *testing.T) {
	hits := []*atomic.Int32{{}}
	hs := newHarness(t, hitsByRoute(hits))
	hs.setMappingRoutes("")
	hs.publishRequestTransform(t, 100, modelRewriteRules)

	rec := hs.serve(hs.anthropicRequest(compressedReqBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	want := strings.Replace(compressedReqBody, `"model":"claude-opus-5"`, `"model":"rewritten"`, 1)
	if string(hs.gotReq.body) != want {
		t.Fatalf("upstream body =\n%s\nwant\n%s", hs.gotReq.body, want)
	}
}
