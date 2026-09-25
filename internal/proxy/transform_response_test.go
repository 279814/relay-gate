package proxy

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/transform"
)

func TestResponseTransform_AppliesPublishedBinding(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream", "raw")
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true,"note":"upstream"}`))
	})
	reg := transform.NewRegistry(8)
	set, err := reg.CreateSet("resp")
	if err != nil {
		t.Fatal(err)
	}
	rules := []transform.Rule{
		{Kind: transform.KindSetHeader, Name: "X-Transformed", Value: "1"},
		{Kind: transform.KindReplaceBytes, From: `"note":"upstream"`, To: `"note":"gateway"`},
		{Kind: transform.KindSetStatus, Value: "201"},
	}
	if _, err := reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailClosed, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","max_tokens":1}`))
	if rec.Code != 201 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Transformed") != "1" {
		t.Fatalf("missing transform header: %v", rec.Header())
	}
	if !strings.Contains(rec.Body.String(), `"note":"gateway"`) {
		t.Fatalf("body not transformed: %s", rec.Body.String())
	}
}

// When replace_bytes changes the body, Content-Encoding must not still claim
// the upstream coding — the client would gunzip/inflate the transformed bytes.
func TestResponseTransform_DropsContentEncodingWhenBodyChanges(t *testing.T) {
	for _, coding := range []string{"gzip", "deflate", "br"} {
		coding := coding
		t.Run(coding, func(t *testing.T) {
			hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Encoding", coding)
				w.WriteHeader(200)
				// Plaintext body with a stale encoding claim (transform does not decompress).
				w.Write([]byte(`{"ok":true,"note":"upstream"}`))
			})
			reg := transform.NewRegistry(4)
			set, err := reg.CreateSet("enc-" + coding)
			if err != nil {
				t.Fatal(err)
			}
			rules := []transform.Rule{
				{Kind: transform.KindReplaceBytes, From: `"note":"upstream"`, To: `"note":"gateway"`},
			}
			if _, err := reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailClosed, ""); err != nil {
				t.Fatal(err)
			}
			if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
				t.Fatal(err)
			}
			hs.h.WithTransforms(reg)

			rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","max_tokens":1}`))
			if rec.Code != 200 {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Content-Encoding"); got != "" {
				t.Fatalf("Content-Encoding=%q want cleared after body transform", got)
			}
			if rec.Header().Get("Content-Length") != "" {
				t.Fatal("Content-Length must stay deleted on transform commit")
			}
			if !strings.Contains(rec.Body.String(), `"note":"gateway"`) {
				t.Fatalf("body not transformed: %s", rec.Body.String())
			}
		})
	}
}

// Header-only response rules leave the body untouched, so upstream
// Content-Encoding must remain (passthrough of the original coding).
func TestResponseTransform_KeepsContentEncodingWhenBodyUnchanged(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	})
	reg := transform.NewRegistry(4)
	set, err := reg.CreateSet("hdr-only")
	if err != nil {
		t.Fatal(err)
	}
	rules := []transform.Rule{
		{Kind: transform.KindSetHeader, Name: "X-Transformed", Value: "1"},
	}
	if _, err := reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailClosed, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","max_tokens":1}`))
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Transformed") != "1" {
		t.Fatalf("missing transform header: %v", rec.Header())
	}
	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding=%q want gzip when body unchanged", got)
	}
	if rec.Body.String() != `{"ok":true}` {
		t.Fatalf("body=%s", rec.Body.String())
	}
}

// When replace_bytes changes the body, upstream Content-MD5 / ETag describe the
// old bytes and must not be forwarded.
func TestResponseTransform_DropsContentMD5AndETagWhenBodyChanges(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-MD5", "d41d8cd98f00b204e9800998ecf8427e")
		w.Header().Set("ETag", `"upstream-body"`)
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true,"note":"upstream"}`))
	})
	reg := transform.NewRegistry(4)
	set, err := reg.CreateSet("md5-etag-change")
	if err != nil {
		t.Fatal(err)
	}
	rules := []transform.Rule{
		{Kind: transform.KindReplaceBytes, From: `"note":"upstream"`, To: `"note":"gateway"`},
	}
	if _, err := reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailClosed, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","max_tokens":1}`))
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-MD5"); got != "" {
		t.Fatalf("Content-MD5=%q want cleared after body transform", got)
	}
	if got := rec.Header().Get("ETag"); got != "" {
		t.Fatalf("ETag=%q want cleared after body transform", got)
	}
	if !strings.Contains(rec.Body.String(), `"note":"gateway"`) {
		t.Fatalf("body not transformed: %s", rec.Body.String())
	}
}

// Header-only response rules leave the body untouched, so upstream Content-MD5
// and ETag must remain.
func TestResponseTransform_KeepsContentMD5AndETagWhenBodyUnchanged(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-MD5", "d41d8cd98f00b204e9800998ecf8427e")
		w.Header().Set("ETag", `"upstream-body"`)
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	})
	reg := transform.NewRegistry(4)
	set, err := reg.CreateSet("md5-etag-keep")
	if err != nil {
		t.Fatal(err)
	}
	rules := []transform.Rule{
		{Kind: transform.KindSetHeader, Name: "X-Transformed", Value: "1"},
	}
	if _, err := reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailClosed, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","max_tokens":1}`))
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Transformed") != "1" {
		t.Fatalf("missing transform header: %v", rec.Header())
	}
	if got := rec.Header().Get("Content-MD5"); got != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Fatalf("Content-MD5=%q want kept when body unchanged", got)
	}
	if got := rec.Header().Get("ETag"); got != `"upstream-body"` {
		t.Fatalf("ETag=%q want kept when body unchanged", got)
	}
	if rec.Body.String() != `{"ok":true}` {
		t.Fatalf("body=%s", rec.Body.String())
	}
}

func TestResponseTransform_UnboundPassthrough(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream", "keep")
		w.Header().Set("Content-MD5", "d41d8cd98f00b204e9800998ecf8427e")
		w.Header().Set("ETag", `"passthrough-body"`)
		w.Write([]byte(`{"ok":true}`))
	})
	reg := transform.NewRegistry(4)
	set, _ := reg.CreateSet("unused")
	_, _ = reg.UpdateDraft(set.ID, []transform.Rule{
		{Kind: transform.KindSetHeader, Name: "X-Should-Not", Value: "x"},
	}, transform.FailClosed, transform.FailOpen, "")
	_, _, _ = reg.PublishSnapshot(set.ID, 999, 999)
	hs.h.WithTransforms(reg)

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","max_tokens":1}`))
	if rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}
	if rec.Header().Get("X-Should-Not") != "" {
		t.Fatal("unbound must not apply transform headers")
	}
	if rec.Header().Get("X-Upstream") != "keep" {
		t.Fatalf("passthrough header lost: %q", rec.Header().Get("X-Upstream"))
	}
	if got := rec.Header().Get("Content-MD5"); got != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Fatalf("Content-MD5=%q want kept on unbound passthrough", got)
	}
	if got := rec.Header().Get("ETag"); got != `"passthrough-body"` {
		t.Fatalf("ETag=%q want kept on unbound passthrough", got)
	}
	if rec.Body.String() != `{"ok":true}` {
		t.Fatalf("body=%s", rec.Body.String())
	}
}

func TestResponseTransform_FailClosedRollsBackBeforeCommit(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})
	reg := transform.NewRegistry(4)
	set, _ := reg.CreateSet("bad")
	rules := []transform.Rule{
		{Kind: transform.KindSetHeader, Name: "X-Partial", Value: "yes"},
		{Kind: transform.KindSetJSONPointer, Name: "/missing", Value: `"x"`},
	}
	if _, err := reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailClosed, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","max_tokens":1}`))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("want 502 fail_closed, got %d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Partial") != "" {
		t.Fatal("partial header must not reach client on fail_closed")
	}
}

func TestSSETransform_AppliesEventsAndSyntheticEnd(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		w.Write([]byte("event: message_start\ndata: {\"type\":\"message_start\"}\n\n"))
		fl.Flush()
		w.Write([]byte("event: content_block_delta\ndata: {\"delta\":\"hi\"}\n\n"))
		fl.Flush()
	})
	reg := transform.NewRegistry(4)
	set, _ := reg.CreateSet("sse")
	rules := []transform.Rule{
		{Kind: transform.KindSSEMatch, Match: "content_block_delta", From: "hi", To: "hello"},
		{Kind: transform.KindSSEAppendEnd, Match: "message_stop", Value: `{"type":"message_stop"}`},
		{Kind: transform.KindSetHeader, Name: "X-SSE-Transformed", Value: "1"},
	}
	if _, err := reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","stream":true}`))
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-SSE-Transformed") != "1" {
		t.Fatalf("header=%v", rec.Header())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"delta":"hello"`) {
		t.Fatalf("sse data not transformed: %s", body)
	}
	if !strings.Contains(body, "event: message_stop") {
		t.Fatalf("missing synthetic end: %s", body)
	}
}

// SSE commit re-encodes frames; a stale Content-Encoding must not survive.
func TestSSETransform_DropsContentEncoding(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "gzip")
		fl := w.(http.Flusher)
		w.Write([]byte("event: content_block_delta\ndata: {\"delta\":\"hi\"}\n\n"))
		fl.Flush()
	})
	reg := transform.NewRegistry(4)
	set, _ := reg.CreateSet("sse-enc")
	rules := []transform.Rule{
		{Kind: transform.KindSSEMatch, Match: "content_block_delta", From: "hi", To: "hello"},
	}
	if _, err := reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","stream":true}`))
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding=%q want cleared on SSE transform commit", got)
	}
	if !strings.Contains(rec.Body.String(), `"delta":"hello"`) {
		t.Fatalf("sse data not transformed: %s", rec.Body.String())
	}
}

// SSE commit re-encodes frames; stale Content-MD5 / ETag must not survive.
func TestSSETransform_DropsContentMD5AndETag(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-MD5", "d41d8cd98f00b204e9800998ecf8427e")
		w.Header().Set("ETag", `"upstream-sse"`)
		fl := w.(http.Flusher)
		w.Write([]byte("event: content_block_delta\ndata: {\"delta\":\"hi\"}\n\n"))
		fl.Flush()
	})
	reg := transform.NewRegistry(4)
	set, _ := reg.CreateSet("sse-md5-etag")
	rules := []transform.Rule{
		{Kind: transform.KindSSEMatch, Match: "content_block_delta", From: "hi", To: "hello"},
	}
	if _, err := reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","stream":true}`))
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-MD5"); got != "" {
		t.Fatalf("Content-MD5=%q want cleared on SSE transform commit", got)
	}
	if got := rec.Header().Get("ETag"); got != "" {
		t.Fatalf("ETag=%q want cleared on SSE transform commit", got)
	}
	if !strings.Contains(rec.Body.String(), `"delta":"hello"`) {
		t.Fatalf("sse data not transformed: %s", rec.Body.String())
	}
}

// §15: exact MaxBodyBuffer is still transformable; one byte over must follow the
// pre-Commit fail policy and must not return a truncated success body.
func TestResponseTransform_BodyAtMaxBufferSucceeds(t *testing.T) {
	const marker = `"note":"upstream"`
	const replaced = `"note":"gateways"` // same length so body stays at MaxBodyBuffer
	full := make([]byte, transform.MaxBodyBuffer)
	copy(full, []byte(`{"ok":true,`+marker+`}`))
	for i := len(`{"ok":true,` + marker + `}`); i < len(full); i++ {
		full[i] = 'x'
	}

	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(full)
	})
	reg := transform.NewRegistry(4)
	set, err := reg.CreateSet("cap")
	if err != nil {
		t.Fatal(err)
	}
	rules := []transform.Rule{
		{Kind: transform.KindReplaceBytes, From: marker, To: replaced},
	}
	if _, err := reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailClosed, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","max_tokens":1}`))
	if rec.Code != 200 {
		preview := rec.Body.String()
		if len(preview) > 200 {
			preview = preview[:200]
		}
		t.Fatalf("status=%d body=%s", rec.Code, preview)
	}
	if rec.Body.Len() != transform.MaxBodyBuffer {
		t.Fatalf("len=%d want %d", rec.Body.Len(), transform.MaxBodyBuffer)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(replaced)) {
		t.Fatal("exact-cap body must still be transformed")
	}
	if bytes.Contains(rec.Body.Bytes(), []byte(marker)) {
		t.Fatal("marker should have been replaced")
	}
}

func TestResponseTransform_BodyOverMaxBufferFailClosed(t *testing.T) {
	// Cap+1: large enough that a truncated success body would be visible, and
	// larger than limit+1 read so a buggy fail_open path would drop the tail.
	full := bytes.Repeat([]byte("a"), transform.MaxBodyBuffer+2)
	copy(full, []byte(`{"note":"upstream"}`))

	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream", "raw")
		w.WriteHeader(200)
		w.Write(full)
	})
	reg := transform.NewRegistry(4)
	set, _ := reg.CreateSet("over-closed")
	rules := []transform.Rule{
		{Kind: transform.KindSetHeader, Name: "X-Transformed", Value: "1"},
		{Kind: transform.KindReplaceBytes, From: `"note":"upstream"`, To: `"note":"gateway"`},
	}
	if _, err := reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailClosed, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","max_tokens":1}`))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("want 502 fail_closed, got %d len=%d", rec.Code, rec.Body.Len())
	}
	if rec.Header().Get("X-Transformed") != "" {
		t.Fatal("transform header must not reach client on over-limit fail_closed")
	}
	if rec.Header().Get("X-Upstream") != "" {
		t.Fatal("upstream header must not leak on fail_closed over-limit")
	}
	// Must not be a truncated success body of a's / partial JSON.
	if rec.Body.Len() > 512 && bytes.Count(rec.Body.Bytes(), []byte("a")) > 100 {
		t.Fatalf("client received truncated upstream body as response: len=%d", rec.Body.Len())
	}
	if bytes.Contains(rec.Body.Bytes(), []byte(`"note":"gateway"`)) {
		t.Fatal("must not commit a transformed truncated body")
	}
}

func TestResponseTransform_BodyOverMaxBufferFailOpenPassthrough(t *testing.T) {
	// Body larger than MaxBodyBuffer+1 so a truncated commit would drop the tail.
	full := bytes.Repeat([]byte("b"), transform.MaxBodyBuffer+4096)
	copy(full, []byte(`{"note":"upstream","pad":"`))
	copy(full[len(full)-2:], []byte(`"}`))

	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream", "keep")
		w.WriteHeader(200)
		w.Write(full)
	})
	reg := transform.NewRegistry(4)
	set, _ := reg.CreateSet("over-open")
	rules := []transform.Rule{
		{Kind: transform.KindSetHeader, Name: "X-Transformed", Value: "1"},
		{Kind: transform.KindReplaceBytes, From: `"note":"upstream"`, To: `"note":"gateway"`},
	}
	// req fail_closed, res fail_open (doc default for response).
	if _, err := reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","max_tokens":1}`))
	if rec.Code != 200 {
		t.Fatalf("fail_open over-limit want 200 original, got %d", rec.Code)
	}
	if rec.Header().Get("X-Transformed") != "" {
		t.Fatal("over-limit fail_open must not apply transform headers")
	}
	if rec.Header().Get("X-Upstream") != "keep" {
		t.Fatalf("original header lost: %q", rec.Header().Get("X-Upstream"))
	}
	if rec.Body.Len() != len(full) {
		t.Fatalf("truncated success body: got %d want %d", rec.Body.Len(), len(full))
	}
	if !bytes.Equal(rec.Body.Bytes(), full) {
		t.Fatal("fail_open over-limit must pass through the original full body")
	}
	if bytes.Contains(rec.Body.Bytes(), []byte(`"note":"gateway"`)) {
		t.Fatal("transform must not apply when body exceeds buffer")
	}
}
