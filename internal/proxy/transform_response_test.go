package proxy

import (
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

func TestResponseTransform_UnboundPassthrough(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream", "keep")
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
