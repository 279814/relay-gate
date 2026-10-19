package proxy

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/transform"
)

func TestSampleKeepsOriginalUpstreamStatusHeadersAndBodyAcrossTransform(t *testing.T) {
	const original = `{"note":"before"}`
	hs := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-View", "upstream")
		w.WriteHeader(202)
		io.WriteString(w, original)
	})
	logs := &recordingLogSink{}
	hs.h.WithLogSink(logs)
	reg := transform.NewRegistry(8)
	set, _ := reg.CreateSet("raw-response")
	if _, err := reg.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindReplaceBytes, From: "before", To: "after"}, {Kind: transform.KindSetHeader, Name: "X-View", Value: "client"}, {Kind: transform.KindSetStatus, Value: "201"}}, transform.FailClosed, transform.FailClosed, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)
	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))
	if rec.Code != 201 || rec.Header().Get("X-View") != "client" || !strings.Contains(rec.Body.String(), "after") {
		t.Fatalf("client transform changed: %d %s", rec.Code, rec.Body.String())
	}
	smp := hs.sink.one(t)
	if smp.RespStatus != 202 || smp.RespHeaders.Get("X-View") != "upstream" || string(smp.RespBody) != original || smp.Metadata.ResponseView != "upstream_response" {
		t.Fatalf("sample is not original upstream response: status=%d headers=%v body=%q metadata=%+v", smp.RespStatus, smp.RespHeaders, smp.RespBody, smp.Metadata)
	}
	if rows := logs.all(); len(rows) != 1 || rows[0].RespStatus != 201 || rows[0].BytesWritten != int64(rec.Body.Len()) || rows[0].Metadata.ResponseView != "client_response" {
		t.Fatalf("RequestLog lost client facts: %+v", rows)
	}
}

func TestSampleKeepsEncodedSSEBeforeRewriteAndSyntheticCompletion(t *testing.T) {
	const original = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"before\"}}\n\n"
	for _, encoding := range []string{"identity", "gzip", "br"} {
		t.Run(encoding, func(t *testing.T) {
			wire := []byte(original)
			if encoding == "gzip" {
				wire = gzipBody(t, wire)
			} else if encoding == "br" {
				wire = brotliBody(wire)
			}
			hs := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				if encoding != "identity" {
					w.Header().Set("Content-Encoding", encoding)
				}
				w.Write(wire)
			})
			reg := transform.NewRegistry(8)
			set, _ := reg.CreateSet("raw-sse")
			if _, err := reg.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindSSEMatch, Match: "content_block_delta", From: "before", To: "after"}, {Kind: transform.KindSSEAppendEnd, Match: "message_stop", Value: `{"type":"message_stop"}`}}, transform.FailClosed, transform.FailClosed, ""); err != nil {
				t.Fatal(err)
			}
			if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
				t.Fatal(err)
			}
			hs.h.WithTransforms(reg)
			rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","stream":true}`))
			if rec.Code != 200 || !strings.Contains(rec.Body.String(), "after") || !strings.Contains(rec.Body.String(), "message_stop") {
				t.Fatalf("client output=%d %s", rec.Code, rec.Body.String())
			}
			smp := hs.sink.one(t)
			wantEncoding := encoding
			if encoding == "identity" {
				wantEncoding = ""
			}
			if !bytes.Equal(smp.RespBody, wire) || smp.RespHeaders.Get("Content-Encoding") != wantEncoding || !smp.Metadata.SyntheticCompletion || smp.Metadata.ResponseView != "upstream_response" {
				t.Fatalf("sample contains decoded/transformed/synthetic output: bodylen=%d original=%d encoding=%s meta=%+v", len(smp.RespBody), len(wire), smp.RespHeaders.Get("Content-Encoding"), smp.Metadata)
			}
		})
	}
}

func TestSampleFailClosedKeepsUpstreamBodyAndIncompleteDiscardIsMarked(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"upstream":"original"}`)
	})
	reg := transform.NewRegistry(8)
	set, _ := reg.CreateSet("raw-fail-closed")
	if _, err := reg.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindSetJSONPointer, Name: "/missing/child", Value: `"new"`}}, transform.FailClosed, transform.FailClosed, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)
	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","missing":{"child":"request"}}`))
	if rec.Code != 502 {
		t.Fatalf("status=%d", rec.Code)
	}
	smp := hs.sink.one(t)
	if string(smp.RespBody) != `{"upstream":"original"}` || smp.Metadata.ResponseView != "upstream_response" {
		t.Fatalf("fail_closed lost raw upstream body: %q %+v", smp.RespBody, smp.Metadata)
	}

	multi := newMultiHarness(t, respondStatus(503, strings.Repeat("upstream-", 2048)), respondOK(`{"content":[{"type":"text","text":"done"}]}`))
	multi.cfg.settings.RealTotalSec = 30
	if rec := multi.serve(multi.req()); rec.Code != 200 {
		t.Fatalf("retry status=%d", rec.Code)
	}
	first := multi.sink.one(t).Attempts[0]
	if !first.Truncated.Has(model.TruncRespBody) || first.Metadata.ResponseView != "upstream_attempt_prefix" || len(first.RespBody) > discardDrainLimit {
		t.Fatalf("discard claimed a complete sample: bytes=%d flags=%d view=%s", len(first.RespBody), first.Truncated, first.Metadata.ResponseView)
	}
}
