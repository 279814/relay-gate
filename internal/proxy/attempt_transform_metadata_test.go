package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/transform"
)

type partialMetadataWriter struct{ *httptest.ResponseRecorder }

func (w partialMetadataWriter) Write(p []byte) (int, error) {
	n := min(3, len(p))
	w.ResponseRecorder.Write(p[:n])
	return n, io.ErrClosedPipe
}

func TestTransformedPartialClientWriteKeepsAttemptBytesAndClientAbort(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"value":"before"}`))
	})
	logs := &recordingLogSink{}
	hs.h.WithLogSink(logs)
	reg := transform.NewRegistry(8)
	set, _ := reg.CreateSet("partial-write")
	if _, err := reg.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindReplaceBytes, From: "before", To: "after"}}, transform.FailClosed, transform.FailClosed, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)
	mux := http.NewServeMux()
	hs.h.Routes(mux)
	mux.ServeHTTP(partialMetadataWriter{httptest.NewRecorder()}, hs.anthropicRequest(`{"model":"claude-opus-5"}`))
	rows := logs.all()
	if len(rows) != 1 {
		t.Fatalf("logs=%d", len(rows))
	}
	if rows[0].BytesWritten != 3 || rows[0].Outcome != "client_abort" || rows[0].Metadata.ResponseDiffReason != "incomplete" || rows[0].Metadata.ResponseOutputHash != "" {
		t.Fatalf("partial write facts=%+v", rows[0])
	}
}

func TestAttemptMetadataCapturesSafeResponseDiffAndOmitsCredentialTaint(t *testing.T) {
	for _, tainted := range []bool{false, true} {
		t.Run(map[bool]string{false: "safe", true: "secret taint"}[tainted], func(t *testing.T) {
			body := `{"note":"before"}`
			if tainted {
				body = `{"note":"before","token":"sk-upstream-secret"}`
			}
			hs := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(body))
			})
			reg := transform.NewRegistry(8)
			set, _ := reg.CreateSet("response-metadata")
			if _, err := reg.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindReplaceBytes, From: "before", To: "after"}}, transform.FailClosed, transform.FailClosed, ""); err != nil {
				t.Fatal(err)
			}
			if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
				t.Fatal(err)
			}
			hs.h.WithTransforms(reg)
			if rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`)); rec.Code != 200 {
				t.Fatalf("status=%d", rec.Code)
			}
			m := hs.sink.one(t).Metadata
			if tainted {
				if m.ResponseDiffReason != "secret_taint" || m.ResponseInputHash != "" || m.ResponseOutputHash != "" || m.ResponseBodyChanged {
					t.Fatalf("tainted diff=%+v", m)
				}
			} else {
				if m.ResponseDiffReason != "recorded" || len(m.ResponseInputHash) != 64 || len(m.ResponseOutputHash) != 64 || m.ResponseInputHash == m.ResponseOutputHash || !m.ResponseBodyChanged {
					t.Fatalf("safe transform facts missing: %+v", m)
				}
			}
		})
	}
}

func TestResponseFailClosedStillRecordsTheActualAttempt(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"value":"unchanged"}`))
	})
	logs := &recordingLogSink{}
	hs.h.WithLogSink(logs)
	reg := transform.NewRegistry(8)
	set, _ := reg.CreateSet("response-failure")
	if _, err := reg.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindSetJSONPointer, Name: "/missing/child", Value: `"new"`}}, transform.FailClosed, transform.FailClosed, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)
	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","missing":{"child":"in"}}`))
	if rec.Code != 502 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(logs.all()) != 1 {
		t.Fatalf("actual send disappeared after response transform failure: %d logs", len(logs.all()))
	}
	if smp := hs.sink.one(t); len(smp.Attempts) != 1 || smp.Metadata.TransformVersionID == 0 {
		t.Fatalf("sample lost actual attempt: %+v", smp)
	}
}

func TestSyntheticEventMetadataMarksOnlyActualSyntheticTransformOutput(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"before\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"))
	})
	reg := transform.NewRegistry(8)
	set, _ := reg.CreateSet("synthetic-event")
	if _, err := reg.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindSSEMatch, Match: "content_block_delta", From: "before", To: "after", Synthetic: true}}, transform.FailClosed, transform.FailClosed, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)
	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","stream":true}`))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "after") {
		t.Fatalf("not transformed: %d %s", rec.Code, rec.Body.String())
	}
	if !hs.sink.one(t).Metadata.SyntheticCompletion {
		t.Fatal("actual synthetic event not recorded")
	}
}
