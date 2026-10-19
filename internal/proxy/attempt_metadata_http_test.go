package proxy

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

func TestAttemptMetadataHTTPStageFailuresKeepOnlyObservedTimes(t *testing.T) {
	for _, stage := range []string{"response_header", "first_byte", "first_semantic", "partial"} {
		t.Run(stage, func(t *testing.T) {
			hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
				if stage == "response_header" {
					<-r.Context().Done()
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				if stage == "partial" {
					w.Header().Set("Content-Length", "999")
				}
				w.WriteHeader(200)
				w.(http.Flusher).Flush()
				if stage == "first_byte" {
					<-r.Context().Done()
					return
				}
				if stage == "partial" {
					w.Write([]byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"partial\"}}\n\n"))
					return
				}
				w.Write([]byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"x\",\"type\":\"message\"}}\n\n"))
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			})
			hs.cfg.settings.SampleEnabled = false
			hs.cfg.settings.RealTotalSec = 3
			hs.cfg.settings.RealResponseHeaderSec = 1
			hs.cfg.settings.RealFirstByteSec = 1
			hs.cfg.settings.RealFirstSemanticSec = 1
			logs := &recordingLogSink{}
			hs.h.WithLogSink(logs)
			hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","stream":true}`))
			rows := logs.all()
			if len(rows) != 1 {
				t.Fatalf("stage %s lost actual Attempt: %d", stage, len(rows))
			}
			row, m := rows[0], rows[0].Metadata
			if m.RequestWriteState != "written" || m.RequestDiffReason != "sample_disabled" || m.RequestInputHash != "" || len(hs.sink.all()) != 0 {
				t.Fatalf("write/capture facts wrong: %+v", m)
			}
			if (m.ResponseHeaderAtMS > 0) != (stage != "response_header") {
				t.Fatalf("invented/missing header time: %+v", m)
			}
			if (row.TSFirstByte > 0) != (stage == "first_semantic" || stage == "partial") {
				t.Fatalf("invented/missing first-byte time: %+v", row)
			}
			if (m.FirstSemanticAtMS > 0) != (stage == "partial") {
				t.Fatalf("invented/missing semantic time: %+v", m)
			}
			if stage == "partial" && (row.BytesWritten == 0 || row.Outcome != model.OutcomeUpstreamError) {
				t.Fatalf("partial response facts wrong: %+v", row)
			}
		})
	}
}

func TestAttemptMetadataHTTPClientCancellationDoesNotInventResponseTimes(t *testing.T) {
	entered := make(chan struct{})
	hs := newHarness(t, func(_ http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() })
	logs := &recordingLogSink{}
	hs.h.WithLogSink(logs)
	ctx, cancel := context.WithCancel(context.Background())
	req := hs.anthropicRequest(`{"model":"claude-opus-5"}`).WithContext(ctx)
	done := make(chan struct{})
	go func() { defer close(done); hs.serve(req) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream not entered")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not finish")
	}
	rows := logs.all()
	if len(rows) != 1 {
		t.Fatalf("cancelled send lost Attempt: %d", len(rows))
	}
	m := rows[0].Metadata
	if rows[0].Outcome != model.OutcomeClientAbort || m.ResponseHeaderAtMS != 0 || m.FirstEventAtMS != 0 || m.FirstSemanticAtMS != 0 || m.RequestWriteState != "written" {
		t.Fatalf("cancelled facts=%+v metadata=%+v", rows[0], m)
	}
}
