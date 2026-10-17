package probe

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/proxy"
	"github.com/andybalholm/brotli"
)

func forwardWithTrafficProgress(t *testing.T, h *trafficHTTPHarness, to proxy.Timeouts) (*proxy.Result, []byte) {
	t.Helper()
	instrument := h.manager.PrepareAttempt(context.Background(), health.AttemptTarget{UpstreamID: h.up.ID, RouteID: h.route.ID, Protocol: model.ProtoAnthropic, Endpoint: model.EndpointMessages}, health.AttemptRequestView{})
	f := &proxy.Forwarder{Transport: http.DefaultTransport, Timeouts: to, Protocol: model.ProtoAnthropic, RespObserver: instrument.Observer}
	at := f.Send(context.Background(), "POST", h.up.BaseURL, http.Header{"Accept-Encoding": {"identity"}}, nil)
	if at.Failed() {
		at.Discard()
		t.Fatal(at.Result().Err)
	}
	instrument.Observer.TryHeaders(at.Result().Status, at.Result().RespHeaders, time.Now())
	rec := httptest.NewRecorder()
	res := at.Commit(rec)
	instrument.Observer.Finish(health.AttemptFinish{ReadErr: res.Err, ClientCommitted: res.HeadersSent})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := h.manager.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	return res, rec.Body.Bytes()
}

func TestTrafficProgressHTTP_CompressedKeepaliveCannotExtendSemanticIdle(t *testing.T) {
	for _, encoding := range []string{"gzip", "br"} {
		t.Run(encoding, func(t *testing.T) {
			h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Content-Encoding", encoding)
				var encoder interface {
					io.Writer
					Flush() error
					Close() error
				}
				if encoding == "gzip" {
					encoder = gzip.NewWriter(w)
				} else {
					encoder = brotli.NewWriter(w)
				}
				defer encoder.Close()
				_, _ = io.WriteString(encoder, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"raw\"}}\n\n")
				_ = encoder.Flush()
				w.(http.Flusher).Flush()
				ticker := time.NewTicker(15 * time.Millisecond)
				defer ticker.Stop()
				end := time.NewTimer(300 * time.Millisecond)
				defer end.Stop()
				for {
					select {
					case <-ticker.C:
						_, _ = io.WriteString(encoder, ": heartbeat\n\n")
						_ = encoder.Flush()
						w.(http.Flusher).Flush()
					case <-r.Context().Done():
						return
					case <-end.C:
						return
					}
				}
			})
			res, _ := forwardWithTrafficProgress(t, h, proxy.Timeouts{FirstToken: 200 * time.Millisecond, Idle: 90 * time.Millisecond, Total: time.Second})
			if !errors.Is(res.Err, proxy.ErrStreamStalled) || !res.SemanticSeen || res.FirstSemanticAt.IsZero() {
				t.Fatalf("compressed raw progress did not control Idle: %+v", res)
			}
			exec := h.execution(t)
			if exec.Success || !exec.Partial {
				t.Fatalf("truncated compressed stream must stay partial: %+v", exec)
			}
		})
	}
}

func TestTrafficProgressHTTP_CapacityAndCodecFailuresPreserveWireAndOuterLimit(t *testing.T) {
	for _, mode := range []string{"no-full-lease", "bad-gzip", "unsupported-coding"} {
		t.Run(mode, func(t *testing.T) {
			var encoded bytes.Buffer
			zw := gzip.NewWriter(&encoded)
			_, _ = io.WriteString(zw, "data: {\"type\":\"message_stop\"}\n\n")
			_ = zw.Close()
			wire := encoded.Bytes()
			encoding := "gzip"
			if mode == "bad-gzip" {
				wire = []byte("not gzip; original private bytes")
			}
			if mode == "unsupported-coding" {
				encoding = "unknown"
				wire = []byte("opaque original response")
			}
			h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Content-Encoding", encoding)
				first := 1
				if mode == "bad-gzip" {
					first = 12
				} // enough bytes to reject the header now
				_, _ = w.Write(wire[:first])
				w.(http.Flusher).Flush()
				select {
				case <-time.After(140 * time.Millisecond):
					_, _ = w.Write(wire[first:])
				case <-r.Context().Done():
				}
			})
			if mode == "no-full-lease" {
				for i := 0; i < fullObserverLeases; i++ {
					<-h.manager.leases
				}
				defer func() {
					for i := 0; i < fullObserverLeases; i++ {
						h.manager.leases <- struct{}{}
					}
				}()
			}
			res, out := forwardWithTrafficProgress(t, h, proxy.Timeouts{FirstToken: 50 * time.Millisecond, Idle: 30 * time.Millisecond, Total: time.Second})
			if res.Err != nil || !bytes.Equal(out, wire) || res.ObserverIncomplete == "" {
				t.Fatalf("observer failure changed upstream bytes or became transport timeout: result=%+v body=%q", res, out)
			}
			exec := h.execution(t)
			if exec.Success || !exec.ObserverIncomplete || exec.ObserverIncompleteReason == "" {
				t.Fatalf("incomplete response was promoted to success: %+v", exec)
			}
		})
	}
}

func TestTrafficProgressHTTP_CapacityFallbackStillHonorsOuterTotal(t *testing.T) {
	h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write([]byte{0x1f})
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	for i := 0; i < fullObserverLeases; i++ {
		<-h.manager.leases
	}
	defer func() {
		for i := 0; i < fullObserverLeases; i++ {
			h.manager.leases <- struct{}{}
		}
	}()
	res, out := forwardWithTrafficProgress(t, h, proxy.Timeouts{FirstToken: 30 * time.Millisecond, Idle: 20 * time.Millisecond, Total: 120 * time.Millisecond})
	if !errors.Is(res.Err, proxy.ErrTotalTimeout) || !bytes.Equal(out, []byte{0x1f}) || res.ObserverIncomplete != model.ObserverCapacity {
		t.Fatalf("outer total was lost: %+v %x", res, out)
	}
}

func TestTrafficProgressHTTP_CapacityFallbackStillHonorsFirstByteLimit(t *testing.T) {
	h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "gzip")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	for i := 0; i < fullObserverLeases; i++ {
		<-h.manager.leases
	}
	defer func() {
		for i := 0; i < fullObserverLeases; i++ {
			h.manager.leases <- struct{}{}
		}
	}()
	res, out := forwardWithTrafficProgress(t, h, proxy.Timeouts{FirstToken: 40 * time.Millisecond, Idle: 20 * time.Millisecond, Total: time.Second})
	if !errors.Is(res.Err, proxy.ErrFirstTokenTimeout) || len(out) != 0 {
		t.Fatalf("observer capacity disabled first-byte bound: %+v %x", res, out)
	}
}
