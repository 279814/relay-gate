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
	"github.com/279814/relay-gate/internal/transform"
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

type progressEncoder interface {
	io.WriteCloser
	Flush() error
}

type plainProgressEncoder struct{ io.Writer }

func (plainProgressEncoder) Flush() error { return nil }
func (plainProgressEncoder) Close() error { return nil }

func newProgressEncoder(w io.Writer, encoding string) progressEncoder {
	switch encoding {
	case "gzip":
		return gzip.NewWriter(w)
	case "br":
		return brotli.NewWriter(w)
	default:
		return plainProgressEncoder{w}
	}
}

func TestTrafficProgressHTTP_RawKeepaliveAfterSemanticResetsIdle(t *testing.T) {
	for _, encoding := range []string{"identity", "gzip", "br"} {
		t.Run(encoding, func(t *testing.T) {
			h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Content-Encoding", encoding)
				encoder := newProgressEncoder(w, encoding)
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
						_, _ = io.WriteString(encoder, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
						return
					}
				}
			})
			res, _ := forwardWithTrafficProgress(t, h, proxy.Timeouts{FirstToken: 200 * time.Millisecond, Idle: 90 * time.Millisecond, Total: time.Second})
			if res.Err != nil || !res.SemanticSeen || res.FirstSemanticAt.IsZero() {
				t.Fatalf("raw keepalives after genuine semantic must keep the stream active: %+v", res)
			}
			exec := h.execution(t)
			if !exec.Success || exec.Partial || !exec.NormalEndSeen {
				t.Fatalf("complete stream with keepalives must retain complete semantic evidence: %+v", exec)
			}
		})
	}
}

func TestTrafficProgressHTTP_RealSilenceAfterSemanticStillExpiresIdle(t *testing.T) {
	for _, encoding := range []string{"identity", "gzip", "br"} {
		t.Run(encoding, func(t *testing.T) {
			h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Content-Encoding", encoding)
				encoder := newProgressEncoder(w, encoding)
				defer encoder.Close()
				_, _ = io.WriteString(encoder, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"raw\"}}\n\n")
				_ = encoder.Flush()
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			})
			res, _ := forwardWithTrafficProgress(t, h, proxy.Timeouts{FirstToken: 300 * time.Millisecond, Idle: 90 * time.Millisecond, Total: time.Second})
			if !errors.Is(res.Err, proxy.ErrStreamStalled) || !res.SemanticSeen {
				t.Fatalf("genuinely silent upstream must expire Idle: %+v", res)
			}
			exec := h.execution(t)
			if exec.Success || !exec.Partial {
				t.Fatalf("silent partial stream was promoted: %+v", exec)
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

func TestTrafficProgressHTTP_BadGzipSSETransformStopsCommittedStream(t *testing.T) {
	for _, policy := range []string{transform.FailOpen, transform.FailClosed} {
		t.Run(policy, func(t *testing.T) {
			h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Content-Encoding", "gzip")
				_, _ = io.WriteString(w, "invalid gzip upstream bytes")
			})
			endpoint, err := h.store.Endpoint(context.Background(), h.up.ID, model.EndpointMessages)
			if err != nil {
				t.Fatal(err)
			}
			reg := transform.NewRegistry(8)
			set, err := reg.CreateSet("bad-gzip-sse")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = reg.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindSSEMatch, Match: "content_block_delta", From: "raw", To: "rewritten"}}, transform.FailClosed, policy, ""); err != nil {
				t.Fatal(err)
			}
			if _, _, err = reg.PublishSnapshot(set.ID, h.route.ID, endpoint.ID); err != nil {
				t.Fatal(err)
			}
			h.handler.WithTransforms(reg)
			if body := h.request(t); len(body) != 0 {
				t.Fatalf("postcommit decoder failure inserted local JSON or bad original bytes: %q", body)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err = h.manager.Flush(ctx); err != nil {
				t.Fatal(err)
			}
			exec := h.execution(t)
			if exec.Success || !exec.ObserverIncomplete {
				t.Fatalf("malformed compressed input was promoted to success: %+v", exec)
			}
			if row := h.caps.Snapshot(model.RecipeScopeRoute, h.route.ID, model.EndpointMessages); row != nil && row.LastRealOKAt != 0 {
				t.Fatal("bad compressed input created piggyback evidence")
			}
			failed := false
			for _, execution := range reg.ListExecutions(0) {
				if execution.Phase == "sse" && !execution.OK && execution.FailPolicyUsed == policy {
					failed = true
				}
			}
			if !failed {
				t.Fatal("postcommit stream setup failure was not recorded under the selected policy")
			}
		})
	}
}
