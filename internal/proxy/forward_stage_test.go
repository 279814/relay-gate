package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
)

func TestForwarderNativeSemanticFloorKeepsIndependentByteLimit(t *testing.T) {
	settings := model.DefaultSettings()
	settings.RealResponseHeaderSec = 1
	settings.RealFirstByteSec = 1
	settings.RealFirstSemanticSec = 300
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		select {
		case <-time.After(1300 * time.Millisecond):
			w.Write([]byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"2\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"))
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	f := testForwarder(t, TimeoutsFrom(outbound.RealBudget(settings)))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := f.Forward(ctx, httptest.NewRecorder(), "POST", server.URL+"/v1/messages", http.Header{}, []byte(`{"model":"fixture","stream":true}`))
	if result.Err == nil {
		t.Fatalf("valid stage setting ignored by temporary projection: first_byte_limit=1s native_semantic=300s projected=%v actual_first_byte=%v semantic_seen=%t", f.Timeouts.FirstSemantic, result.FirstByteAt.Sub(result.SentAt), result.SemanticSeen)
	}
}

func TestForwarderAbsolutePhasesAcrossHeaderAndPeek(t *testing.T) {
	for _, test := range []struct {
		name                 string
		headDelay, bodyDelay time.Duration
		prefix               string
		peek                 bool
		timeouts             Timeouts
		reason               string
	}{
		{"header", 100 * time.Millisecond, 0, "", false, Timeouts{ResponseHead: 40 * time.Millisecond, FirstByte: 300 * time.Millisecond, FirstSemantic: 500 * time.Millisecond, Total: time.Second}, "response_header_timeout"},
		{"byte_from_sent", 60 * time.Millisecond, 70 * time.Millisecond, "", false, Timeouts{ResponseHead: 100 * time.Millisecond, FirstByte: 100 * time.Millisecond, FirstSemantic: 500 * time.Millisecond, Total: time.Second}, "first_byte_timeout"},
		{"semantic_after_raw_ping", 0, 200 * time.Millisecond, "event: ping\ndata: {}\n\n", false, Timeouts{ResponseHead: time.Second, FirstByte: 80 * time.Millisecond, FirstSemantic: 120 * time.Millisecond, Idle: 40 * time.Millisecond, Total: time.Second}, "semantic_timeout"},
		{"peek_owns_byte_deadline", 0, 120 * time.Millisecond, "", true, Timeouts{ResponseHead: time.Second, FirstByte: 40 * time.Millisecond, FirstSemantic: 500 * time.Millisecond, PeekWait: 300 * time.Millisecond, CommitOnPeekTimeout: true, Total: time.Second}, "first_byte_timeout"},
	} {
		t.Run(test.name, func(t *testing.T) {
			wait := func(ctx context.Context, d time.Duration) bool {
				timer := time.NewTimer(d)
				defer timer.Stop()
				select {
				case <-timer.C:
					return true
				case <-ctx.Done():
					return false
				}
			}
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !wait(r.Context(), test.headDelay) {
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(200)
				w.(http.Flusher).Flush()
				if test.prefix != "" {
					w.Write([]byte(test.prefix))
					w.(http.Flusher).Flush()
				}
				if !wait(r.Context(), test.bodyDelay) {
					return
				}
				w.Write([]byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"late\"}}\n\n"))
			}))
			defer up.Close()
			f := testForwarder(t, test.timeouts)
			var result *Result
			if test.peek {
				at := f.Send(context.Background(), "POST", up.URL, http.Header{}, nil)
				at.Peek()
				result = at.Result()
				at.Discard()
			} else {
				result = f.Forward(context.Background(), httptest.NewRecorder(), "POST", up.URL, http.Header{}, nil)
			}
			if !errors.Is(result.Err, ErrFirstTokenTimeout) || !strings.Contains(result.Err.Error(), test.reason) {
				t.Fatalf("phase %s did not enforce its original SentAt deadline: %v", test.name, result.Err)
			}
		})
	}
}
func TestForwarderDistinguishesSharedTotalCauseFromClientCancellation(t *testing.T) {
	for _, ownTotal := range []bool{false, true} {
		t.Run(fmt.Sprintf("own_total_%t", ownTotal), func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(200)
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			}))
			defer up.Close()
			var ctx context.Context
			var cancel context.CancelFunc
			if ownTotal {
				ctx, cancel = context.WithDeadlineCause(context.Background(), time.Now().Add(60*time.Millisecond), ErrTotalTimeout)
			} else {
				ctx, cancel = context.WithCancel(context.Background())
				time.AfterFunc(60*time.Millisecond, cancel)
			}
			defer cancel()
			f := testForwarder(t, Timeouts{FirstByte: time.Second, FirstSemantic: time.Second, PeekWait: time.Second, CommitOnPeekTimeout: true, Total: time.Second})
			at := f.Send(ctx, "POST", up.URL, http.Header{}, nil)
			at.Peek()
			at.Discard()
			want := ErrCanceled
			if ownTotal {
				want = ErrTotalTimeout
			}
			if !errors.Is(at.Result().Err, want) {
				t.Fatalf("cancellation ownership lost: %v want %v", at.Result().Err, want)
			}
		})
	}
}

func TestForwarderDiscardDrainRespectsByteDeadline(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		w.(http.Flusher).Flush()
		select {
		case <-time.After(250 * time.Millisecond):
			w.Write([]byte("error"))
		case <-r.Context().Done():
		}
	}))
	defer up.Close()
	f := testForwarder(t, Timeouts{FirstByte: 40 * time.Millisecond, FirstSemantic: 500 * time.Millisecond, Total: time.Second})
	at := f.Send(context.Background(), "POST", up.URL, http.Header{}, nil)
	start := time.Now()
	at.Discard()
	if time.Since(start) > 150*time.Millisecond {
		t.Fatalf("discarding a retry response escaped its first-byte phase: %v", time.Since(start))
	}
}

func TestForwarderAlreadyCanceledCallerWinsReadyStageAndEOF(t *testing.T) {
	for _, own := range []bool{false, true} {
		var ctx context.Context
		var cancel context.CancelFunc
		if own {
			ctx, cancel = context.WithDeadlineCause(context.Background(), time.Now().Add(-time.Second), ErrTotalTimeout)
		} else {
			ctx, cancel = context.WithCancel(context.Background())
			cancel()
		}
		defer cancel()
		at := &Attempt{ctx: ctx, clientCtx: ctx}
		at.stageTimeout.Store(responseByteTimeout)
		want := ErrCanceled
		if own {
			want = ErrTotalTimeout
		}
		if err := at.readFailure(io.EOF, 0); !errors.Is(err, want) {
			t.Fatalf("already canceled parent lost to ready stage/EOF: %v want %v", err, want)
		}
	}
}
