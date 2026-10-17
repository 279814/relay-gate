package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/transform"
)

func TestCommitExpiredHandoffDoesNotSendHeaders(t *testing.T) {
	for _, transformed := range []bool{false, true} {
		for _, canceled := range []bool{false, true} {
			t.Run(fmt.Sprintf("transform=%t/cancel=%t", transformed, canceled), func(t *testing.T) {
				up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "text/event-stream")
					w.(http.Flusher).Flush()
					<-r.Context().Done()
				}))
				defer up.Close()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				f := testForwarder(t, Timeouts{ResponseHead: time.Second, FirstByte: time.Second, FirstSemantic: time.Second, PeekWait: 10 * time.Millisecond, CommitOnPeekTimeout: true, Total: 60 * time.Millisecond})
				at := f.Send(ctx, "POST", up.URL, http.Header{}, nil)
				at.Peek()
				want := ErrTotalTimeout
				if canceled {
					cancel()
					want = ErrCanceled
				} else {
					<-at.ctx.Done()
				}
				rec := httptest.NewRecorder()
				var result *Result
				if transformed {
					compiled, err := transform.Compile(transform.Version{Rules: []transform.Rule{{Kind: transform.KindSetHeader, Name: "X-Transformed", Value: "1"}}})
					if err != nil {
						t.Fatal(err)
					}
					result = at.CommitTransformed(rec, compiled, nil)
				} else {
					result = at.Commit(rec)
				}
				if result.HeadersSent || !errors.Is(result.Err, want) || rec.Body.Len() != 0 || rec.Header().Get("X-Transformed") != "" {
					t.Fatalf("expired handoff was committed: result=%+v body=%q", result, rec.Body.String())
				}
			})
		}
	}
}

func TestBufferedTransportFailureNeverUsesTransformFailOpen(t *testing.T) {
	for _, policy := range []string{transform.FailOpen, transform.FailClosed} {
		for _, failure := range []string{"first-byte", "total", "caller-cancel", "transport"} {
			t.Run(policy+"/"+failure, func(t *testing.T) {
				up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if failure == "transport" {
						conn, buffer, err := w.(http.Hijacker).Hijack()
						if err != nil {
							return
						}
						defer conn.Close()
						fmt.Fprint(buffer, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 99\r\n\r\n{")
						buffer.Flush()
						return
					}
					w.Header().Set("Content-Type", "application/json")
					w.(http.Flusher).Flush()
					<-r.Context().Done()
				}))
				defer up.Close()
				to := Timeouts{ResponseHead: time.Second, FirstByte: time.Second, FirstSemantic: time.Second, Total: time.Second}
				want := ErrStreamBroke
				switch failure {
				case "first-byte":
					to.FirstByte = 30 * time.Millisecond
					want = ErrFirstTokenTimeout
				case "total":
					to.Total = 30 * time.Millisecond
					want = ErrTotalTimeout
				case "caller-cancel":
					want = ErrCanceled
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				f := testForwarder(t, to)
				at := f.Send(ctx, "POST", up.URL, http.Header{}, nil)
				if at.Failed() {
					at.Discard()
					t.Fatal(at.Result().Err)
				}
				if failure == "caller-cancel" {
					timer := time.AfterFunc(20*time.Millisecond, cancel)
					defer timer.Stop()
				}
				compiled, err := transform.Compile(transform.Version{ResFailPolicy: policy, Rules: []transform.Rule{{Kind: transform.KindReplaceBytes, From: "old", To: "new"}}})
				if err != nil {
					t.Fatal(err)
				}
				rec := httptest.NewRecorder()
				result := at.CommitTransformed(rec, compiled, nil)
				if result.HeadersSent || !errors.Is(result.Err, want) || rec.Body.Len() != 0 {
					t.Fatalf("upstream read failure became transformed success: result=%+v body=%q", result, rec.Body.String())
				}
			})
		}
	}
}

func TestCommitStageExpiresWhilePeekWatcherIsStopped(t *testing.T) {
	for _, transformed := range []bool{false, true} {
		t.Run(fmt.Sprintf("transform=%t", transformed), func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			}))
			defer up.Close()
			f := testForwarder(t, Timeouts{ResponseHead: time.Second, FirstByte: 40 * time.Millisecond, FirstSemantic: time.Second, PeekWait: 10 * time.Millisecond, CommitOnPeekTimeout: true, Total: time.Second})
			at := f.Send(context.Background(), "POST", up.URL, http.Header{}, nil)
			at.Peek()
			timer := time.NewTimer(90 * time.Millisecond)
			defer timer.Stop()
			<-timer.C
			if at.ctx.Err() != nil || at.stageTimeout.Load() != 0 {
				t.Fatal("fixture needs an active total and stopped Peek stage watcher")
			}
			rec := httptest.NewRecorder()
			var result *Result
			if transformed {
				compiled, err := transform.Compile(transform.Version{Rules: []transform.Rule{{Kind: transform.KindSetHeader, Name: "X-Transformed", Value: "1"}}})
				if err != nil {
					t.Fatal(err)
				}
				result = at.CommitTransformed(rec, compiled, nil)
			} else {
				result = at.Commit(rec)
			}
			if result.HeadersSent || !errors.Is(result.Err, ErrFirstTokenTimeout) || !strings.Contains(result.Err.Error(), "first_byte_timeout") {
				t.Fatalf("stage renewed between Peek and Commit: %+v", result)
			}
		})
	}
}

func TestBufferedTransformWorkCannotCommitAfterTotal(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"content":[{"type":"text","text":"old"}]}`)
	}))
	defer up.Close()
	f := testForwarder(t, Timeouts{ResponseHead: time.Second, FirstByte: time.Second, FirstSemantic: time.Second, Total: 60 * time.Millisecond})
	at := f.Send(context.Background(), "POST", up.URL, http.Header{}, nil)
	compiled, err := transform.Compile(transform.Version{ResFailPolicy: transform.FailOpen, Rules: []transform.Rule{{Kind: transform.KindReplaceBytes, From: "old", To: "new"}}})
	if err != nil {
		t.Fatal(err)
	}
	var recorded bool
	rec := httptest.NewRecorder()
	result := at.CommitTransformed(rec, compiled, func(transform.ExecutionRecord) { recorded = true; <-at.ctx.Done() })
	if !recorded || result.HeadersSent || !errors.Is(result.Err, ErrTotalTimeout) || rec.Body.Len() != 0 {
		t.Fatalf("local work renewed the original total before WriteHeader: %+v", result)
	}
}

func TestHandlerUncommittedBudgetFailureReturns504WithAndWithoutTransform(t *testing.T) {
	for _, transformed := range []bool{false, true} {
		t.Run(fmt.Sprintf("transform=%t", transformed), func(t *testing.T) {
			var sends atomic.Int32
			hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
				sends.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.(http.Flusher).Flush()
				if transformed {
					io.WriteString(w, "{")
					w.(http.Flusher).Flush()
				}
				<-r.Context().Done()
			})
			hs.cfg.settings = model.DefaultSettings()
			hs.cfg.settings.RealConnectSec = 1
			hs.cfg.settings.RealResponseHeaderSec = 1
			hs.cfg.settings.RealFirstByteSec = 1
			hs.cfg.settings.RealFirstSemanticSec = 300
			hs.cfg.settings.RealTotalSec = 301
			if err := hs.cfg.settings.Validate(); err != nil {
				t.Fatal(err)
			}
			if transformed {
				registry := transform.NewRegistry(8)
				set, err := registry.CreateSet("buffered-timeout")
				if err != nil {
					t.Fatal(err)
				}
				if _, err = registry.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindReplaceBytes, From: "old", To: "new"}}, transform.FailClosed, transform.FailOpen, ""); err != nil {
					t.Fatal(err)
				}
				if _, _, err = registry.PublishSnapshot(set.ID, 100, 1); err != nil {
					t.Fatal(err)
				}
				hs.h.WithTransforms(registry)
			}
			mux := http.NewServeMux()
			hs.h.Routes(mux)
			// Keep validated production Settings while shortening the same
			// gateway-owned parent total context used by the retry pipeline.
			gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx, cancel := context.WithTimeoutCause(r.Context(), time.Second, ErrTotalTimeout)
				defer cancel()
				mux.ServeHTTP(w, r.WithContext(ctx))
			}))
			defer gate.Close()
			request := hs.anthropicRequest(`{"model":"claude-opus-5","max_tokens":1}`)
			request.URL.Scheme = "http"
			request.URL.Host = strings.TrimPrefix(gate.URL, "http://")
			request.RequestURI = ""
			response, err := (&http.Client{Timeout: 3 * time.Second}).Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusGatewayTimeout || strings.Contains(string(body), "fail_closed") || sends.Load() != 1 {
				t.Fatalf("uncommitted timeout misclassified: status=%d sends=%d body=%s", response.StatusCode, sends.Load(), body)
			}
			_, open, _ := hs.health.stats()
			if open != 0 {
				t.Fatalf("synthetic forwarding lease leaked: %d", open)
			}
		})
	}
}
