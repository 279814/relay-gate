package probe

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
)

func TestExecutorStageDeadlinesRealHTTP(t *testing.T) {
	for _, c := range []struct {
		name                   string
		headerDelay, bodyDelay time.Duration
		prefix                 string
		budget                 outbound.Budget
	}{
		{"response_header", 250 * time.Millisecond, 0, "", outbound.Budget{Connect: time.Second, ResponseHead: 40 * time.Millisecond, FirstSemantic: 600 * time.Millisecond, Total: time.Second}},
		{"byte_deadline_also_applies_before_headers", 250 * time.Millisecond, 0, "", outbound.Budget{Connect: time.Second, ResponseHead: 500 * time.Millisecond, FirstByte: 40 * time.Millisecond, FirstSemantic: 600 * time.Millisecond, Total: time.Second}},
		{"first_byte_ignored", 0, 250 * time.Millisecond, "", outbound.Budget{Connect: time.Second, ResponseHead: 500 * time.Millisecond, FirstByte: 40 * time.Millisecond, FirstEvent: 500 * time.Millisecond, FirstSemantic: 600 * time.Millisecond, Total: time.Second}},
		{"first_event_ignored", 0, 250 * time.Millisecond, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"", outbound.Budget{Connect: time.Second, ResponseHead: 500 * time.Millisecond, FirstByte: 400 * time.Millisecond, FirstEvent: 40 * time.Millisecond, FirstSemantic: 600 * time.Millisecond, Total: time.Second}},
		{"semantic_restarts_after_header", 120 * time.Millisecond, 100 * time.Millisecond, "", outbound.Budget{Connect: time.Second, ResponseHead: 150 * time.Millisecond, FirstSemantic: 180 * time.Millisecond, Total: time.Second}},
		{"total_restarts_after_header", 120 * time.Millisecond, 100 * time.Millisecond, "", outbound.Budget{Connect: time.Second, ResponseHead: 150 * time.Millisecond, Total: 180 * time.Millisecond}},
	} {
		t.Run(c.name, func(t *testing.T) {
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
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				drainBody(r)
				if !wait(r.Context(), c.headerDelay) {
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(200)
				w.(http.Flusher).Flush()
				if c.prefix != "" {
					w.Write([]byte(c.prefix))
					w.(http.Flusher).Flush()
				}
				if !wait(r.Context(), c.bodyDelay) {
					return
				}
				if c.prefix != "" {
					w.Write([]byte("2\"}}\n\n"))
				} else {
					w.Write([]byte(anthropicSemanticBody()))
				}
				w.(http.Flusher).Flush()
			}))
			defer server.Close()
			up := upstreamFor(server.URL)
			executor := stageHTTPExecutor(t, up)
			request := l2RequestFor(up)
			request.Budget = c.budget
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			start := time.Now()
			result, err := executor.Execute(ctx, request)
			elapsed := time.Since(start)
			if err != nil {
				t.Fatalf("infrastructure failure: %v", err)
			}
			if result.Decision.Success {
				t.Fatalf("expired phase accepted success: elapsed=%v header=%dms first_byte=%dms first_event=%dms first_semantic=%dms detail=%q", elapsed, result.Execution.ResponseHeaderAtMS-result.Execution.SentAtMS, result.Execution.FirstByteAtMS-result.Execution.SentAtMS, result.Execution.FirstEventAtMS-result.Execution.SentAtMS, result.Execution.FirstSemanticAtMS-result.Execution.SentAtMS, result.Execution.RedactedDetail)
			}
			want := map[string]string{"response_header": "response_header_timeout", "byte_deadline_also_applies_before_headers": "first_byte_timeout", "first_byte_ignored": "first_byte_timeout", "first_event_ignored": "first_event_timeout", "semantic_restarts_after_header": "semantic_timeout", "total_restarts_after_header": "total_timeout"}[c.name]
			if result.Execution.RedactedDetail != want {
				t.Fatalf("timeout phase=%q want %q", result.Execution.RedactedDetail, want)
			}
		})
	}
}

func stageHTTPExecutor(t *testing.T, up *model.Upstream) *Executor {
	t.Helper()
	manager := outbound.NewManager()
	t.Cleanup(manager.CloseIdleConnections)
	targets := outbound.NewProvider(testEndpoints{upstream: up}, nil, outbound.NewResolver(testHasher{}))
	return NewExecutor(targets, nil, builtinOnlyResolver(), ManagerTransports{Manager: manager}, &captureRecorder{}, AlwaysOpenAdmission(), WallClock(), nil)
}
func TestExecutorGzipInitializationIsInsideAbsoluteBudget(t *testing.T) {
	var encoded bytes.Buffer
	writer := gzip.NewWriter(&encoded)
	writer.Write([]byte(anthropicSemanticBody()))
	writer.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		drainBody(r)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		select {
		case <-time.After(250 * time.Millisecond):
			w.Write(encoded.Bytes())
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	up := upstreamFor(server.URL)
	executor := stageHTTPExecutor(t, up)
	request := l2RequestFor(up)
	request.Budget = outbound.Budget{Connect: time.Second, FirstSemantic: 40 * time.Millisecond, Total: 100 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	result, err := executor.Execute(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision.Success || time.Since(start) > 200*time.Millisecond {
		t.Fatalf("gzip header read escaped stage budget: elapsed=%v success=%t", time.Since(start), result.Decision.Success)
	}
}
func TestExecutorObserveRealIdleUsesOriginalActivityAfterSemantic(t *testing.T) {
	for _, pause := range []bool{false, true} {
		t.Run(fmt.Sprintf("pause_%t", pause), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				drainBody(r)
				w.Header().Set("Content-Type", "text/event-stream")
				w.Write([]byte(anthropicSemanticBody()))
				w.(http.Flusher).Flush()
				for i := 0; i < 5; i++ {
					select {
					case <-time.After(20 * time.Millisecond):
					case <-r.Context().Done():
						return
					}
					w.Write([]byte(": heartbeat\n\n"))
					w.(http.Flusher).Flush()
				}
				if pause {
					select {
					case <-time.After(120 * time.Millisecond):
					case <-r.Context().Done():
						return
					}
				}
				w.Write([]byte("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"))
				w.(http.Flusher).Flush()
			}))
			defer server.Close()
			up := upstreamFor(server.URL)
			executor := stageHTTPExecutor(t, up)
			request := l2RequestFor(up)
			request.Mode = ObserveReal
			request.Budget = outbound.Budget{Connect: time.Second, FirstSemantic: 500 * time.Millisecond, Idle: 50 * time.Millisecond, Total: time.Second}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			start := time.Now()
			result, err := executor.Execute(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			if pause {
				if result.Decision.Success || !result.Decision.Partial || time.Since(start) > 200*time.Millisecond {
					t.Fatalf("post-semantic raw silence ignored Idle: elapsed=%v success=%t partial=%t", time.Since(start), result.Decision.Success, result.Decision.Partial)
				}
				if result.Execution.RedactedDetail != "partial_after_semantic:idle_timeout" {
					t.Fatalf("partial idle reason=%q", result.Execution.RedactedDetail)
				}
			} else if !result.Decision.Success {
				t.Fatalf("raw heartbeats after semantic did not reset Idle: %+v", result.Decision)
			}
		})
	}
}

func TestExecutorGzipFirstByteIsTheOriginalHeaderNotDecodedSemantic(t *testing.T) {
	var encoded bytes.Buffer
	writer := gzip.NewWriter(&encoded)
	writer.Write([]byte(anthropicSemanticBody()))
	writer.Close()
	wire := encoded.Bytes()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		drainBody(r)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(wire[:10])
		w.(http.Flusher).Flush()
		select {
		case <-time.After(80 * time.Millisecond):
			w.Write(wire[10:])
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	up := upstreamFor(server.URL)
	executor := stageHTTPExecutor(t, up)
	request := l2RequestFor(up)
	request.Budget = outbound.Budget{Connect: time.Second, FirstByte: 40 * time.Millisecond, FirstEvent: 150 * time.Millisecond, FirstSemantic: 200 * time.Millisecond, Total: time.Second}
	result, err := executor.Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Decision.Success || result.Execution.FirstByteAtMS-result.Execution.SentAtMS >= 40 || result.Execution.FirstEventAtMS-result.Execution.FirstByteAtMS < 60 {
		t.Fatalf("compressed raw-byte phase was confused with decoded event: success=%t first=%d event=%d", result.Decision.Success, result.Execution.FirstByteAtMS-result.Execution.SentAtMS, result.Execution.FirstEventAtMS-result.Execution.SentAtMS)
	}
}
func TestExecutorPreSemanticHeartbeatDoesNotStartIdleOrExtendSemantic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		drainBody(r)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		for i := 0; i < 8; i++ {
			select {
			case <-time.After(20 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
			w.Write([]byte("event: ping\ndata: {}\n\n"))
			w.(http.Flusher).Flush()
		}
		w.Write([]byte(anthropicSemanticBody()))
	}))
	defer server.Close()
	up := upstreamFor(server.URL)
	request := l2RequestFor(up)
	request.Budget = outbound.Budget{Connect: time.Second, FirstByte: 60 * time.Millisecond, FirstEvent: 60 * time.Millisecond, FirstSemantic: 100 * time.Millisecond, Idle: 30 * time.Millisecond, Total: time.Second}
	start := time.Now()
	result, err := stageHTTPExecutor(t, up).Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision.Success || result.Decision.SemanticSeen || result.Execution.RedactedDetail != "semantic_timeout" || time.Since(start) < 80*time.Millisecond {
		t.Fatalf("pre-semantic heartbeat changed phase semantics: elapsed=%v decision=%+v", time.Since(start), result.Decision)
	}
}
func TestExecutorNativeLongThinkKeepsSemanticFloorWithStageTimer(t *testing.T) {
	clock := NewManualClock(time.Now())
	body := newGatedBody()
	binding := messagesBinding()
	binding.Version.TimeoutProfile = model.TimeoutL2LongThink
	up := upstreamFor("https://fixture.example")
	rt := &countingRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: body}, nil
	}}
	targets := outbound.NewProvider(testEndpoints{upstream: up}, nil, outbound.NewResolver(testHasher{}))
	executor := NewExecutor(targets, nil, testResolver(&fakeRecipeSource{routeBinding: binding}), fakeTransports{rt: rt}, &captureRecorder{}, AlwaysOpenAdmission(), clock, nil)
	request := l2RequestFor(up)
	request.Budget = outbound.Budget{ResponseHead: 100 * time.Second, FirstSemantic: time.Second, Total: 310 * time.Second}
	done := make(chan executeResult, 1)
	go func() {
		result, err := executor.Execute(context.Background(), request)
		done <- executeResult{result, err}
	}()
	select {
	case <-body.entered:
	case <-time.After(time.Second):
		t.Fatal("long-thinking fixture never reached reader")
	}
	clock.Advance(200 * time.Second)
	select {
	case <-done:
		t.Fatal("native long-thinking semantic limit was shortened below 300s")
	default:
	}
	clock.Advance(101 * time.Second)
	select {
	case got := <-done:
		if got.err != nil || got.result.Execution.RedactedDetail != "semantic_timeout" || rt.count() != 1 {
			t.Fatalf("long-thinking expiry lost semantics: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("native semantic deadline did not fire")
	}
}
