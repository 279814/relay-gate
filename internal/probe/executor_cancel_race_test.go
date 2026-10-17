package probe

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
)

type cancellationAuditBody struct {
	io.ReadCloser
	active atomic.Int32
	closed atomic.Int32
}

func (body *cancellationAuditBody) Read(p []byte) (int, error) {
	body.active.Add(1)
	defer body.active.Add(-1)
	return body.ReadCloser.Read(p)
}
func (body *cancellationAuditBody) Close() error {
	body.closed.Add(1)
	return body.ReadCloser.Close()
}

// Preserve the shared Decoder and change only cancellation scheduling between
// recognition and classification. No parser, transport, or verdict is replaced.
type cancelRecognizedEventDecoder struct {
	Decoder
	postSemantic bool
	semantic     chan struct{}
	once         sync.Once
	cancel       context.CancelFunc
	clock        *ManualClock
	canceled     bool
}

func (decoder *cancelRecognizedEventDecoder) Feed(body []byte) ([]ProtocolEvent, error) {
	events, err := decoder.Decoder.Feed(body)
	for _, event := range events {
		if event.Semantic {
			decoder.once.Do(func() { close(decoder.semantic) })
		}
		if (!decoder.postSemantic && event.Semantic) || (decoder.postSemantic && event.Kind == EventKeepalive) {
			decoder.canceled = true
			decoder.cancel()
			decoder.clock.Advance(2 * time.Second)
		}
	}
	return events, err
}

func TestExecutorReadCancellationBeforeClassificationBeatsReadyDeadline(t *testing.T) {
	for _, encoding := range []string{"identity", "gzip"} {
		for _, postSemantic := range []bool{false, true} {
			name := encoding + "/before-semantic"
			if postSemantic {
				name = encoding + "/after-semantic"
			}
			t.Run(name, func(t *testing.T) {
				semantic := make(chan struct{})
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "text/event-stream")
					var stream io.Writer = w
					var encoder *gzip.Writer
					if encoding == "gzip" {
						w.Header().Set("Content-Encoding", "gzip")
						encoder = gzip.NewWriter(w)
						stream = encoder
						defer encoder.Close()
					}
					flush := func() {
						if encoder != nil {
							encoder.Flush()
						}
						w.(http.Flusher).Flush()
					}
					io.WriteString(stream, anthropicSemanticBody())
					flush()
					if postSemantic {
						select {
						case <-semantic:
						case <-r.Context().Done():
							return
						}
						io.WriteString(stream, "event: ping\ndata: {\"type\":\"ping\"}\n\n")
						flush()
					}
					<-r.Context().Done()
				}))
				defer server.Close()
				parent, cancelParent := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancelParent()
				sendContext, cancelSend := context.WithCancel(parent)
				defer cancelSend()
				request, err := http.NewRequestWithContext(sendContext, "GET", server.URL, nil)
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("Accept-Encoding", "identity")
				response, err := http.DefaultClient.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				body := &cancellationAuditBody{ReadCloser: response.Body}
				clock := NewManualClock(time.Now())
				sent := clock.Now()
				timing := sendTiming{sentAtMS: sent.UnixMilli(), responseHeaderAtMS: sent.UnixMilli()}
				budget := outbound.Budget{FirstSemantic: time.Second, Idle: time.Second, Total: 30 * time.Second}
				decoder, err := NewDecoder(DecoderSpec{Endpoint: model.EndpointMessages, Protocol: model.ProtoAnthropic}, WireAuto, defaultMaxEventBytes, defaultMaxTotalBytes)
				if err != nil {
					t.Fatal(err)
				}
				controlled := &cancelRecognizedEventDecoder{Decoder: decoder, postSemantic: postSemantic, semantic: semantic, cancel: cancelParent, clock: clock}
				mode := ObserveProbe
				if postSemantic {
					mode = ObserveReal
				}
				classifier := NewResponseClassifier(mode, model.EndpointMessages, 200, response.Header, sent)
				executor := &Executor{clock: clock}
				timer := clock.NewTimer(time.Second)
				defer timer.Stop()
				result := executor.readStream(sendContext, parent, cancelSend, body, response.Header.Get("Content-Encoding"), controlled, classifier, ExecutionRequest{Mode: mode}, budget, sent, &timing, timer)
				body.Close()
				if !controlled.canceled {
					t.Fatal("fixture did not cancel at the intended classification boundary")
				}
				decision := classifier.Finish(result.readErr, result.cancelCause)
				if decision.ErrorClass != model.ErrorIgnored || decision.Partial || decision.Success || result.expectedCancel {
					t.Fatalf("external cancellation became deadline/partial/success: decision=%+v read=%v cause=%v expected=%t", decision, result.readErr, result.cancelCause, result.expectedCancel)
				}
				limit := time.Now().Add(time.Second)
				for body.active.Load() != 0 && time.Now().Before(limit) {
					time.Sleep(time.Millisecond)
				}
				if body.active.Load() != 0 || body.closed.Load() != 1 {
					t.Fatalf("reader/close ownership leaked: active=%d closed=%d", body.active.Load(), body.closed.Load())
				}
			})
		}
	}
}

func TestExecutorHeaderCancellationBeatsReadyDeadlineAndPreservesSendFacts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		drainBody(r)
		w.Header().Set("Content-Type", "text/event-stream")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clock := NewManualClock(time.Now())
	var tracked *cancellationAuditBody
	transport := &countingRoundTripper{fn: func(request *http.Request) (*http.Response, error) {
		response, err := http.DefaultTransport.RoundTrip(request)
		if response != nil {
			tracked = &cancellationAuditBody{ReadCloser: response.Body}
			response.Body = tracked
		}
		cancel()
		clock.Advance(2 * time.Second)
		return response, err
	}}
	up := upstreamFor(server.URL)
	admission := &spyAdmission{}
	executor := newTestExecutorFor(up, transport, &captureRecorder{}, admission, clock)
	request := l2RequestFor(up)
	request.Budget = outbound.Budget{Connect: time.Second, ResponseHead: time.Second, FirstSemantic: time.Second, Total: 30 * time.Second}
	result, err := executor.Execute(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision.ErrorClass != model.ErrorIgnored || result.Outcome.Verdict != health.VerdictIgnore || result.ExpectedCancel {
		t.Fatalf("header cancellation lost priority: %+v", result.Decision)
	}
	if !result.Sent || result.Execution.SentAtMS == 0 || result.Execution.RequestBytes == 0 {
		t.Fatal("cancellation after socket write erased actual sending/cost facts")
	}
	if transport.count() != 1 || admission.acquires != 1 || admission.releases != 1 || tracked == nil || tracked.closed.Load() != 1 {
		t.Fatal("cancelled header attempt leaked transport or synthetic lease")
	}
}
