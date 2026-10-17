package probe

// Wire regressions exercise production Executor/Decoder/Classifier, not a
// second scanner or an error-message keyword parser.
import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func executeStreamFixture(t *testing.T, proto model.Protocol, reader io.Reader) ExecutionResult {
	t.Helper()
	transport := &countingRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: io.NopCloser(reader)}, nil
	}}
	harness := testProbeExecutor()
	harness.Transport = transport
	harness.L2(context.Background(), upstreamFor("http://fixture.invalid"), modelNameFor(proto), &model.Route{ID: 1}, fastSettings())
	if transport.count() != 1 {
		t.Fatalf("stream fixture performed %d RoundTrips", transport.count())
	}
	return harness.Last
}

func TestNativeStreamSemanticEvidenceAcrossProtocols(t *testing.T) {
	cases := []struct {
		name  string
		proto model.Protocol
		wire  string
	}{
		{"Anthropic text", model.ProtoAnthropic, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"2\"}}\n\n"},
		{"Anthropic thinking", model.ProtoAnthropic, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"reason\"}}\n\n"},
		{"Chat content", model.ProtoOpenAIChat, "data: {\"choices\":[{\"delta\":{\"content\":\"2\"}}]}\n\n"},
		{"Chat reasoning", model.ProtoOpenAIChat, "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"reason\"}}]}\n\n"},
		{"Responses text", model.ProtoOpenAIResponses, "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"2\"}\n\n"},
		{"tool invocation", model.ProtoOpenAIChat, "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call-1\",\"function\":{\"name\":\"ping\",\"arguments\":\"{}\"}}]}}]}\n\n"},
		{"positive output usage", model.ProtoAnthropic, "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":1}}\n\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := executeStreamFixture(t, tc.proto, strings.NewReader(tc.wire))
			if !result.Execution.Success || !result.Execution.SemanticSeen || !result.ExpectedCancel {
				t.Fatalf("semantic probe must succeed and cancel intentionally: %+v", result.Execution)
			}
		})
	}
}

func TestNativeStreamMetadataAndEmptyToolScaffoldingAreNotLife(t *testing.T) {
	for _, tc := range []struct {
		name  string
		proto model.Protocol
		wire  string
	}{
		{"Anthropic metadata/end", model.ProtoAnthropic, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"x\",\"content\":[]}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"},
		{"empty tool index", model.ProtoOpenAIChat, "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0}]}}]}\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := executeStreamFixture(t, tc.proto, strings.NewReader(tc.wire))
			if result.Execution.Success || result.Execution.SemanticSeen || result.Execution.ErrorClass != model.ErrorFakeAlive || result.Execution.ResponseBytes == 0 {
				t.Fatalf("metadata falsely proved life: %+v", result.Execution)
			}
		})
	}
}

func TestNativeStreamStructuredErrorEventsKeepSafeClassification(t *testing.T) {
	for _, tc := range []struct {
		name, wire string
		want       model.ErrorClass
		detail     string
	}{
		{"named error", "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"private upstream body\"}}\n\n", model.ErrorRateLimited, "overloaded_error"},
		{"bare error", "data: {\"error\":{\"message\":\"private upstream body\",\"code\":\"no_available_channel\"}}\n\n", model.ErrorTransient, "no_available_channel"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := executeStreamFixture(t, model.ProtoAnthropic, strings.NewReader(tc.wire))
			if result.Execution.Success || result.Execution.ErrorClass != tc.want || !strings.Contains(result.Execution.RedactedDetail, tc.detail) || strings.Contains(result.Execution.RedactedDetail, "private upstream body") {
				t.Fatalf("wrong structured/private evidence: %+v", result.Execution)
			}
		})
	}
}

func TestNativeStreamEmptyBodyHasNoResponseBytes(t *testing.T) {
	result := executeStreamFixture(t, model.ProtoAnthropic, strings.NewReader(""))
	if result.Execution.Success || result.Execution.ResponseBytes != 0 || result.Execution.ErrorClass != model.ErrorTransient || result.Execution.FirstByteAtMS != 0 {
		t.Fatalf("empty stream falsely succeeded: %+v", result.Execution)
	}
}

// The Executor can have one read in flight when semantic cancellation returns.
// Only that goroutine owns Reader; assertions observe the atomic byte count.
type streamFixtureReadCounter struct {
	io.Reader
	bytes atomic.Int64
}

func (r *streamFixtureReadCounter) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.bytes.Add(int64(n))
	return n, err
}

func TestNativeStreamStopsReadingAfterFirstSemanticVerdict(t *testing.T) {
	head := "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"2\"}}\n\n"
	tail := strings.Repeat("event: ping\ndata: {}\n\n", 5000)
	reader := &streamFixtureReadCounter{Reader: strings.NewReader(head + tail)}
	result := executeStreamFixture(t, model.ProtoAnthropic, reader)
	unread := int64(len(head)+len(tail)) - reader.bytes.Load()
	if !result.Execution.Success || !result.ExpectedCancel || unread <= 0 || result.Execution.ResponseBytes >= int64(len(head)+len(tail)) {
		t.Fatalf("semantic verdict consumed remaining generation: %+v unread=%d", result.Execution, unread)
	}
}

func TestNativeStreamEndlessNoiseIsBounded(t *testing.T) {
	noise := strings.Repeat("event: ping\ndata: {}\n\n", 500000)
	result := executeStreamFixture(t, model.ProtoAnthropic, strings.NewReader(noise))
	if result.Execution.Success || result.Execution.ResponseBytes > defaultMaxTotalBytes+readChunk {
		t.Fatalf("unbounded noise scan: bytes=%d error=%s", result.Execution.ResponseBytes, result.Execution.ErrorClass)
	}
}

func TestNativeStreamFirstByteTimestampSurvivesLaterEvents(t *testing.T) {
	result := executeStreamFixture(t, model.ProtoAnthropic, strings.NewReader("event: message_start\ndata: {\"type\":\"message_start\"}\n\n"+aliveSSE))
	execution := result.Execution
	if !execution.Success || execution.FirstByteAtMS == 0 || execution.FirstByteAtMS > execution.FirstEventAtMS || execution.FirstEventAtMS > execution.FirstSemanticAtMS {
		t.Fatalf("first-byte/event/semantic timeline inconsistent: %+v", execution)
	}
}

func TestNativeStreamAcceptsLongMetadataWithinEventBudget(t *testing.T) {
	padding := strings.Repeat("a", 200<<10)
	wire := "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"" + padding + "\"}}\n\n" + aliveSSE
	if result := executeStreamFixture(t, model.ProtoAnthropic, strings.NewReader(wire)); !result.Execution.Success {
		t.Fatalf("long valid metadata broke decoding: %+v", result.Execution)
	}
}

func TestNativeStreamEventNameEndsAtBlankLine(t *testing.T) {
	wire := "event: error\n\n" + "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"2\"}}\n\n"
	if result := executeStreamFixture(t, model.ProtoAnthropic, strings.NewReader(wire)); !result.Execution.Success {
		t.Fatalf("empty event leaked its name: %+v", result.Execution)
	}
}

func TestNativeStreamStructuredStatusRemainsEventEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, payload string
		want          int
	}{
		{"error.code", `{"error":{"code":401,"message":"private"}}`, 0},
		{"error.status", `{"error":{"status":429}}`, 429},
		{"no numeric status", `{"error":{"message":"private"}}`, 0},
		{"out-of-range code", `{"error":{"code":99}}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decoder, err := NewDecoder(DecoderSpec{Endpoint: model.EndpointMessages, Protocol: model.ProtoAnthropic}, WireSSE, 1<<20, 8<<20)
			if err != nil {
				t.Fatal(err)
			}
			events, err := decoder.Feed([]byte("event: error\ndata: " + tc.payload + "\n\n"))
			if err != nil {
				t.Fatal(err)
			}
			if len(events) != 1 || events[0].Kind != EventRemoteError || events[0].ErrorStatus != tc.want {
				t.Fatalf("numeric error evidence invented/lost: %+v", events)
			}
		})
	}
	decoder, err := NewDecoder(DecoderSpec{Endpoint: model.EndpointMessages, Protocol: model.ProtoAnthropic}, WireSSE, 1<<20, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Feed([]byte("data: boom\n\n")); err == nil {
		t.Fatal("malformed text became fabricated HTTP 500")
	}
}
