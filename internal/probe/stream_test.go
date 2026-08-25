package probe

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func decodeChunks(t *testing.T, spec DecoderSpec, format WireFormat, chunks ...string) ([]ProtocolEvent, error) {
	t.Helper()
	decoder, err := NewDecoder(spec, format, 256<<10, 1<<20)
	if err != nil {
		return nil, err
	}
	var events []ProtocolEvent
	for _, chunk := range chunks {
		got, err := decoder.Feed([]byte(chunk))
		if err != nil {
			return events, err
		}
		events = append(events, got...)
	}
	got, err := decoder.Finish()
	events = append(events, got...)
	return events, err
}

func eventSpec(endpoint model.EndpointKind, protocol model.Protocol) DecoderSpec {
	return DecoderSpec{Endpoint: endpoint, Protocol: protocol}
}

func TestNewDecoderRejectsInvalidEndpointProtocolCombination(t *testing.T) {
	tests := []struct {
		name string
		spec DecoderSpec
	}{
		{"models borrows route protocol", eventSpec(model.EndpointModels, model.ProtoAnthropic)},
		{"messages uses responses protocol", eventSpec(model.EndpointMessages, model.ProtoOpenAIResponses)},
		{"responses uses chat protocol", eventSpec(model.EndpointResponses, model.ProtoOpenAIChat)},
		{"chat uses anthropic protocol", eventSpec(model.EndpointChatCompletions, model.ProtoAnthropic)},
		{"count tokens uses responses protocol", eventSpec(model.EndpointCountTokens, model.ProtoOpenAIResponses)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewDecoder(tc.spec, WireJSON, 1024, 4096); !errors.Is(err, ErrInvalidDecoderSpec) {
				t.Fatalf("NewDecoder error = %v, want ErrInvalidDecoderSpec", err)
			}
		})
	}
}

func TestSSECombinesMultilineDataAndSupportsCRLFComments(t *testing.T) {
	wire := ": keepalive\r\n" +
		"event: content_block_delta\r\n" +
		"data: {\"type\":\"content_block_delta\",\r\n" +
		"data: \"delta\":{\"type\":\"text_delta\",\"text\":\"2\"}}\r\n" +
		"\r\n"

	events, err := decodeChunks(t, eventSpec(model.EndpointMessages, model.ProtoAnthropic), WireSSE,
		wire[:17], wire[17:31], wire[31:])
	if err != nil {
		t.Fatalf("decode SSE: %v", err)
	}
	want := []ProtocolEvent{
		{Kind: EventSemantic, EventName: "content_block_delta", Semantic: true, SemanticKind: "text"},
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %#v, want %#v", events, want)
	}
}

func TestSSEEmitsMetadataKeepaliveAndErrorWithoutTreatingThemAsSemantic(t *testing.T) {
	wire := "event: ping\ndata: {\"type\":\"ping\"}\n\n" +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":0},\"error\":null}\n\n" +
		"event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"code\":\"busy\",\"param\":\"model\",\"message\":\"do not retain\"}}\n\n"

	events, err := decodeChunks(t, eventSpec(model.EndpointMessages, model.ProtoAnthropic), WireSSE, wire)
	if err != nil {
		t.Fatalf("decode SSE: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3: %#v", len(events), events)
	}
	if events[0].Kind != EventKeepalive || events[0].EventName != "ping" || events[0].SemanticKind != "" {
		t.Errorf("ping event = %#v", events[0])
	}
	if events[1].Kind != EventMetadata || events[1].OutputTokens != 0 || events[1].SemanticKind != "" {
		t.Errorf("zero usage event = %#v", events[1])
	}
	if events[2].Kind != EventRemoteError || events[2].RedactedType != "overloaded_error" ||
		events[2].ErrorCode != "busy" || events[2].ErrorField != "model" || events[2].SemanticKind != "" {
		t.Errorf("error event = %#v", events[2])
	}
}

func TestSSEFinishCommitsEventWithoutTrailingBlankLine(t *testing.T) {
	wire := "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"2\"}}"
	events, err := decodeChunks(t, eventSpec(model.EndpointMessages, model.ProtoAnthropic), WireSSE, wire)
	if err != nil {
		t.Fatalf("decode SSE: %v", err)
	}
	if len(events) != 1 || !events[0].Semantic || events[0].EventName != "content_block_delta" {
		t.Fatalf("events = %#v, want one semantic content_block_delta", events)
	}
}

func TestNDJSONEmitsEachCompleteLineAndRejectsTruncatedTail(t *testing.T) {
	wire := "{\"type\":\"response.output_text.delta\",\"delta\":\"2\"}\n" +
		"{\"type\":\"response.completed\"}\n"
	events, err := decodeChunks(t, eventSpec(model.EndpointResponses, model.ProtoOpenAIResponses), WireNDJSON,
		wire[:8], wire[8:])
	if err != nil {
		t.Fatalf("decode NDJSON: %v", err)
	}
	if len(events) != 2 || !events[0].Semantic || events[1].Semantic {
		t.Fatalf("events = %#v, want semantic then metadata", events)
	}

	decoder, err := NewDecoder(eventSpec(model.EndpointResponses, model.ProtoOpenAIResponses), WireNDJSON, 1024, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Feed([]byte(`{"type":"response.output_text.delta"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Finish(); !errors.Is(err, ErrIncompleteWire) {
		t.Fatalf("Finish error = %v, want ErrIncompleteWire", err)
	}
}

func TestJSONRejectsTrailingNonWhitespace(t *testing.T) {
	decoder, err := NewDecoder(eventSpec(model.EndpointChatCompletions, model.ProtoOpenAIChat), WireJSON, 1024, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Feed([]byte(`{"id":"x","choices":[{"message":{"content":"2"}}]} garbage`)); err != nil {
		t.Fatalf("Feed error = %v, want deferred Finish validation", err)
	}
	if _, err := decoder.Finish(); !errors.Is(err, ErrTrailingJSON) {
		t.Fatalf("Finish error = %v, want ErrTrailingJSON", err)
	}
}

func TestCountTokensUsesInputTokensAndModelsRecognizesEmptyList(t *testing.T) {
	events, err := decodeChunks(t, eventSpec(model.EndpointCountTokens, model.ProtoAnthropic), WireJSON,
		`{"input_tokens":8}`)
	if err != nil {
		t.Fatalf("count_tokens decode: %v", err)
	}
	if len(events) != 1 || !events[0].Semantic || events[0].InputTokens != 8 || events[0].OutputTokens != 0 {
		t.Fatalf("count_tokens events = %#v", events)
	}

	events, err = decodeChunks(t, eventSpec(model.EndpointModels, ""), WireJSON, `{"data":[]}`)
	if err != nil {
		t.Fatalf("models decode: %v", err)
	}
	if len(events) != 1 || !events[0].ModelListRecognized || !events[0].Semantic || events[0].ModelCount != 0 {
		t.Fatalf("models events = %#v", events)
	}
}

func TestNonEmptyModelOutputIsSemanticButErrorEnvelopeIsNot(t *testing.T) {
	events, err := decodeChunks(t, eventSpec(model.EndpointChatCompletions, model.ProtoOpenAIChat), WireJSON,
		`{"id":"x","object":"chat.completion","choices":[{"message":{"content":"2"}}]}`)
	if err != nil {
		t.Fatalf("chat decode: %v", err)
	}
	if len(events) != 1 || !events[0].Semantic || events[0].SemanticKind != "text" {
		t.Fatalf("chat events = %#v", events)
	}

	events, err = decodeChunks(t, eventSpec(model.EndpointChatCompletions, model.ProtoOpenAIChat), WireJSON,
		`{"error":{"type":"server_error","code":"upstream_error","message":"secret response"}}`)
	if err != nil {
		t.Fatalf("error envelope decode: %v", err)
	}
	if len(events) != 1 || events[0].Kind != EventRemoteError || events[0].Semantic || events[0].RedactedType != "server_error" {
		t.Fatalf("error envelope events = %#v", events)
	}
}

func TestDecoderErrorsDoNotContainRawPayload(t *testing.T) {
	secret := "fixture-secret-response"
	decoder, err := NewDecoder(eventSpec(model.EndpointMessages, model.ProtoAnthropic), WireSSE, 32, 128)
	if err != nil {
		t.Fatal(err)
	}
	_, err = decoder.Feed([]byte("data: {\"type\":\"content_block_delta\",\"payload\":\"" + secret + "\"}\n\n"))
	if err == nil {
		t.Fatal("oversized event should fail")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("decoder error leaked raw payload: %v", err)
	}
}

func TestDetectWireFormatUsesPrefixWhenContentTypeIsMissingOrWrong(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		prefix      string
		want        WireFormat
	}{
		{"sse missing type", "", "event: ping\ndata: {}\n", WireSSE},
		{"sse wrong type", "application/json", "data: [DONE]\n", WireSSE},
		{"ndjson explicit type", "application/x-ndjson", "{\"type\":\"x\"}\n", WireNDJSON},
		{"json object", "text/plain", string([]byte{0xef, 0xbb, 0xbf}) + " {\"ok\":true}", WireJSON},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := DetectWireFormat(tc.contentType, []byte(tc.prefix)); got != tc.want {
				t.Fatalf("DetectWireFormat() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSemanticEvidenceAcrossProtocols(t *testing.T) {
	tests := []struct {
		name     string
		spec     DecoderSpec
		format   WireFormat
		wire     string
		wantKind string
	}{
		{
			name: "anthropic text",
			spec: eventSpec(model.EndpointMessages, model.ProtoAnthropic), format: WireSSE,
			wire:     "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"2\"}}\n\n",
			wantKind: "text",
		},
		{
			name: "anthropic thinking",
			spec: eventSpec(model.EndpointMessages, model.ProtoAnthropic), format: WireSSE,
			wire:     "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"reason\"}}\n\n",
			wantKind: "thinking",
		},
		{
			name: "anthropic input json",
			spec: eventSpec(model.EndpointMessages, model.ProtoAnthropic), format: WireSSE,
			wire:     "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"x\\\":\"}}\n\n",
			wantKind: "input_json",
		},
		{
			name: "responses output text",
			spec: eventSpec(model.EndpointResponses, model.ProtoOpenAIResponses), format: WireNDJSON,
			wire:     "{\"type\":\"response.output_text.delta\",\"delta\":\"2\"}\n",
			wantKind: "text",
		},
		{
			name: "responses reasoning",
			spec: eventSpec(model.EndpointResponses, model.ProtoOpenAIResponses), format: WireNDJSON,
			wire:     "{\"type\":\"response.reasoning_summary_text.delta\",\"delta\":\"reason\"}\n",
			wantKind: "reasoning",
		},
		{
			name: "responses refusal",
			spec: eventSpec(model.EndpointResponses, model.ProtoOpenAIResponses), format: WireNDJSON,
			wire:     "{\"type\":\"response.refusal.delta\",\"delta\":\"no\"}\n",
			wantKind: "refusal",
		},
		{
			name: "responses function arguments",
			spec: eventSpec(model.EndpointResponses, model.ProtoOpenAIResponses), format: WireNDJSON,
			wire:     "{\"type\":\"response.function_call_arguments.delta\",\"delta\":\"{\"}\n",
			wantKind: "function_args",
		},
		{
			name: "chat content",
			spec: eventSpec(model.EndpointChatCompletions, model.ProtoOpenAIChat), format: WireSSE,
			wire:     "data: {\"choices\":[{\"delta\":{\"content\":\"2\"}}]}\n\n",
			wantKind: "text",
		},
		{
			name: "chat tool arguments",
			spec: eventSpec(model.EndpointChatCompletions, model.ProtoOpenAIChat), format: WireSSE,
			wire:     "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":\"{\"}}]}}]}\n\n",
			wantKind: "tool",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			events, err := decodeChunks(t, tc.spec, tc.format, tc.wire)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(events) != 1 || !events[0].Semantic || events[0].Kind != EventSemantic || events[0].SemanticKind != tc.wantKind {
				t.Fatalf("events = %#v, want one %q semantic event", events, tc.wantKind)
			}
		})
	}
}

func TestEmptyDeltasAndZeroUsageAreNotSemantic(t *testing.T) {
	tests := []struct {
		name   string
		spec   DecoderSpec
		format WireFormat
		wire   string
	}{
		{
			name: "anthropic empty text", spec: eventSpec(model.EndpointMessages, model.ProtoAnthropic), format: WireSSE,
			wire: "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"\"}}\n\n",
		},
		{
			name: "responses empty refusal", spec: eventSpec(model.EndpointResponses, model.ProtoOpenAIResponses), format: WireNDJSON,
			wire: "{\"type\":\"response.refusal.delta\",\"delta\":\"\"}\n",
		},
		{
			name: "chat empty content", spec: eventSpec(model.EndpointChatCompletions, model.ProtoOpenAIChat), format: WireSSE,
			wire: "data: {\"choices\":[{\"delta\":{\"content\":\"\"}}]}\n\n",
		},
		{
			name: "anthropic zero usage", spec: eventSpec(model.EndpointMessages, model.ProtoAnthropic), format: WireSSE,
			wire: "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":0}}\n\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			events, err := decodeChunks(t, tc.spec, tc.format, tc.wire)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			for _, event := range events {
				if event.Semantic || event.Kind == EventSemantic {
					t.Fatalf("empty/zero event became semantic: %#v", event)
				}
			}
		})
	}
}

// 正数 output usage 必须带出 EventUsage 与准确的 token 数。
//
// 刻意不断言 Semantic：manifest 里 responses_output_text_delta 的
// response.completed 带 usage 却标记为非 semantic，也就是「有没有内容证据」
// 与「产生了多少 token」是两件事。把 usage 也算成内容证据的话，一个
// 只回 usage 就收尾的站会和真正吐出内容的站不可区分 —— 而那正是 §8.8
// 列为「不能单独判活」的一条。判活规则属于 P0-08 的 Classifier。
func TestPositiveOutputUsageIsReportedAsUsageEvent(t *testing.T) {
	tests := []struct {
		name   string
		spec   DecoderSpec
		wire   string
		tokens int64
	}{
		{
			name:   "anthropic",
			spec:   eventSpec(model.EndpointMessages, model.ProtoAnthropic),
			wire:   "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":1}}\n\n",
			tokens: 1,
		},
		{
			name:   "responses",
			spec:   eventSpec(model.EndpointResponses, model.ProtoOpenAIResponses),
			wire:   "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"output_tokens\":2}}}\n\n",
			tokens: 2,
		},
		{
			name:   "chat",
			spec:   eventSpec(model.EndpointChatCompletions, model.ProtoOpenAIChat),
			wire:   "data: {\"choices\":[],\"usage\":{\"completion_tokens\":3}}\n\n",
			tokens: 3,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			events, err := decodeChunks(t, tc.spec, WireSSE, tc.wire)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(events) != 1 {
				t.Fatalf("events = %#v, want exactly one", events)
			}
			if events[0].Kind != EventUsage || events[0].OutputTokens != tc.tokens {
				t.Fatalf("event = %#v, want EventUsage with %d output tokens", events[0], tc.tokens)
			}
		})
	}
}

func TestSSEEventWithoutDataStillProducesProtocolEvent(t *testing.T) {
	events, err := decodeChunks(t, eventSpec(model.EndpointMessages, model.ProtoAnthropic), WireSSE,
		"event: ping\n\n")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(events) != 1 || events[0].Kind != EventKeepalive || events[0].EventName != "ping" {
		t.Fatalf("events = %#v, want ping keepalive", events)
	}
}

func TestBareTypeErrorIsRemoteErrorWithoutMessageRetention(t *testing.T) {
	events, err := decodeChunks(t, eventSpec(model.EndpointResponses, model.ProtoOpenAIResponses), WireNDJSON,
		"{\"type\":\"error\",\"code\":\"overloaded\",\"message\":\"must not retain\"}\n")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(events) != 1 || events[0].Kind != EventRemoteError || events[0].ErrorCode != "overloaded" {
		t.Fatalf("events = %#v", events)
	}
}

func TestWireAutoDetectsSSEJSONAndNDJSON(t *testing.T) {
	tests := []struct {
		name string
		spec DecoderSpec
		wire string
		want string
	}{
		{
			name: "sse", spec: eventSpec(model.EndpointMessages, model.ProtoAnthropic),
			wire: "data: {\"type\":\"ping\"}\n\n", want: "ping",
		},
		{
			name: "json", spec: eventSpec(model.EndpointCountTokens, model.ProtoAnthropic),
			wire: "{\"input_tokens\":8}", want: "count_tokens",
		},
		{
			name: "ndjson", spec: eventSpec(model.EndpointResponses, model.ProtoOpenAIResponses),
			wire: "{\"type\":\"response.created\"}\n{\"type\":\"response.completed\"}\n", want: "response.created",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decoder, err := NewDecoder(tc.spec, WireAuto, 1024, 4096)
			if err != nil {
				t.Fatal(err)
			}
			var events []ProtocolEvent
			for _, b := range []byte(tc.wire) {
				got, err := decoder.Feed([]byte{b})
				if err != nil {
					t.Fatalf("Feed: %v", err)
				}
				events = append(events, got...)
			}
			got, err := decoder.Finish()
			if err != nil {
				t.Fatalf("Finish: %v", err)
			}
			events = append(events, got...)
			if len(events) == 0 || events[0].EventName != tc.want {
				t.Fatalf("events = %#v, want first event %q", events, tc.want)
			}
		})
	}
}

func TestJSONModelsDirectArrayAndArbitraryObject(t *testing.T) {
	events, err := decodeChunks(t, eventSpec(model.EndpointModels, ""), WireJSON, `[]`)
	if err != nil {
		t.Fatalf("decode array: %v", err)
	}
	if len(events) != 1 || !events[0].ModelListRecognized || events[0].ModelCount != 0 {
		t.Fatalf("direct array events = %#v", events)
	}

	events, err = decodeChunks(t, eventSpec(model.EndpointModels, ""), WireJSON, `{"ok":true}`)
	if err != nil {
		t.Fatalf("decode object: %v", err)
	}
	for _, event := range events {
		if event.ModelListRecognized || event.Kind == EventModelList {
			t.Fatalf("arbitrary object recognized as model list: %#v", events)
		}
	}
}

func TestDecoderNamedLimitsAndExactBoundaries(t *testing.T) {
	t.Run("event too large", func(t *testing.T) {
		decoder, err := NewDecoder(eventSpec(model.EndpointMessages, model.ProtoAnthropic), WireSSE, 16, 1024)
		if err != nil {
			t.Fatal(err)
		}
		_, err = decoder.Feed([]byte("data: {\"value\":\"12345678901234567\"}\n\n"))
		if !errors.Is(err, ErrEventTooLarge) {
			t.Fatalf("Feed error = %v, want ErrEventTooLarge", err)
		}
	})

	t.Run("body too large", func(t *testing.T) {
		decoder, err := NewDecoder(eventSpec(model.EndpointChatCompletions, model.ProtoOpenAIChat), WireJSON, 1024, 4)
		if err != nil {
			t.Fatal(err)
		}
		_, err = decoder.Feed([]byte(`{"x":1}`))
		if !errors.Is(err, ErrDecodedBodyTooLarge) {
			t.Fatalf("Feed error = %v, want ErrDecodedBodyTooLarge", err)
		}
	})

	t.Run("exact total limit", func(t *testing.T) {
		wire := `{"input_tokens":8}`
		decoder, err := NewDecoder(eventSpec(model.EndpointCountTokens, model.ProtoAnthropic), WireJSON, 1024, int64(len(wire)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decoder.Feed([]byte(wire)); err != nil {
			t.Fatalf("exact limit Feed: %v", err)
		}
		if _, err := decoder.Finish(); err != nil {
			t.Fatalf("exact limit Finish: %v", err)
		}
	})
}

func TestDecoderFinishReturnsSameEOFEventOnRepeat(t *testing.T) {
	decoder, err := NewDecoder(eventSpec(model.EndpointMessages, model.ProtoAnthropic), WireSSE, 1024, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Feed([]byte("event: ping\ndata: {\"type\":\"ping\"}")); err != nil {
		t.Fatal(err)
	}
	first, firstErr := decoder.Finish()
	second, secondErr := decoder.Finish()
	if firstErr != nil || secondErr != nil || !reflect.DeepEqual(first, second) || len(first) != 1 {
		t.Fatalf("Finish not repeatable: first=%#v/%v second=%#v/%v", first, firstErr, second, secondErr)
	}
}

func TestDecoderFinishIsIdempotent(t *testing.T) {
	decoder, err := NewDecoder(eventSpec(model.EndpointResponses, model.ProtoOpenAIResponses), WireNDJSON, 1024, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Feed([]byte(`{"type":"response.completed"}\n`)); err != nil {
		t.Fatal(err)
	}
	first, firstErr := decoder.Finish()
	second, secondErr := decoder.Finish()
	if !reflect.DeepEqual(first, second) || !reflect.DeepEqual(firstErr, secondErr) {
		t.Fatalf("Finish not idempotent: first=%#v/%v second=%#v/%v", first, firstErr, second, secondErr)
	}
}
