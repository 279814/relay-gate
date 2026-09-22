package probe

import (
	"errors"
	"fmt"
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

// payloadEvents 剥掉非流式正文末尾的「正文读完」事件。
//
// 普通 JSON 的完整正文自己就是协议结束（见 finishJSON），所以每份 JSON 都会
// 多一个 EventProtocolEnd。断言正文语义的那些用例关心的是它**前面**那些事件，
// 而顺手把 len 改成 2 会让「多出来的这一个到底是什么」不再被检查 ——
// 于是任何一个多余事件都能混进来。这里顺带把那个契约钉住。
func payloadEvents(t *testing.T, events []ProtocolEvent) []ProtocolEvent {
	t.Helper()
	if len(events) == 0 {
		t.Fatal("no events at all")
	}
	last := events[len(events)-1]
	if last.Kind != EventProtocolEnd {
		t.Fatalf("last event = %#v, want the body-complete protocol end", last)
	}
	return events[:len(events)-1]
}

func TestCountTokensUsesInputTokensAndModelsRecognizesEmptyList(t *testing.T) {
	events, err := decodeChunks(t, eventSpec(model.EndpointCountTokens, model.ProtoAnthropic), WireJSON,
		`{"input_tokens":8}`)
	if err != nil {
		t.Fatalf("count_tokens decode: %v", err)
	}
	events = payloadEvents(t, events)
	if len(events) != 1 || !events[0].Semantic || events[0].InputTokens != 8 || events[0].OutputTokens != 0 {
		t.Fatalf("count_tokens events = %#v", events)
	}

	events, err = decodeChunks(t, eventSpec(model.EndpointModels, ""), WireJSON, `{"data":[]}`)
	if err != nil {
		t.Fatalf("models decode: %v", err)
	}
	events = payloadEvents(t, events)
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
	events = payloadEvents(t, events)
	if len(events) != 1 || !events[0].Semantic || events[0].SemanticKind != "text" {
		t.Fatalf("chat events = %#v", events)
	}

	events, err = decodeChunks(t, eventSpec(model.EndpointChatCompletions, model.ProtoOpenAIChat), WireJSON,
		`{"error":{"type":"server_error","code":"upstream_error","message":"secret response"}}`)
	if err != nil {
		t.Fatalf("error envelope decode: %v", err)
	}
	events = payloadEvents(t, events)
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

// 正数 output usage 必须带出准确的 token 数，且不算语义证据。
//
// 刻意不断言 Semantic：manifest 里 responses_output_text_delta 的
// response.completed 带 usage 却标记为非 semantic，也就是「有没有内容证据」
// 与「产生了多少 token」是两件事。把 usage 也算成内容证据的话，一个
// 只回 usage 就收尾的站会和真正吐出内容的站不可区分 —— 而那正是 §8.8
// 列为「不能单独判活」的一条。判活规则属于 P0-08 的 Classifier。
//
// Kind 按 case 声明而不是一律 EventUsage：response.completed 同时是
// Responses 协议的**结束标记**，它的 Kind 必须是 EventProtocolEnd
// （否则 Real 模式看不到协议正常结束，见 protocolTerminalEvents）。
// token 不会因此丢失 —— Classifier 与 Kind 无关地累加。
func TestPositiveOutputUsageIsReportedWithAccurateTokens(t *testing.T) {
	tests := []struct {
		name     string
		spec     DecoderSpec
		wire     string
		tokens   int64
		wantKind EventKind
	}{
		{
			name:     "anthropic",
			spec:     eventSpec(model.EndpointMessages, model.ProtoAnthropic),
			wire:     "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":1}}\n\n",
			tokens:   1,
			wantKind: EventUsage,
		},
		{
			name:     "responses",
			spec:     eventSpec(model.EndpointResponses, model.ProtoOpenAIResponses),
			wire:     "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"output_tokens\":2}}}\n\n",
			tokens:   2,
			wantKind: EventProtocolEnd,
		},
		{
			name:     "chat",
			spec:     eventSpec(model.EndpointChatCompletions, model.ProtoOpenAIChat),
			wire:     "data: {\"choices\":[],\"usage\":{\"completion_tokens\":3}}\n\n",
			tokens:   3,
			wantKind: EventUsage,
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
			if events[0].Kind != tc.wantKind || events[0].OutputTokens != tc.tokens {
				t.Fatalf("event = %#v, want %s with %d output tokens", events[0], tc.wantKind, tc.tokens)
			}
			if events[0].Semantic {
				t.Fatalf("usage must not be semantic evidence: %#v", events[0])
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

// JSON null 不是模型列表。
//
// `json.Unmarshal([]byte("null"), &slice)` **返回 nil error** 并把 slice 置为
// nil —— JSON null 对任何 Go 类型都是合法的。于是 `{"data":null}` 与
// `{"data":[]}`（§4.6 明说合法的空列表）在解析结果上完全相同，
// 一个回 `data:null` 的站会被判成 models supported。
//
// 这不是理论形态：中转站在后端尚未就绪时常常回
// `{"status":"ok","data":null}` 带 200 —— 正是「假活」的定义，而 §8.9 要求
// 只有「结构可读的模型列表」才能算 supported。判错的后果是站级 models 能力
// 显示可用，L2 于是持续往一个没有任何模型的站上烧 token。
func TestModelsRejectsNullAndNonArrayDataFields(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"data null", `{"status":"ok","message":"gateway is running","data":null}`},
		{"data string", `{"data":"not-a-list"}`},
		{"data object", `{"data":{"id":"fixture-model"}}`},
		{"data number", `{"data":7}`},
		{"top level null", `null`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			events, err := decodeChunks(t, eventSpec(model.EndpointModels, ""), WireJSON, tc.body)
			if err != nil {
				// 顶层 null 报协议错误也是可接受的结论 —— 要挡住的是
				// 「静默判成 supported」，而不是要求某个特定错误。
				return
			}
			for _, event := range events {
				if event.ModelListRecognized || event.Kind == EventModelList {
					t.Fatalf("%s was recognized as a model list: %#v", tc.name, events)
				}
			}
		})
	}
}

func TestJSONModelsDirectArrayAndArbitraryObject(t *testing.T) {
	events, err := decodeChunks(t, eventSpec(model.EndpointModels, ""), WireJSON, `[]`)
	if err != nil {
		t.Fatalf("decode array: %v", err)
	}
	events = payloadEvents(t, events)
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

// 本身就是结束事件的 JSON 正文不能拿到第二个结束事件。
//
// finishJSON 给非流式正文补一个 body_complete，而 `{"type":"message_stop"}`
// 已经被识别成 EventProtocolEnd —— 无条件追加会让「这个响应结束了几次」变得
// 含混，而下一个按结束事件计数的读者（P0-13 的真实流量观察器）会看到 2。
func TestJSONTerminalBodyDoesNotGetASecondProtocolEnd(t *testing.T) {
	events, err := decodeChunks(t, eventSpec(model.EndpointMessages, model.ProtoAnthropic), WireJSON,
		`{"type":"message_stop"}`)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %#v, want exactly one protocol end", events)
	}
	if events[0].Kind != EventProtocolEnd || events[0].EventName != "message_stop" {
		t.Fatalf("event = %#v, want the message_stop protocol end", events[0])
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

// SemanticKind 必须是确定的，不能取决于 map 遍历顺序。
//
// 一个 chunk 里同时出现 content 和 refusal 是真实形态（拒答时个别站两个都填）。
// 用 map 遍历挑字段的话，同一份字节在两次运行里会给出不同的 SemanticKind，
// 而 P0-08 要按它分流「真内容」与「拒答」—— 于是同一个站会随机地被判成
// 两种不同结果，且复现不了。
func TestChatSemanticKindIsDeterministicWhenSeveralFieldsArePresent(t *testing.T) {
	wire := "data: {\"choices\":[{\"delta\":{\"refusal\":\"no\",\"content\":\"2\",\"reasoning_content\":\"think\"}}]}\n\n"
	for range 16 {
		events, err := decodeChunks(t, eventSpec(model.EndpointChatCompletions, model.ProtoOpenAIChat), WireSSE, wire)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(events) != 1 || events[0].SemanticKind != "text" {
			t.Fatalf("events = %#v, want SemanticKind \"text\" (content outranks refusal)", events)
		}
	}
}

// 空的 tool/function arguments 不是内容证据。
//
// 用 `bytes.Contains(raw, "arguments")` 判定的话，`"arguments":""` 与
// `{"name":"arguments"}` 都会被算成「模型在生成」—— 与 §8.8 对空 delta 的
// 要求正好相反，而这两种形态恰恰是假活站的典型输出。
func TestEmptyToolArgumentsAreNotSemantic(t *testing.T) {
	cases := []struct {
		name string
		wire string
	}{
		{"empty tool arguments", "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":\"\"}}]}}]}\n\n"},
		{"empty function arguments", "data: {\"choices\":[{\"delta\":{\"function_call\":{\"arguments\":\"\"}}}]}\n\n"},
		{"arguments only as an index", "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0}]}}]}\n\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events, err := decodeChunks(t, eventSpec(model.EndpointChatCompletions, model.ProtoOpenAIChat), WireSSE, tc.wire)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			for _, event := range events {
				if event.Semantic {
					t.Fatalf("empty arguments became semantic: %#v", event)
				}
			}
		})
	}
}

// 负数 token 数必须当作「没有可信数字」丢掉，而不是原样带出。
//
// P0-08 要把 usage 事件单调累加成 Decision 的 token 总数。让 -5 流进去的话
// 总和会往回走，于是「这次探活比上次少花了 token」这种不可能的结论会进数据库，
// 而源头在这里 —— 到那一层已经查不出是哪个站发的。
func TestNegativeTokenCountsAreDiscarded(t *testing.T) {
	cases := []struct {
		name string
		spec DecoderSpec
		wire string
	}{
		{
			name: "anthropic output tokens",
			spec: eventSpec(model.EndpointMessages, model.ProtoAnthropic),
			wire: "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":-5}}\n\n",
		},
		{
			name: "chat completion tokens",
			spec: eventSpec(model.EndpointChatCompletions, model.ProtoOpenAIChat),
			wire: "data: {\"choices\":[],\"usage\":{\"completion_tokens\":-1}}\n\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events, err := decodeChunks(t, tc.spec, WireSSE, tc.wire)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			for _, event := range events {
				if event.OutputTokens != 0 || event.InputTokens != 0 || event.Kind == EventUsage {
					t.Fatalf("negative usage leaked into the event: %#v", event)
				}
			}
		})
	}
}

func TestNegativeCountTokensInputIsNotSemantic(t *testing.T) {
	events, err := decodeChunks(t, eventSpec(model.EndpointCountTokens, model.ProtoAnthropic), WireJSON,
		`{"input_tokens":-3}`)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, event := range events {
		if event.Semantic || event.InputTokens != 0 {
			t.Fatalf("negative input_tokens leaked: %#v", event)
		}
	}
}

// `"error"` 字段的这几种「没有错误」写法不能当成流内错误。
//
// 中转站表达「本次无错误」的拼法不统一：null、false、空串、空对象都见过。
// 把它们当成真错误的话，一个正常工作的站会被判成「上游报错」，而正文里
// 根本没有错误信息可展示 —— UI 上只会出现一个没有原因的失败。
func TestEmptyErrorFieldSpellingsAreNotRemoteErrors(t *testing.T) {
	for _, spelling := range []string{"null", "false", `""`, "{}"} {
		t.Run(spelling, func(t *testing.T) {
			wire := "data: {\"type\":\"message_delta\",\"error\":" + spelling + "}\n\n"
			events, err := decodeChunks(t, eventSpec(model.EndpointMessages, model.ProtoAnthropic), WireSSE, wire)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			for _, event := range events {
				if event.Kind == EventRemoteError {
					t.Fatalf("%s was treated as a remote error: %#v", spelling, event)
				}
			}
		})
	}
}

// Finish 之后再 Feed 必须报错，不能静默丢字节。
//
// 静默返回空序列的话，一个把 Finish 提前调用了的调用方会看到「流里什么都没有」，
// 而字节其实到了、只是被扔了。这与 scanStream 当年把读错误藏进 Err() 是同一类
// 问题：失败没有出口，于是排查方向从一开始就是错的。
func TestFeedAfterFinishIsRejected(t *testing.T) {
	decoder, err := NewDecoder(eventSpec(model.EndpointMessages, model.ProtoAnthropic), WireSSE, 1024, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Feed([]byte("event: ping\ndata: {\"type\":\"ping\"}\n\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Finish(); err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Feed([]byte("data: {\"type\":\"ping\"}\n\n")); !errors.Is(err, ErrDecoderFinished) {
		t.Fatalf("Feed after Finish = %v, want ErrDecoderFinished", err)
	}
}

// WireAuto 的格式重判不能是 O(n²)。
//
// 重判要扫整个已攒缓冲，而「一直定不了型」的正文会让每个字节都触发一次重扫，
// 也就是平方复杂度。最现实的这种正文是 HTML 错误页：公益站被网关拦下时常常
// 回一整页 HTML，它既不是 SSE 也不是 JSON，于是格式永远定不下来。
// 一份攒到上限的这种正文能把一次探活变成几十秒的纯 CPU，而探活跑在调度器起的
// goroutine 里、每 30 秒一轮、站有几十个。
// 工作预算就是为这个准备的 —— 它必须真的能触发，否则只是个没接线的开关。
func TestWireAutoScanWorkIsBounded(t *testing.T) {
	const size = 8 << 10
	adversarial := []byte("<!DOCTYPE html><html><body>" +
		strings.Repeat("upstream gateway error ", size/16) + "</body></html>")

	decoder, err := NewDecoder(eventSpec(model.EndpointResponses, model.ProtoOpenAIResponses),
		WireAuto, int64(len(adversarial))*2, int64(len(adversarial))*2)
	if err != nil {
		t.Fatal(err)
	}
	var feedErr error
	for _, b := range adversarial {
		if _, feedErr = decoder.Feed([]byte{b}); feedErr != nil {
			break
		}
	}
	if feedErr == nil {
		_, feedErr = decoder.Finish()
	}
	if !errors.Is(feedErr, ErrDecoderWorkBudget) {
		t.Fatalf("error = %v, want ErrDecoderWorkBudget", feedErr)
	}
}

// 逐字节到达的**正常** JSON 正文不能被工作预算误杀。
//
// 上一条的预算是给恶意形状准备的。一份合法的大 JSON 也会逐字节走同一条路径，
// 如果重判照样扫全缓冲，它会先撞上预算 —— 症状是「这个站的响应解析不了」，
// 而站是好的。所以在还不可能出现第二个值时（缓冲里没有换行）根本不必重扫。
func TestWireAutoAcceptsLargeSingleValueJSONFedByteByByte(t *testing.T) {
	const size = 8 << 10
	body := `{"input_tokens":8,"padding":"` + strings.Repeat("p", size) + `"}`

	decoder, err := NewDecoder(eventSpec(model.EndpointCountTokens, model.ProtoAnthropic),
		WireAuto, int64(len(body)), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < len(body); index++ {
		if _, err := decoder.Feed([]byte{body[index]}); err != nil {
			t.Fatalf("Feed byte %d: %v", index, err)
		}
	}
	events, err := decoder.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	events = payloadEvents(t, events)
	if len(events) != 1 || events[0].InputTokens != 8 {
		t.Fatalf("events = %#v, want one count_tokens event with 8 input tokens", events)
	}
}

// 缩进过的 JSON 也要能逐字节走完 WireAuto。
//
// 这类正文里到处是换行，而换行正是「可能出现第二个值」的信号 —— 天真的实现
// 会在每个字节上重扫全缓冲，于是一份合法的 models 列表（非流式端点常常是
// 缩进过的）会撞上工作预算，症状是「这个站的响应解析不了」，而站是好的。
func TestWireAutoAcceptsPrettyPrintedJSONFedByteByByte(t *testing.T) {
	body := "{\n  \"data\": [\n"
	for index := range 40 {
		body += fmt.Sprintf("    {\"id\": \"model-%02d\"},\n", index)
	}
	body += "    {\"id\": \"model-last\"}\n  ]\n}\n"

	decoder, err := NewDecoder(eventSpec(model.EndpointModels, ""), WireAuto,
		int64(len(body)), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < len(body); index++ {
		if _, err := decoder.Feed([]byte{body[index]}); err != nil {
			t.Fatalf("Feed byte %d of %d: %v", index, len(body), err)
		}
	}
	events, err := decoder.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	events = payloadEvents(t, events)
	if len(events) != 1 || !events[0].ModelListRecognized || events[0].ModelCount != 41 {
		t.Fatalf("events = %#v, want one model list of 41", events)
	}
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
