package probe

import (
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/protocol"
)

func TestCanaryStrictPayloadUsesSharedDecoder(t *testing.T) {
	nonce := "00112233445566778899aabbccddeeff"
	args := `{"nonce":"` + nonce + `"}`
	good := []struct {
		name     string
		endpoint model.EndpointKind
		proto    model.Protocol
		body     string
	}{
		{"messages-json", model.EndpointMessages, model.ProtoAnthropic, `{"content":[{"type":"tool_use","id":"one","name":"relay_canary_noop","input":` + args + `}],"stop_reason":"tool_use","usage":{"input_tokens":0,"output_tokens":0}}`},
		{"responses-json", model.EndpointResponses, model.ProtoOpenAIResponses, `{"status":"completed","output":[{"id":"one","type":"function_call","call_id":"call","name":"relay_canary_noop","arguments":"{\"nonce\":\"` + nonce + `\"}"}],"usage":{"input_tokens":0,"output_tokens":0}}`},
		{"chat-json", model.EndpointChatCompletions, model.ProtoOpenAIChat, `{"choices":[{"index":0,"message":{"tool_calls":[{"id":"one","type":"function","function":{"name":"relay_canary_noop","arguments":"{\"nonce\":\"` + nonce + `\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":0,"completion_tokens":0}}`},
		{"messages-sse", model.EndpointMessages, model.ProtoAnthropic, "event: content_block_start\ndata: " + `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"one","name":"relay_canary_noop","input":{}}}` + "\n\nevent: content_block_delta\ndata: " + `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"nonce\":\"` + nonce + `\"}"}}` + "\n\nevent: message_delta\ndata: " + `{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":0}}` + "\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"},
		{"chat-sse", model.EndpointChatCompletions, model.ProtoOpenAIChat, "data: " + `{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"one","function":{"name":"relay_canary_","arguments":"{\"nonce\":"}}]}}]}` + "\n\ndata: " + `{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"noop","arguments":"\"` + nonce + `\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"completion_tokens":0}}` + "\n\ndata: [DONE]\n\n"},
		{"responses-sse", model.EndpointResponses, model.ProtoOpenAIResponses, "event: response.output_item.added\ndata: " + `{"type":"response.output_item.added","output_index":0,"item":{"id":"one","type":"function_call","name":"relay_canary_noop","arguments":""}}` + "\n\nevent: response.function_call_arguments.delta\ndata: " + `{"type":"response.function_call_arguments.delta","output_index":0,"item_id":"one","delta":"{\"nonce\":\"` + nonce + `\"}"}` + "\n\nevent: response.function_call_arguments.done\ndata: " + `{"type":"response.function_call_arguments.done","output_index":0,"item_id":"one","arguments":"{\"nonce\":\"` + nonce + `\"}"}` + "\n\nevent: response.completed\ndata: " + `{"type":"response.completed","response":{"status":"completed","output":[{"id":"one","type":"function_call","name":"relay_canary_noop","arguments":"{\"nonce\":\"` + nonce + `\"}"}],"usage":{"input_tokens":0,"output_tokens":0}}}` + "\n\n"},
	}
	for _, tc := range good {
		t.Run(tc.name, func(t *testing.T) {
			for _, chunkSize := range []int{1, len(tc.body)} {
				check := newCanaryCheck(tc.endpoint, nonce, model.CanaryManual, 0)
				decoder, err := protocol.NewDecoderWithPayloadSink(protocol.DecoderSpec{Endpoint: tc.endpoint, Protocol: tc.proto}, protocol.WireAuto, 256<<10, 1<<20, check.observe)
				if err != nil {
					t.Fatal(err)
				}
				e := model.ProbeExecution{ID: "synthetic-canary", SentAtMS: 1, Success: true}
				feed := func(events []protocol.ProtocolEvent) {
					for _, event := range events {
						e.SemanticSeen = e.SemanticSeen || event.Semantic
						e.NormalEndSeen = e.NormalEndSeen || event.Kind == protocol.EventProtocolEnd
					}
				}
				for offset := 0; offset < len(tc.body); offset += chunkSize {
					events, err := decoder.Feed([]byte(tc.body[offset:min(offset+chunkSize, len(tc.body))]))
					if err != nil {
						t.Fatalf("fixture decode: %v", err)
					}
					feed(events)
				}
				events, err := decoder.Finish()
				if err != nil {
					t.Fatalf("fixture finish: %v", err)
				}
				feed(events)
				result := check.finalize(e)
				if result.Verdict != "passed" || !e.SemanticSeen || result.NonceMatched == nil || !*result.NonceMatched || result.ToolMatched == nil || !*result.ToolMatched || !result.OutputUsagePresent {
					t.Fatalf("strict valid payload chunk=%d result=%+v normalEnd=%v", chunkSize, result, e.NormalEndSeen)
				}
			}
		})
	}
	base := good[0]
	for name, body := range map[string]string{
		"wrong-nonce":         strings.ReplaceAll(base.body, nonce, "ffeeddccbbaa99887766554433221100"),
		"other-tool":          strings.ReplaceAll(base.body, model.CanaryTool, "run_shell"),
		"extra-text":          strings.Replace(base.body, `"content":[`, `"content":[{"type":"text","text":"extra"},`, 1),
		"duplicate-tool":      strings.Replace(base.body, `],"stop_reason"`, `,{"type":"tool_use","id":"two","name":"relay_canary_noop","input":`+args+`}],"stop_reason"`, 1),
		"extra-argument":      strings.Replace(base.body, `"nonce":"`+nonce+`"`, `"nonce":"`+nonce+`","command":"none"`, 1),
		"duplicate-nonce-key": strings.Replace(base.body, `"nonce":"`+nonce+`"`, `"nonce":"wrong","nonce":"`+nonce+`"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			check := newCanaryCheck(base.endpoint, nonce, model.CanaryManual, 0)
			decoder, _ := protocol.NewDecoderWithPayloadSink(protocol.DecoderSpec{Endpoint: base.endpoint, Protocol: base.proto}, protocol.WireJSON, 256<<10, 1<<20, check.observe)
			if _, err := decoder.Feed([]byte(body)); err != nil {
				t.Fatal(err)
			}
			if _, err := decoder.Finish(); err != nil {
				t.Fatal(err)
			}
			result := check.finalize(model.ProbeExecution{ID: "synthetic-canary", SentAtMS: 1, Success: true, NormalEndSeen: true})
			if result.Verdict != "violation" {
				t.Fatalf("constraint violation accepted: %+v", result)
			}
		})
	}
}

func TestCanaryPayloadRetainsOnlyBoundedToolDataAfterViolation(t *testing.T) {
	check := newCanaryCheck(model.EndpointMessages, "00112233445566778899aabbccddeeff", model.CanaryManual, 0)
	check.setName(strings.Repeat("n", 256<<10), false)
	check.setArgs(strings.Repeat("a", 256<<10), true)
	if !check.violation || len(check.name) > len(model.CanaryTool) || len(check.args) > 8192 {
		t.Fatalf("unbounded retained diagnostic data: name=%d args=%d", len(check.name), len(check.args))
	}
}

func TestCanaryChatRejectsADeclaredNonFunctionTool(t *testing.T) {
	nonce := "00112233445566778899aabbccddeeff"
	check := newCanaryCheck(model.EndpointChatCompletions, nonce, model.CanaryManual, 0)
	decoder, _ := protocol.NewDecoderWithPayloadSink(protocol.DecoderSpec{Endpoint: model.EndpointChatCompletions, Protocol: model.ProtoOpenAIChat}, protocol.WireJSON, 256<<10, 1<<20, check.observe)
	body := `{"choices":[{"message":{"tool_calls":[{"type":"command","function":{"name":"relay_canary_noop","arguments":"{\"nonce\":\"` + nonce + `\"}"}}]},"finish_reason":"tool_calls"}]}`
	if _, err := decoder.Feed([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Finish(); err != nil {
		t.Fatal(err)
	}
	result := check.finalize(model.ProbeExecution{ID: "synthetic-canary", SentAtMS: 1, Success: true, NormalEndSeen: true})
	if result.Verdict != "violation" {
		t.Fatalf("non-function tool passed strict Canary: %+v", result)
	}
}
