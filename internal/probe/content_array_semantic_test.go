package probe

import (
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

// 形状与 proxy/handler_test.go 里非流式 Anthropic 成功正文一致：
// content 是块数组，非空 text 必须置 EventSemantic —— 否则探活只会看到
// metadata + body_complete，最终以「无语义」超时。
func TestNonStreamAnthropicContentArrayIsSemantic(t *testing.T) {
	wire := `{"type":"message","role":"assistant","content":[{"type":"text","text":"ok"}]}`
	events, err := decodeChunks(t, eventSpec(model.EndpointMessages, model.ProtoAnthropic), WireJSON, wire)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	found := false
	for _, event := range events {
		if event.Semantic && event.Kind == EventSemantic && event.SemanticKind == "text" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("non-empty Anthropic content array text must be EventSemantic; got %#v", events)
	}
}

// Responses 非流式正文把 text 放在 output[].content[]；既有 walker
// （原 proxy/semantic_evidence.responsesOutputSemantic）已知如何遍历，
// 探活 Decoder 不得把数组里的非空 text 当成无语义。
func TestNonStreamResponsesOutputPartsAreSemantic(t *testing.T) {
	wire := `{"id":"resp_fixture","output":[{"type":"message","content":[{"type":"output_text","text":"hi"}]}]}`
	events, err := decodeChunks(t, eventSpec(model.EndpointResponses, model.ProtoOpenAIResponses), WireJSON, wire)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	found := false
	for _, event := range events {
		if event.Semantic && event.Kind == EventSemantic && event.SemanticKind == "text" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("non-empty Responses output part text must be EventSemantic; got %#v", events)
	}
}
