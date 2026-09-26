package semanticevidence

import (
	"encoding/json"
	"testing"
)

func TestAnthropicContentSemantic(t *testing.T) {
	kind, ok := AnthropicContentSemantic(json.RawMessage(`[{"type":"text","text":"ok"}]`))
	if !ok || kind != "text" {
		t.Fatalf("got kind=%q ok=%v, want text", kind, ok)
	}
	if _, ok := AnthropicContentSemantic(json.RawMessage(`[]`)); ok {
		t.Fatal("empty content array must not count")
	}
	if _, ok := AnthropicContentSemantic(json.RawMessage(`[{"type":"text","text":""}]`)); ok {
		t.Fatal("empty text must not count")
	}
	if _, ok := AnthropicContentSemantic(json.RawMessage(`"plain"`)); ok {
		t.Fatal("string content must not count as block array")
	}
}

func TestResponsesOutputSemantic(t *testing.T) {
	kind, ok := ResponsesOutputSemantic(json.RawMessage(
		`[{"content":[{"type":"output_text","text":"hi"}]}]`))
	if !ok || kind != "text" {
		t.Fatalf("got kind=%q ok=%v, want text", kind, ok)
	}
	if _, ok := ResponsesOutputSemantic(json.RawMessage(`[]`)); ok {
		t.Fatal("empty output must not count")
	}
	if _, ok := ResponsesOutputSemantic(json.RawMessage(
		`[{"content":[{"type":"output_text","text":""}]}]`)); ok {
		t.Fatal("empty part text must not count")
	}
}
