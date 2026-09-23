package semanticevidence

import (
	"encoding/json"
	"testing"
)

func TestPositiveOutputUsage(t *testing.T) {
	mustObject := func(raw string) map[string]json.RawMessage {
		t.Helper()
		var top map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &top); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return top
	}

	if !PositiveOutputUsage(mustObject(`{"usage":{"output_tokens":3}}`)) {
		t.Fatal("positive output_tokens must count")
	}
	if !PositiveOutputUsage(mustObject(`{"usage":{"completion_tokens":2}}`)) {
		t.Fatal("positive completion_tokens must count")
	}
	if !PositiveOutputUsage(mustObject(`{"response":{"usage":{"output_tokens":1}}}`)) {
		t.Fatal("nested response.usage must count")
	}
	if PositiveOutputUsage(mustObject(`{"usage":{"output_tokens":0}}`)) {
		t.Fatal("output_tokens:0 must not count")
	}
	if PositiveOutputUsage(mustObject(`{"usage":{"input_tokens":9}}`)) {
		t.Fatal("input_tokens alone must not count")
	}
	if PositiveOutputUsage(mustObject(`{"usage":{"prompt_tokens":8,"completion_tokens":0}}`)) {
		t.Fatal("prompt_tokens with zero completion must not count")
	}
	if PositiveOutputUsage(mustObject(`{"usage":{"output_tokens":-1}}`)) {
		t.Fatal("negative output_tokens must not count")
	}
}
