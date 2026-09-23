package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHasSemanticEvidence_TextDeltaAndHTML(t *testing.T) {
	sseText := "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"2\"}}\n\n"
	if !HasSemanticEvidence([]byte(sseText), "text/event-stream") {
		t.Fatal("non-empty text delta must be semantic evidence")
	}

	// 正文里拼写 error 的正常 delta 仍是语义证据，不得当失败。
	sseErrorWord := "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"fix spelling\"}}\n\n"
	if !HasSemanticEvidence([]byte(sseErrorWord), "text/event-stream") {
		t.Fatal("text containing the word error must still count as semantic")
	}

	html := []byte("<!DOCTYPE html><html><body>502 Bad Gateway</body></html>")
	if HasSemanticEvidence(html, "text/html") {
		t.Fatal("HTML 200 must not count as semantic evidence")
	}

	chat := []byte(`{"choices":[{"message":{"content":"hello"}}]}`)
	if !HasSemanticEvidence(chat, "application/json") {
		t.Fatal("non-stream non-empty model output must be semantic")
	}

	// 顶层结构化 error 即便带 content/choices/text 伴生字段，也不能当语义成功。
	errWithContent := []byte(`{"error":{"message":"boom"},"content":[{"type":"text","text":"hi"}]}`)
	if HasSemanticEvidence(errWithContent, "application/json") {
		t.Fatal("structured error with content text must not count as semantic")
	}
	errWithChoices := []byte(`{"error":{"message":"boom"},"choices":[{"message":{"content":"hi"}}]}`)
	if HasSemanticEvidence(errWithChoices, "application/json") {
		t.Fatal("structured error with choices text must not count as semantic")
	}
	sseErrWithContent := "data: {\"error\":{\"message\":\"boom\"},\"content\":[{\"type\":\"text\",\"text\":\"hi\"}]}\n\n"
	if HasSemanticEvidence([]byte(sseErrWithContent), "text/event-stream") {
		t.Fatal("SSE structured error with content text must not count as semantic")
	}
}

func TestHasSemanticEvidence_PositiveUsageAndRefusal(t *testing.T) {
	// §8.8：正数 output usage 单独即判活。
	usageOnly := []byte(`{"type":"message_delta","usage":{"output_tokens":3}}`)
	if !HasSemanticEvidence(usageOnly, "application/json") {
		t.Fatal("positive output_tokens alone must set semantic evidence")
	}
	if HasSemanticEvidence([]byte(`{"type":"message_delta","usage":{"output_tokens":0}}`), "application/json") {
		t.Fatal("output_tokens:0 must not count as semantic")
	}
	if HasSemanticEvidence([]byte(`{"usage":{"completion_tokens":0}}`), "application/json") {
		t.Fatal("completion_tokens:0 must not count as semantic")
	}
	if HasSemanticEvidence([]byte(`{"usage":{"input_tokens":9}}`), "application/json") {
		t.Fatal("input_tokens alone must not count as semantic")
	}
	if HasSemanticEvidence([]byte(`{"usage":{"prompt_tokens":8,"completion_tokens":0}}`), "application/json") {
		t.Fatal("prompt_tokens with zero completion must not count as semantic")
	}
	if HasSemanticEvidence([]byte(`{"usage":{"output_tokens":-1}}`), "application/json") {
		t.Fatal("negative output_tokens must not count as positive")
	}
	chatUsage := []byte(`{"choices":[],"usage":{"completion_tokens":3}}`)
	if !HasSemanticEvidence(chatUsage, "application/json") {
		t.Fatal("positive completion_tokens on empty choices must be semantic")
	}
	responsesUsage := []byte(`{"type":"response.completed","response":{"usage":{"output_tokens":2}}}`)
	if !HasSemanticEvidence(responsesUsage, "application/json") {
		t.Fatal("nested response.usage output_tokens>0 must be semantic")
	}
	sseUsage := "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":1}}\n\n"
	if !HasSemanticEvidence([]byte(sseUsage), "text/event-stream") {
		t.Fatal("SSE positive usage alone must be semantic")
	}

	// §8.8：非空 refusal delta 单独即判活。
	refusal := []byte(`{"type":"response.refusal.delta","delta":"no"}`)
	if !HasSemanticEvidence(refusal, "application/json") {
		t.Fatal("non-empty refusal delta must be semantic")
	}
	sseRefusal := "data: {\"type\":\"response.refusal.delta\",\"delta\":\"no\"}\n\n"
	if !HasSemanticEvidence([]byte(sseRefusal), "text/event-stream") {
		t.Fatal("SSE non-empty refusal delta must be semantic")
	}
	if HasSemanticEvidence([]byte(`{"type":"response.refusal.delta","delta":""}`), "application/json") {
		t.Fatal("empty refusal delta must not count")
	}
	chatRefusal := []byte(`{"choices":[{"delta":{"refusal":"no"}}]}`)
	if !HasSemanticEvidence(chatRefusal, "application/json") {
		t.Fatal("chat non-empty refusal field must be semantic")
	}

	// 结构化 error 优先：即便伴生正数 usage 也不能当语义成功。
	errWithUsage := []byte(`{"error":{"message":"boom"},"usage":{"output_tokens":9}}`)
	if HasSemanticEvidence(errWithUsage, "application/json") {
		t.Fatal("structured error with usage must not count as semantic")
	}
}

func TestHasSemanticEvidence_ThinkingAndToolDeltas(t *testing.T) {
	thinking := "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"hmm\"}}\n\n"
	if !HasSemanticEvidence([]byte(thinking), "text/event-stream") {
		t.Fatal("non-empty thinking delta must be semantic evidence")
	}
	tool := "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"a\\\":1}\"}}\n\n"
	if !HasSemanticEvidence([]byte(tool), "text/event-stream") {
		t.Fatal("non-empty tool/input JSON delta must be semantic evidence")
	}
	// 正文仅含字母 error 仍是语义证据，不得当失败。
	withErrorWord := "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"error\"}}\n\n"
	if !HasSemanticEvidence([]byte(withErrorWord), "text/event-stream") {
		t.Fatal(`text delta containing "error" must still count as semantic`)
	}
}

func TestCommit_StructuredErrorWithTextHasNoSemanticSeen(t *testing.T) {
	body := `{"error":{"message":"boom"},"content":[{"type":"text","text":"hi"}]}`
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(body))
	}))
	defer up.Close()

	f := testForwarder(t, fastTimeouts())
	at := f.Send(context.Background(), "POST", up.URL, http.Header{}, []byte("{}"))
	if at.Failed() {
		t.Fatalf("Send: %v", at.Result().Err)
	}
	_ = at.Peek()
	rec := httptest.NewRecorder()
	res := at.Commit(rec)
	if res.BytesWritten == 0 {
		t.Fatal("error body should still reach the client")
	}
	if !strings.Contains(rec.Body.String(), `"error"`) {
		t.Fatalf("client bytes changed or lost: %q", rec.Body.String())
	}
	if res.SemanticSeen {
		t.Fatal("structured error with text field must not set SemanticSeen")
	}
}

func TestCommit_SetsSemanticSeenOnPositiveUsage(t *testing.T) {
	body := `{"type":"message_delta","usage":{"output_tokens":3}}`
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(body))
	}))
	defer up.Close()

	f := testForwarder(t, fastTimeouts())
	at := f.Send(context.Background(), "POST", up.URL, http.Header{}, []byte("{}"))
	if at.Failed() {
		t.Fatalf("Send: %v", at.Result().Err)
	}
	_ = at.Peek()
	rec := httptest.NewRecorder()
	res := at.Commit(rec)
	if !res.SemanticSeen {
		t.Fatal("Commit must set SemanticSeen on positive output_tokens alone")
	}
	if !strings.Contains(rec.Body.String(), `"output_tokens":3`) {
		t.Fatalf("client bytes changed or lost: %q", rec.Body.String())
	}
}

func TestCommit_SetsSemanticSeenOnTextDelta(t *testing.T) {
	body := "event: message_start\ndata: {\"type\":\"message_start\"}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(body))
	}))
	defer up.Close()

	f := testForwarder(t, fastTimeouts())
	at := f.Send(context.Background(), "POST", up.URL, http.Header{}, []byte("{}"))
	if at.Failed() {
		t.Fatalf("Send: %v", at.Result().Err)
	}
	_ = at.Peek()
	rec := httptest.NewRecorder()
	res := at.Commit(rec)
	if !res.SemanticSeen {
		t.Fatal("Commit must set SemanticSeen on non-empty text delta")
	}
	if !strings.Contains(rec.Body.String(), `"text":"hi"`) {
		t.Fatalf("client bytes changed or lost delta: %q", rec.Body.String())
	}
}

func TestCommit_HTML200HasNoSemanticSeen(t *testing.T) {
	html := "<!DOCTYPE html><html><body>ok</body></html>"
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(html))
	}))
	defer up.Close()

	f := testForwarder(t, fastTimeouts())
	at := f.Send(context.Background(), "GET", up.URL, http.Header{}, nil)
	if at.Failed() {
		t.Fatalf("Send: %v", at.Result().Err)
	}
	_ = at.Peek()
	res := at.Commit(httptest.NewRecorder())
	if res.BytesWritten == 0 {
		t.Fatal("HTML body should reach the client")
	}
	if res.SemanticSeen {
		t.Fatal("HTML 200 must not set SemanticSeen")
	}
}
