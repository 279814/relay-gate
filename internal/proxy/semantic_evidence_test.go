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

	usageOnly := []byte(`{"type":"message_delta","usage":{"output_tokens":3}}`)
	if HasSemanticEvidence(usageOnly, "application/json") {
		t.Fatal("positive usage alone must not count as semantic (align with probe Decoder)")
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
