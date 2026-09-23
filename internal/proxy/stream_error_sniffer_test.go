package proxy

import (
	"bytes"
	"strings"
	"testing"
)

func TestStreamErrorSniffer_MidStreamAnthropicError(t *testing.T) {
	s := &streamErrorSniffer{}
	// 先正常内容，再协议错误 —— 健康侧必须认出（重试侧会判 payloadContent）。
	s.Feed([]byte("event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}` +
		"\n\n"))
	if s.Found() {
		t.Fatal("content delta must not be treated as protocol error")
	}
	s.Feed([]byte("event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\"}}\n\n"))
	if !s.Found() {
		t.Fatal("mid-stream event: error must be found")
	}
	if !IsStructuredErrorPayload(s.Sample(), "text/event-stream") {
		t.Fatalf("sample must classify as structured error, got %q", s.Sample())
	}
	// 重试判据仍是「内容优先」—— 健康嗅探不得改那条路径。
	full := "event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}` +
		"\n\n" +
		"event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\"}}\n\n"
	if got := classifyPayload([]byte(full), "text/event-stream"); got != payloadContent {
		t.Fatalf("retry path must stay content-first, got %v", got)
	}
}

func TestStreamErrorSniffer_OpenAIDataError(t *testing.T) {
	s := &streamErrorSniffer{}
	s.Feed([]byte(`data: {"choices":[{"delta":{"content":"ok"}}]}` + "\n\n"))
	s.Feed([]byte(`data: {"error":{"message":"insufficient quota","type":"insufficient_quota"}}` + "\n\n"))
	if !s.Found() {
		t.Fatal("OpenAI-style data error after content must be found")
	}
	if !IsStructuredErrorPayload(s.Sample(), "text/event-stream") {
		t.Fatalf("sample not structured error: %q", s.Sample())
	}
}

func TestStreamErrorSniffer_TextContainingErrorIsOK(t *testing.T) {
	s := &streamErrorSniffer{}
	// 正文恰好是 error 这个词 —— 子串匹配会假阳性。
	chunk := "event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,` +
		`"delta":{"type":"text_delta","text":"error"}}` + "\n\n"
	s.Feed([]byte(chunk))
	s.Feed([]byte("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"))
	if s.Found() {
		t.Fatalf("text delta spelling \"error\" must not be protocol error, sample=%q", s.Sample())
	}
}

func TestStreamErrorSniffer_AcrossChunkBoundary(t *testing.T) {
	s := &streamErrorSniffer{}
	frame := "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"server_error\"}}\n\n"
	// 故意切在 "event" 与 ": error" 之间、再切在 data JSON 中间。
	s.Feed([]byte(frame[:5]))
	s.Feed([]byte(frame[5:20]))
	s.Feed([]byte(frame[20:]))
	if !s.Found() {
		t.Fatal("error event split across chunks must still be found")
	}
}

func TestStreamErrorSniffer_IgnoresCommentAndPing(t *testing.T) {
	s := &streamErrorSniffer{}
	s.Feed([]byte(": keepalive\n\n"))
	s.Feed([]byte("event: ping\ndata: {}\n\n"))
	s.Feed([]byte("event: message_start\ndata: {\"type\":\"message_start\"}\n\n"))
	if s.Found() {
		t.Fatal("ping/message_start must not be protocol error")
	}
}

func TestStreamErrorSniffer_DropsOverlongLine(t *testing.T) {
	s := &streamErrorSniffer{}
	over := []byte("data: " + strings.Repeat("x", maxErrBodyCapture+10))
	s.Feed(over)
	if len(s.lineBuf) > maxErrBodyCapture {
		t.Fatalf("lineBuf must not retain past maxErrBodyCapture, got %d", len(s.lineBuf))
	}
	s.Feed([]byte("\n"))
	if len(s.lineBuf) != 0 {
		t.Fatalf("after overlong resync, lineBuf must be empty, got %d", len(s.lineBuf))
	}
	// 超长行被丢弃；随后的真错误仍应能识别。
	s.Feed([]byte("event: error\ndata: {\"type\":\"error\"}\n\n"))
	if !s.Found() {
		t.Fatal("after dropping overlong line, later error event must still match")
	}
}

func TestStreamErrorSniffer_OverlongLineDoesNotRetainTail(t *testing.T) {
	s := &streamErrorSniffer{}
	// 单 chunk 内带换行的超长行：不得为分类保留尾部，也不得把超限 data 当成错误。
	line := "data: {\"error\":{\"message\":\"" + strings.Repeat("z", maxErrBodyCapture) + "\"}}\n"
	chunk := []byte(line)
	orig := append([]byte(nil), chunk...)
	s.Feed(chunk)
	if !bytes.Equal(chunk, orig) {
		t.Fatal("Feed must not mutate caller chunk (client bytes already flushed)")
	}
	if len(s.lineBuf) > maxErrBodyCapture {
		t.Fatalf("lineBuf retained %d bytes past cap", len(s.lineBuf))
	}
	if s.Found() {
		t.Fatalf("over-cap error-shaped line must fail closed, sample=%q", s.Sample())
	}
	if got := s.Sample(); got != nil {
		t.Fatalf("Sample must stay nil on over-cap drop, got %q", got)
	}
}

func TestStreamErrorSniffer_NormalErrorUnderCap(t *testing.T) {
	s := &streamErrorSniffer{}
	frame := []byte("event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\"}}\n\n")
	if len(frame) > maxErrBodyCapture {
		t.Fatalf("test frame must be under cap, got %d", len(frame))
	}
	orig := append([]byte(nil), frame...)
	s.Feed(frame)
	if !bytes.Equal(frame, orig) {
		t.Fatal("Feed must not mutate caller chunk")
	}
	if !s.Found() {
		t.Fatal("normal-sized event: error under cap must set sample")
	}
	if len(s.Sample()) == 0 || len(s.Sample()) > maxErrBodyCapture {
		t.Fatalf("sample length %d outside (0, maxErrBodyCapture]", len(s.Sample()))
	}
	if !IsStructuredErrorPayload(s.Sample(), "text/event-stream") {
		t.Fatalf("sample must classify as structured error, got %q", s.Sample())
	}
}
