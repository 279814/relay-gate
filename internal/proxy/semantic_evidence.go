package proxy

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/279814/relay-gate/internal/semanticevidence"
)

// HasSemanticEvidence 报告一段响应前缀/事件是否含 §8.8 判活证据。
//
// §8.8 判活：非空 text/thinking/tool/refusal delta、正数 output usage、
// 或非流式非空模型输出。message_start、空 delta、output_tokens:0、HTML
// 都不算。拿不准（半截 JSON）返回 false —— piggyback 假阳性比漏掉一次更糟。
func HasSemanticEvidence(prefix []byte, contentType string) bool {
	prefix = bytes.TrimSpace(prefix)
	if len(prefix) == 0 {
		return false
	}
	if isSSEContentType(contentType) || looksLikeSSE(prefix) {
		return ssePrefixHasSemanticEvidence(prefix)
	}
	if isNDJSONContentType(contentType) {
		return ndjsonHasSemanticEvidence(prefix)
	}
	return jsonBytesHaveSemanticEvidence(prefix)
}

func isNDJSONContentType(ct string) bool {
	lower := strings.ToLower(ct)
	return strings.Contains(lower, "ndjson") || strings.Contains(lower, "jsonl")
}

func looksLikeSSE(prefix []byte) bool {
	return bytes.HasPrefix(prefix, []byte("event:")) ||
		bytes.HasPrefix(prefix, []byte("data:")) ||
		bytes.HasPrefix(prefix, []byte(":"))
}

func ssePrefixHasSemanticEvidence(prefix []byte) bool {
	for _, raw := range bytes.Split(prefix, []byte("\n")) {
		line := bytes.TrimRight(raw, "\r")
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		data := bytes.TrimSpace(line[len("data:"):])
		if jsonBytesHaveSemanticEvidence(data) {
			return true
		}
	}
	return false
}

func ndjsonHasSemanticEvidence(prefix []byte) bool {
	for _, raw := range bytes.Split(prefix, []byte("\n")) {
		line := bytes.TrimSpace(bytes.TrimRight(raw, "\r"))
		if len(line) == 0 {
			continue
		}
		if jsonBytesHaveSemanticEvidence(line) {
			return true
		}
	}
	return false
}

func jsonBytesHaveSemanticEvidence(b []byte) bool {
	b = bytes.TrimSpace(b)
	if !looksLikeJSONObject(b) {
		return false
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return false
	}
	return objectHasSemanticEvidence(top)
}

func objectHasSemanticEvidence(top map[string]json.RawMessage) bool {
	// 与 classifyJSONObject 同向：顶层结构化 error 不得因伴生 text/content/
	// choices/usage 被当成语义成功（§6.8 / §8.8 / §8.12）。
	if v, ok := top["error"]; ok && !isJSONNull(v) {
		return false
	}
	name := jsonStringField(top, "type")
	if name == "error" {
		return false
	}

	// Anthropic streaming deltas.
	if name == "content_block_delta" {
		return anthropicDeltaSemantic(top["delta"])
	}

	// OpenAI Responses streaming deltas.
	switch name {
	case "response.output_text.delta",
		"response.reasoning_summary_text.delta",
		"response.refusal.delta",
		"response.function_call_arguments.delta":
		return jsonNonEmptyString(top["delta"])
	}

	// OpenAI Chat streaming / non-streaming.
	if _, ok := top["choices"]; ok {
		if chatChoicesSemantic(top["choices"]) {
			return true
		}
		// choices 可为空壳，但仍可能带正数 usage（探活 Decoder 同路径）。
		if semanticevidence.PositiveOutputUsage(top) {
			return true
		}
		return false
	}

	// Anthropic non-stream message body.
	if name == "message" || name == "" {
		if _, ok := semanticevidence.AnthropicContentSemantic(top["content"]); ok {
			return true
		}
	}

	// OpenAI Responses non-stream: output[].content[].text
	if name == "response" || name == "" {
		if _, ok := semanticevidence.ResponsesOutputSemantic(top["output"]); ok {
			return true
		}
	}

	// §8.8：正数 output usage 单独即判活（与探活 Decoder 共用 semanticevidence）。
	if semanticevidence.PositiveOutputUsage(top) {
		return true
	}

	return false
}

func anthropicDeltaSemantic(raw json.RawMessage) bool {
	var delta map[string]json.RawMessage
	if json.Unmarshal(raw, &delta) != nil {
		return false
	}
	switch jsonStringField(delta, "type") {
	case "text_delta":
		return jsonNonEmptyString(delta["text"])
	case "thinking_delta":
		return jsonNonEmptyString(delta["thinking"])
	case "input_json_delta", "tool_use_delta":
		return jsonNonEmptyString(delta["partial_json"])
	}
	return false
}

func chatChoicesSemantic(raw json.RawMessage) bool {
	var choices []map[string]json.RawMessage
	if json.Unmarshal(raw, &choices) != nil {
		return false
	}
	for _, choice := range choices {
		var delta map[string]json.RawMessage
		_ = json.Unmarshal(choice["delta"], &delta)
		var message map[string]json.RawMessage
		_ = json.Unmarshal(choice["message"], &message)
		for _, field := range []string{"content", "reasoning_content", "refusal"} {
			value := delta[field]
			if len(value) == 0 {
				value = message[field]
			}
			if jsonNonEmptyString(value) {
				return true
			}
		}
		if chatToolArgsSemantic(delta["tool_calls"]) || chatToolArgsSemantic(message["tool_calls"]) {
			return true
		}
		if chatCallArgsSemantic(delta["function_call"]) || chatCallArgsSemantic(message["function_call"]) {
			return true
		}
	}
	return false
}

func chatToolArgsSemantic(raw json.RawMessage) bool {
	var calls []map[string]json.RawMessage
	if json.Unmarshal(raw, &calls) != nil {
		return false
	}
	for _, call := range calls {
		if chatCallArgsSemantic(call["function"]) {
			return true
		}
	}
	return false
}

func chatCallArgsSemantic(raw json.RawMessage) bool {
	var call map[string]json.RawMessage
	if json.Unmarshal(raw, &call) != nil {
		return false
	}
	return jsonNonEmptyString(call["arguments"])
}

func jsonStringField(object map[string]json.RawMessage, name string) string {
	raw, ok := object[name]
	if !ok {
		return ""
	}
	var value string
	if json.Unmarshal(raw, &value) == nil {
		return value
	}
	return ""
}

func jsonNonEmptyString(raw json.RawMessage) bool {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false
	}
	var value string
	return json.Unmarshal(raw, &value) == nil && value != ""
}

// streamSemanticSniffer 在 2xx 响应上增量嗅探 §8.8 语义证据。
//
// Feed 必须放在客户端 flush 之后，与 streamErrorSniffer 同向：不推迟写出、
// 不缓冲整段流。行/前缀上限与 maxErrBodyCapture 一致。
type streamSemanticSniffer struct {
	sse     bool
	lineBuf []byte
	jsonBuf []byte
	seen    bool
}

func newStreamSemanticSniffer(contentType string) *streamSemanticSniffer {
	return &streamSemanticSniffer{
		sse: isSSEContentType(contentType) || isNDJSONContentType(contentType),
	}
}

// Feed 吞下一块已写出的响应字节。找到语义证据后不再处理。
func (s *streamSemanticSniffer) Feed(chunk []byte, contentType string) {
	if s == nil || s.seen || len(chunk) == 0 {
		return
	}
	if !s.sse && (isSSEContentType(contentType) || isNDJSONContentType(contentType) ||
		(len(s.jsonBuf) == 0 && looksLikeSSE(chunk))) {
		s.sse = true
	}
	if s.sse {
		s.feedSSE(chunk, contentType)
		return
	}
	s.feedJSON(chunk, contentType)
}

func (s *streamSemanticSniffer) feedSSE(chunk []byte, contentType string) {
	s.lineBuf = append(s.lineBuf, chunk...)
	for {
		i := bytes.IndexByte(s.lineBuf, '\n')
		if i < 0 {
			if len(s.lineBuf) > maxErrBodyCapture {
				s.lineBuf = s.lineBuf[:0]
			}
			return
		}
		if i > maxErrBodyCapture {
			s.lineBuf = s.lineBuf[i+1:]
			continue
		}
		line := s.lineBuf[:i]
		s.lineBuf = s.lineBuf[i+1:]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if isNDJSONContentType(contentType) {
			if jsonBytesHaveSemanticEvidence(bytes.TrimSpace(line)) {
				s.seen = true
				s.lineBuf = nil
				return
			}
			continue
		}
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		data := bytes.TrimSpace(line[len("data:"):])
		if jsonBytesHaveSemanticEvidence(data) {
			s.seen = true
			s.lineBuf = nil
			return
		}
	}
}

func (s *streamSemanticSniffer) feedJSON(chunk []byte, contentType string) {
	room := maxErrBodyCapture - len(s.jsonBuf)
	if room <= 0 {
		return
	}
	if len(chunk) > room {
		chunk = chunk[:room]
	}
	s.jsonBuf = append(s.jsonBuf, chunk...)
	if HasSemanticEvidence(s.jsonBuf, contentType) {
		s.seen = true
		s.jsonBuf = nil
	}
}

// Seen 报告是否已确认语义证据。
func (s *streamSemanticSniffer) Seen() bool {
	return s != nil && s.seen
}
