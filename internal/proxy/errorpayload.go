package proxy

import (
	"bytes"
	"encoding/json"
	"strings"
)

// 「200 但流内立刻 error」的识别（§3.5 列为可重试的一类）。
//
// ── 判据必须保守，因为两个方向的代价极不对称 ──
//
// 假阳性（把一个好响应当成错误）：丢掉一个已经生成好的答案，换个站重发一遍。
// 用户多等一轮，token 白花一份，而且**第二次未必更好**。最糟的是它不报错 ——
// 表现为「偶尔慢一倍」，没人会想到是网关自己丢的。
//
// 假阴性（漏判一个错误响应）：把上游的错误原样传给客户端。这正是 M5 的现状，
// 也就是说漏判只是没有改进，不是引入退化。
//
// 所以规则是「**证据确凿才算错误**，拿不准一律放行」。
//
// ── 为什么不能用子串匹配 ──
//
// probe/sse.go 的 isErrorPayload 用的是 `bytes.Contains(data, "\"error\"")`。
// 那在**探活**里是安全的：探活的 prompt 是我们自己定的 `1+1=?`，模型不会
// 回一段包含 error 的内容。但真实流量的内容是用户的对话 —— 而流式响应是
// 逐 token 到达的，模型解释报错时，「error」单独成一个 chunk 完全正常，
// 于是 `"text":"error"` 里就出现了未转义的 `"error"`。
// 子串匹配会把这种响应判成错误，然后丢掉重发，再丢掉，直到重试次数耗尽。
//
// 所以这里做**结构化**判定：只认顶层的 error 键，不认内容里的任何字样。
// content_block_delta 的顶层键是 type/index/delta，用户文本嵌在 delta.text
// 里，结构上够不到顶层 —— 这是子串匹配做不到的区分。

// errorPayloadVerdict 是对已 peek 到的响应前缀的判断。
type errorPayloadVerdict int

const (
	// payloadUndecided 前缀里还看不出结论。一律按「不是错误」处理。
	payloadUndecided errorPayloadVerdict = iota
	// payloadError 确认是错误载荷，可以换站重试。
	payloadError
	// payloadContent 确认已经在生成内容，绝不重试。
	payloadContent
)

// classifyPayload 判断一段响应前缀是不是错误载荷。
//
// prefix 是**已经读到的**字节，可能是被截断的半截 JSON —— 解析失败时
// 返回 payloadUndecided（放行），不做任何猜测。
func classifyPayload(prefix []byte, contentType string) errorPayloadVerdict {
	if len(bytes.TrimSpace(prefix)) == 0 {
		return payloadUndecided
	}
	if isSSEContentType(contentType) {
		return classifySSEPrefix(prefix)
	}
	return classifyJSONObject(prefix)
}

func isSSEContentType(ct string) bool {
	return strings.Contains(strings.ToLower(ct), "text/event-stream")
}

// classifySSEPrefix 按**事件顺序**扫描，取第一个有结论的事件。
//
// 顺序很重要：一个正常的流是 message_start → content_block_start → delta…，
// 而错误流在最前面就是 error。只要先看到内容增量就立刻收手 —— 后面再出现
// 什么都与「要不要重试」无关了，因为那时字节已经在往客户端写。
func classifySSEPrefix(prefix []byte) errorPayloadVerdict {
	var curEvent []byte
	for _, raw := range bytes.Split(prefix, []byte("\n")) {
		line := bytes.TrimRight(raw, "\r")
		switch {
		case len(bytes.TrimSpace(line)) == 0:
			curEvent = nil // 事件边界，event 名的作用域到此为止

		case bytes.HasPrefix(line, []byte("event:")):
			curEvent = bytes.TrimSpace(line[len("event:"):])

		case bytes.HasPrefix(line, []byte("data:")):
			data := bytes.TrimSpace(line[len("data:"):])
			// `event: error` 是 Anthropic 的显式错误事件。这里认事件名，
			// 但仍要求 data 能解析 —— 只有事件名而 data 是半截的话，
			// 说明我们 peek 的边界切在中间，那就等下一轮，别急着下结论。
			if bytes.Equal(curEvent, []byte("error")) && looksLikeJSONObject(data) {
				return payloadError
			}
			if v := classifyJSONObject(data); v != payloadUndecided {
				return v
			}
		}
	}
	return payloadUndecided
}

// classifyJSONObject 对单个 JSON 对象做顶层判定。
//
// 三条规则，全部只看**顶层**：
//   - 顶层有非 null 的 error 键 → 错误
//   - 顶层 "type" == "error" → 错误
//   - 顶层是内容事件（delta / choices）→ 已在生成，绝不重试
//
// 解析不了就是 payloadUndecided。截断的半截 JSON 走的正是这条 —— 宁可
// 放行也不猜，猜错的代价是丢掉一个好答案。
func classifyJSONObject(b []byte) errorPayloadVerdict {
	b = bytes.TrimSpace(b)
	if !looksLikeJSONObject(b) {
		return payloadUndecided
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return payloadUndecided
	}

	if v, ok := top["error"]; ok && !isJSONNull(v) {
		return payloadError
	}
	if t, ok := top["type"]; ok && bytes.Equal(bytes.TrimSpace(t), []byte(`"error"`)) {
		return payloadError
	}

	// 内容事件：看到它就说明模型已经在生成，这次响应不该被丢掉。
	//
	// 只认顶层的事件类型名，不认内容本身 —— delta.text 里可以是任何东西，
	// 包括一段看起来像错误的 JSON（用户在问「这个报错怎么修」）。
	if t, ok := top["type"]; ok {
		var name string
		if json.Unmarshal(t, &name) == nil && isContentEventType(name) {
			return payloadContent
		}
	}
	// OpenAI Chat 的流式块没有 type 字段，靠 choices 识别。
	if _, ok := top["choices"]; ok {
		return payloadContent
	}
	return payloadUndecided
}

// isContentEventType 列举「模型正在产出内容」的事件名。
//
// 这份清单只用于**提前收手**（判定 payloadContent），漏一个的后果仅仅是
// 少一次提前退出，最终仍会因为 payloadUndecided 而放行。所以它不需要穷尽，
// 也不该为了穷尽而放宽成模糊匹配。
func isContentEventType(name string) bool {
	switch name {
	case "content_block_delta", "content_block_start", "message_delta",
		"response.output_text.delta", "response.reasoning_summary_text.delta":
		return true
	}
	return false
}

func looksLikeJSONObject(b []byte) bool {
	return len(b) > 0 && b[0] == '{'
}

func isJSONNull(v json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(v), []byte("null"))
}
