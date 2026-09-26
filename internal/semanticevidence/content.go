package semanticevidence

import (
	"bytes"
	"encoding/json"
)

// AnthropicContentSemantic 报告 Anthropic content 块数组是否携带非空模型输出。
//
// 覆盖非流式 message 正文：content:[{type,text|thinking|input}]。
// 空数组、空字符串、以及无法解析的形状都返回 false。
// 真实流量 HasSemanticEvidence 与探活 Decoder 必须调用本函数，避免各写一份比较。
func AnthropicContentSemantic(raw json.RawMessage) (kind string, ok bool) {
	var blocks []map[string]json.RawMessage
	if json.Unmarshal(raw, &blocks) != nil {
		return "", false
	}
	for _, block := range blocks {
		switch stringField(block, "type") {
		case "text":
			if nonEmptyString(block["text"]) {
				return "text", true
			}
		case "thinking":
			if nonEmptyString(block["thinking"]) {
				return "thinking", true
			}
		case "tool_use", "input_json":
			if nonEmptyJSONValue(block["input"]) {
				return "tool", true
			}
		}
	}
	return "", false
}

// ResponsesOutputSemantic 报告 Responses output[] 是否携带非空文本 / 拒答 / 参数。
//
// 覆盖非流式响应：output[].content[].text|refusal，以及 item.arguments。
// 真实流量 HasSemanticEvidence 与探活 Decoder 必须调用本函数，避免各写一份比较。
func ResponsesOutputSemantic(raw json.RawMessage) (kind string, ok bool) {
	var items []map[string]json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return "", false
	}
	for _, item := range items {
		var content []map[string]json.RawMessage
		if json.Unmarshal(item["content"], &content) == nil {
			for _, part := range content {
				if nonEmptyString(part["text"]) {
					return "text", true
				}
				if nonEmptyString(part["refusal"]) {
					return "refusal", true
				}
			}
		}
		if nonEmptyString(item["arguments"]) {
			return "function_args", true
		}
	}
	return "", false
}

func stringField(object map[string]json.RawMessage, name string) string {
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

func nonEmptyString(raw json.RawMessage) bool {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false
	}
	var value string
	return json.Unmarshal(raw, &value) == nil && value != ""
}

func nonEmptyJSONValue(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	switch string(trimmed) {
	case "", "null", "false", `""`, "{}", "[]":
		return false
	}
	return true
}
