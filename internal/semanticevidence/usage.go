package semanticevidence

import "encoding/json"

// PositiveOutputUsage 报告 JSON 对象是否携带 §8.8 正数 output usage。
//
// 路径与探活 Decoder 一致：顶层 usage，以及 Responses response.completed
// 嵌套的 response.usage。正数 completion_tokens / output_tokens 才算；
// 0、缺失、负数、以及仅 input_tokens / prompt_tokens 都不算。
//
// 真实流量 HasSemanticEvidence 与探活 Decoder 必须调用本函数，避免各写一份比较。
func PositiveOutputUsage(top map[string]json.RawMessage) bool {
	if usageHasPositiveOutput(top["usage"]) {
		return true
	}
	if raw, ok := top["response"]; ok {
		var body map[string]json.RawMessage
		if json.Unmarshal(raw, &body) == nil && usageHasPositiveOutput(body["usage"]) {
			return true
		}
	}
	return false
}

func usageHasPositiveOutput(raw json.RawMessage) bool {
	var usage map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &usage) != nil {
		return false
	}
	if n := jsonTokenCount(usage, "completion_tokens"); n > 0 {
		return true
	}
	return jsonTokenCount(usage, "output_tokens") > 0
}

func jsonTokenCount(object map[string]json.RawMessage, name string) int64 {
	raw, ok := object[name]
	if !ok {
		return 0
	}
	var number json.Number
	if json.Unmarshal(raw, &number) != nil {
		return 0
	}
	value, err := number.Int64()
	if err != nil || value < 0 {
		return 0
	}
	return value
}
