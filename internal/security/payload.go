package security

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/279814/relay-gate/internal/protocol"
)

func (r *scanRun) payload(view protocol.PayloadView) {
	if !r.available() {
		return
	}
	r.object(view.Object, "response", 0)
	// Unknown metadata cannot manufacture role/tool facts, but credentials in
	// metadata still deserve detection. Frame/health parsing remains shared.
	var value any
	if json.Unmarshal(view.Raw, &value) == nil {
		r.credentialsInValue(value, 0)
	}
}

func (r *scanRun) object(object map[string]json.RawMessage, path string, depth int) {
	if !r.available() {
		return
	}
	if depth > 16 {
		r.incomplete("structure_depth", true)
		return
	}
	path = r.indexedPath(object, path)
	var role, kind, name string
	_ = json.Unmarshal(object["role"], &role)
	_ = json.Unmarshal(object["type"], &kind)
	_ = json.Unmarshal(object["name"], &name)
	if role != "" && role != "assistant" && role != "tool" {
		severity := SeverityMedium
		if role == "system" || role == "developer" {
			severity = SeverityHigh
		}
		r.add(severity, "unexpected_role", "响应在协议角色位置声明异常角色", role)
	}
	if kind == "tool_use" || kind == "function_call" || kind == "custom_tool_call" {
		r.tool(name)
	}
	for _, field := range []string{"text", "output_text", "completion", "partial_json", "delta"} {
		var text string
		if json.Unmarshal(object[field], &text) == nil && text != "" {
			r.protocolText(path+"/"+field, text)
		}
	}
	if raw, ok := object["content"]; ok {
		var text string
		if json.Unmarshal(raw, &text) == nil {
			r.protocolText(path+"/content", text)
		} else {
			r.objects(raw, path+"/content", depth+1)
		}
	}
	for _, field := range []string{"delta", "message", "response", "item", "content_block"} {
		var child map[string]json.RawMessage
		if json.Unmarshal(object[field], &child) == nil && child != nil {
			r.object(child, path+"/"+field, depth+1)
		}
	}
	for _, field := range []string{"choices", "output"} {
		r.objects(object[field], path+"/"+field, depth+1)
	}
	var tools []map[string]json.RawMessage
	if json.Unmarshal(object["tool_calls"], &tools) == nil {
		for i, tool := range tools {
			toolPath := path + "/tool_arguments/" + strconv.Itoa(i)
			if _, indexed := tool["index"]; indexed {
				toolPath = r.indexedPath(tool, path+"/tool_arguments")
			}
			var function struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			}
			if json.Unmarshal(tool["function"], &function) == nil {
				if function.Name != "" {
					if strings.Contains(path, "/delta") {
						r.toolFragment(toolPath, function.Name)
					} else {
						r.tool(function.Name)
					}
				}
				if function.Arguments != "" {
					r.protocolText(toolPath, function.Arguments)
				}
			}
		}
	}
	var function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	}
	if json.Unmarshal(object["function_call"], &function) == nil {
		if function.Name != "" {
			if strings.Contains(path, "/delta") {
				r.toolFragment(path+"/function_call", function.Name)
			} else {
				r.tool(function.Name)
			}
		}
		if function.Arguments != "" {
			r.protocolText(path+"/function_call_arguments", function.Arguments)
		}
	}
}

func (r *scanRun) indexedPath(object map[string]json.RawMessage, path string) string {
	for _, field := range []string{"index", "output_index", "content_index"} {
		if raw, ok := object[field]; ok {
			var index int
			if json.Unmarshal(raw, &index) != nil || index < 0 || index >= 256 {
				r.incomplete("protocol_index_invalid", false)
			} else {
				path += "/" + field + ":" + strconv.Itoa(index)
			}
		}
	}
	return path
}

func (r *scanRun) toolFragment(channel, name string) {
	if !r.input.Context.ToolsKnown {
		r.incomplete("request_tool_context_unknown", false)
		return
	}
	if r.toolNames == nil {
		r.toolNames = map[string]string{}
	}
	previous, exists := r.toolNames[channel]
	if !exists {
		if len(r.toolNames) >= 16 {
			r.incomplete("tool_name_channels", true)
			return
		}
		r.toolOrder = append(r.toolOrder, channel)
	}
	if len(previous)+len(name) > 128 {
		r.incomplete("tool_name_limit", true)
		return
	}
	r.toolNames[channel] = previous + name
}

func (r *scanRun) objects(raw json.RawMessage, path string, depth int) {
	var items []map[string]json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return
	}
	for i, item := range items {
		if !r.available() {
			return
		}
		if i >= 256 {
			r.incomplete("structure_items", true)
			return
		}
		childPath := path + "/" + strconv.Itoa(i)
		if _, indexed := item["index"]; indexed {
			childPath = path
		}
		r.object(item, childPath, depth)
	}
}

func (r *scanRun) protocolText(channel, text string) {
	if text == "" {
		return
	}
	if r.textTails == nil {
		r.textTails = map[string]string{}
		r.textFences = map[string]bool{}
	}
	if len(r.textTails) >= 16 && r.textTails[channel] == "" {
		r.incomplete("text_channels", true)
		return
	}
	text = r.textTails[channel] + text
	initiallyFenced := r.textFences[channel]
	r.windowsWithFence(text, 0, initiallyFenced)
	if len(text) > scanOverlap {
		cut := len(text) - scanOverlap
		// A one/two-character prefix is not yet a complete Markdown fence.
		// Keep it with the tail so the next event sees the original marker.
		lineStart := strings.LastIndex(text[:cut], "\n") + 1
		prefix := strings.TrimSpace(text[lineStart:cut])
		if prefix == "`" || prefix == "``" || prefix == "~" || prefix == "~~" {
			cut -= len(prefix)
		}
		_, r.textFences[channel] = codeVisibility(text[:cut], initiallyFenced)
		text = text[cut:]
	}
	r.textTails[channel] = text
}

func (r *scanRun) tool(name string) {
	if name == "" {
		return
	}
	if !r.input.Context.ToolsKnown {
		r.incomplete("request_tool_context_unknown", false)
		return
	}
	for _, allowed := range r.input.Context.AllowedTools {
		if name == allowed {
			return
		}
	}
	r.add(SeverityHigh, "unrequested_tool", "响应调用了请求未授权的工具", name)
}

func (r *scanRun) credentialsInValue(value any, depth int) {
	if !r.available() {
		return
	}
	if depth > 16 {
		r.incomplete("structure_depth", true)
		return
	}
	switch value := value.(type) {
	case string:
		r.credentialValue(value, 0)
	case map[string]any:
		for _, child := range value {
			r.credentialsInValue(child, depth+1)
		}
	case []any:
		for _, child := range value {
			r.credentialsInValue(child, depth+1)
		}
	}
}

// Unknown protocol fields cannot establish role/tool facts, but must not hide
// known credentials by placing them in an encoded metadata string.
func (r *scanRun) credentialValue(text string, depth int) {
	if len(r.input.Keys) == 0 || text == "" {
		return
	}
	if len(text) > scanWindow {
		for offset := 0; offset < len(text) && r.available(); {
			end := min(offset+scanWindow, len(text))
			r.credentialValue(text[offset:end], depth)
			if end == len(text) {
				break
			}
			offset = end - scanOverlap
		}
		return
	}
	if !r.spend(len(text)) {
		return
	}
	r.depth = max(r.depth, depth)
	r.credentialSignals(text, text, depth)
	for _, value := range decodedVariants(text) {
		if value.failed {
			r.incomplete("payload_decode_failed", false)
			continue
		}
		if depth >= MaxDecodeDepth {
			r.incomplete("decode_depth_limit", true)
			continue
		}
		r.credentialValue(value.text, depth+1)
	}
}

func requestContext(body []byte) RequestContext {
	var object struct {
		Tools []struct {
			Name     string `json:"name"`
			Function struct {
				Name string `json:"name"`
			} `json:"function"`
		} `json:"tools"`
		Functions []struct {
			Name string `json:"name"`
		} `json:"functions"`
	}
	if len(body) == 0 || len(body) > MaxEventBytes || json.Unmarshal(body, &object) != nil {
		return RequestContext{}
	}
	context := RequestContext{ToolsKnown: true}
	for _, tool := range object.Tools {
		name := tool.Name
		if name == "" {
			name = tool.Function.Name
		}
		if len(name) > 128 || strings.TrimSpace(name) == "" {
			return RequestContext{}
		}
		context.AllowedTools = append(context.AllowedTools, name)
	}
	for _, tool := range object.Functions {
		if len(tool.Name) > 128 || tool.Name == "" {
			return RequestContext{}
		}
		context.AllowedTools = append(context.AllowedTools, tool.Name)
	}
	if len(context.AllowedTools) > 64 {
		return RequestContext{}
	}
	return context
}
