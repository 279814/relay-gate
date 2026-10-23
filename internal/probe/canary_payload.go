package probe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/protocol"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

// canaryCheck consumes the shared Decoder's ephemeral objects. It has no
// transport, framer, tool executor or health writer, and retains at most one
// bounded name/argument pair from this synthetic response.
type canaryCheck struct {
	beforeSend                  func(context.Context) error
	endpoint                    model.EndpointKind
	nonce                       string
	source                      model.CanarySource
	policyRevision              int64
	toolSeen                    bool
	toolID                      string
	name                        string
	args                        string
	violation                   bool
	inputPresent, outputPresent bool
}

func newCanaryCheck(endpoint model.EndpointKind, nonce string, source model.CanarySource, revision int64) *canaryCheck {
	return &canaryCheck{endpoint: endpoint, nonce: nonce, source: source, policyRevision: revision}
}

func canaryObject(raw json.RawMessage) map[string]json.RawMessage {
	var value map[string]json.RawMessage
	_ = json.Unmarshal(raw, &value)
	return value
}
func canaryString(raw json.RawMessage) string {
	var value string
	_ = json.Unmarshal(raw, &value)
	return value
}
func canaryArray(raw json.RawMessage) []map[string]json.RawMessage {
	var value []map[string]json.RawMessage
	_ = json.Unmarshal(raw, &value)
	return value
}

func (c *canaryCheck) observe(view protocol.PayloadView) {
	object := view.Object
	c.usage(canaryObject(object["usage"]))
	c.usage(canaryObject(canaryObject(object["message"])["usage"]))
	c.usage(canaryObject(canaryObject(object["response"])["usage"]))
	if c.violation {
		return
	}
	switch c.endpoint {
	case model.EndpointMessages:
		c.messages(object)
	case model.EndpointResponses:
		c.responses(object)
	case model.EndpointChatCompletions:
		c.chat(object)
	default:
		c.violation = true
	}
}

func (c *canaryCheck) usage(usage map[string]json.RawMessage) {
	for _, pair := range []struct {
		name  string
		input bool
	}{{"input_tokens", true}, {"prompt_tokens", true}, {"output_tokens", false}, {"completion_tokens", false}} {
		if raw, ok := usage[pair.name]; ok {
			var n int64
			if json.Unmarshal(raw, &n) == nil && n >= 0 {
				if pair.input {
					c.inputPresent = true
				} else {
					c.outputPresent = true
				}
			}
		}
	}
}

func (c *canaryCheck) index(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	n, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || n != 0 {
		c.violation = true
		return false
	}
	return true
}

func (c *canaryCheck) bind(id string, start bool) {
	if len(id) > 128 || start && c.toolSeen || c.toolID != "" && id != "" && c.toolID != id {
		c.violation = true
		return
	}
	c.toolSeen = true
	if id != "" {
		c.toolID = id
	}
}
func (c *canaryCheck) setName(name string, delta bool) {
	if name == "" {
		return
	}
	if len(name) > len(model.CanaryTool) {
		c.violation = true
		return
	}
	if delta {
		if len(c.name)+len(name) > len(model.CanaryTool) {
			c.violation = true
			return
		}
		c.name += name
	} else if c.name == "" || strings.HasPrefix(name, c.name) {
		c.name = name
	} else {
		c.violation = true
		return
	}
	if len(c.name) > len(model.CanaryTool) || !strings.HasPrefix(model.CanaryTool, c.name) {
		c.violation = true
	}
}
func (c *canaryCheck) setArgs(args string, delta bool) {
	if args == "" {
		return
	}
	if delta {
		if len(c.args)+len(args) > 8192 {
			c.violation = true
			return
		}
		c.args += args
	} else {
		if len(args) > 8192 {
			c.violation = true
			return
		}
		if c.args != "" && !strings.HasPrefix(args, c.args) && !(canaryNonce(c.args, c.nonce) && canaryNonce(args, c.nonce)) {
			c.violation = true
			return
		}
		c.args = args
	}
}

func (c *canaryCheck) messages(object map[string]json.RawMessage) {
	c.usage(canaryObject(canaryObject(object["message"])["usage"]))
	kind := canaryString(object["type"])
	if raw, ok := object["content"]; ok {
		blocks := canaryArray(raw)
		if len(blocks) != 1 {
			c.violation = true
			return
		}
		c.messageBlock(blocks[0], true)
	}
	if kind == "content_block_start" && c.index(object["index"]) {
		c.messageBlock(canaryObject(object["content_block"]), true)
	}
	if kind == "content_block_delta" && c.index(object["index"]) {
		delta := canaryObject(object["delta"])
		switch canaryString(delta["type"]) {
		case "input_json_delta":
			if !c.toolSeen {
				c.violation = true
				return
			}
			c.setArgs(canaryString(delta["partial_json"]), true)
		case "text_delta", "thinking_delta":
			if canaryString(delta["text"]) != "" || canaryString(delta["thinking"]) != "" {
				c.violation = true
			}
		}
	}
}
func (c *canaryCheck) messageBlock(block map[string]json.RawMessage, start bool) {
	if canaryString(block["type"]) != "tool_use" {
		c.violation = true
		return
	}
	c.bind(canaryString(block["id"]), start)
	c.setName(canaryString(block["name"]), false)
	raw := bytes.TrimSpace(block["input"])
	if len(raw) > 0 && string(raw) != "{}" {
		c.setArgs(string(raw), false)
	}
}

func (c *canaryCheck) chat(object map[string]json.RawMessage) {
	choices := canaryArray(object["choices"])
	if len(choices) > 1 {
		c.violation = true
		return
	}
	for _, choice := range choices {
		if !c.index(choice["index"]) {
			return
		}
		message := canaryObject(choice["delta"])
		delta := message != nil
		if !delta {
			message = canaryObject(choice["message"])
		}
		for _, field := range []string{"content", "refusal", "reasoning_content", "thinking", "function_call"} {
			raw := bytes.TrimSpace(message[field])
			if len(raw) > 0 && string(raw) != "null" && string(raw) != `""` && string(raw) != "[]" {
				c.violation = true
				return
			}
		}
		calls := canaryArray(message["tool_calls"])
		if len(calls) > 1 {
			c.violation = true
			return
		}
		for _, call := range calls {
			if raw, present := call["type"]; present && canaryString(raw) != "function" {
				c.violation = true
				return
			}
			if !c.index(call["index"]) {
				return
			}
			c.bind(canaryString(call["id"]), !delta)
			function := canaryObject(call["function"])
			c.setName(canaryString(function["name"]), delta)
			c.setArgs(canaryString(function["arguments"]), delta)
		}
	}
}

func (c *canaryCheck) responses(object map[string]json.RawMessage) {
	kind := canaryString(object["type"])
	if strings.Contains(kind, "output_text") || strings.Contains(kind, "refusal") {
		if canaryString(object["delta"]) != "" || canaryString(object["text"]) != "" {
			c.violation = true
		}
	}
	if kind == "response.output_item.added" || kind == "response.output_item.done" {
		if !c.index(object["output_index"]) {
			return
		}
		c.responseItem(canaryObject(object["item"]), kind == "response.output_item.added")
	}
	if kind == "response.function_call_arguments.delta" || kind == "response.function_call_arguments.done" {
		if !c.index(object["output_index"]) {
			return
		}
		c.bind(canaryString(object["item_id"]), false)
		if kind == "response.function_call_arguments.delta" {
			c.setArgs(canaryString(object["delta"]), true)
		} else {
			c.setArgs(canaryString(object["arguments"]), false)
		}
	}
	if part := canaryObject(object["part"]); part != nil {
		if canaryString(part["text"]) != "" || canaryString(part["refusal"]) != "" {
			c.violation = true
		}
	}
	response := canaryObject(object["response"])
	if response != nil {
		c.usage(canaryObject(response["usage"]))
	} else {
		response = object
	}
	if raw, ok := response["output"]; ok {
		items := canaryArray(raw)
		if len(items) != 1 {
			c.violation = true
			return
		}
		c.responseItem(items[0], false)
	}
}
func (c *canaryCheck) responseItem(item map[string]json.RawMessage, start bool) {
	if canaryString(item["type"]) != "function_call" {
		c.violation = true
		return
	}
	c.bind(canaryString(item["id"]), start)
	c.setName(canaryString(item["name"]), false)
	c.setArgs(canaryString(item["arguments"]), false)
}

// Token-by-token shape validation rejects duplicate nonce keys, unknown keys,
// arrays and trailing values; json.Unmarshal into a map would erase duplicates.
func canaryNonce(arguments, nonce string) bool {
	decoder := json.NewDecoder(strings.NewReader(arguments))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return false
	}
	key, err := decoder.Token()
	if err != nil || key != "nonce" {
		return false
	}
	value, err := decoder.Token()
	if err != nil || value != nonce {
		return false
	}
	last, err := decoder.Token()
	if err != nil || last != json.Delim('}') {
		return false
	}
	_, err = decoder.Token()
	return err == io.EOF
}

func (c *canaryCheck) finalize(e model.ProbeExecution) *model.CanaryExecution {
	nonceHash := sha256.Sum256([]byte(c.nonce))
	result := &model.CanaryExecution{ExecutionID: e.ID, Source: c.source, PolicyRevision: c.policyRevision, ExpectationVersion: 1, NonceSHA256: hex.EncodeToString(nonceHash[:]), ExpectedTool: model.CanaryTool, InputUsagePresent: c.inputPresent, OutputUsagePresent: c.outputPresent}
	nameMatched := c.toolSeen && c.name == model.CanaryTool
	nonceMatched := c.toolSeen && canaryNonce(c.args, c.nonce)
	if c.toolSeen {
		result.ToolMatched = &nameMatched
		result.NonceMatched = &nonceMatched
	}
	switch {
	case e.SentAtMS <= 0:
		result.Verdict = "not_sent"
	case e.ObserverIncomplete:
		result.Verdict = "incomplete"
	case e.ErrorClass == model.ErrorIgnored && !e.Success:
		result.Verdict = "canceled"
	case c.violation:
		result.Verdict = "violation"
	case e.StatusCode >= 400:
		result.Verdict = "execution_failed"
	case !e.NormalEndSeen || e.Partial:
		result.Verdict = "incomplete"
	case !nameMatched || !nonceMatched:
		result.Verdict = "violation"
	case !e.Success:
		result.Verdict = "execution_failed"
	default:
		result.Verdict = "passed"
	}
	result.EvidenceHash, _ = revisioncodec.NewCanaryEvidenceHash(*result)
	return result
}
