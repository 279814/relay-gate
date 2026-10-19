package main

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/279814/relay-gate/internal/model"
)

// This is the public, non-business system explicitly selected by the producer.
// Isolation flags alone never authorize arbitrary system or session metadata.
const controlSystemPrompt = "Reply with 2 only."

type controlOptions struct {
	Model       string          `json:"model"`
	Stream      *bool           `json:"stream,omitempty"`
	Temperature *float64        `json:"temperature,omitempty"`
	TopP        *float64        `json:"top_p,omitempty"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
}

func (options controlOptions) valid() bool {
	if options.Model == "" || strings.Contains(options.Model, "{{") ||
		(options.Temperature != nil && (*options.Temperature < 0 || *options.Temperature > 2)) ||
		(options.TopP != nil && (*options.TopP < 0 || *options.TopP > 1)) {
		return false
	}
	if len(options.Metadata) != 0 {
		var metadata map[string]json.RawMessage
		if decodeControlJSON(options.Metadata, &metadata) != nil || metadata == nil || len(metadata) != 0 {
			return false
		}
	}
	return true
}

type controlAnthropicBody struct {
	controlOptions
	Messages      json.RawMessage `json:"messages"`
	MaxTokens     *int            `json:"max_tokens,omitempty"`
	TopK          *int            `json:"top_k,omitempty"`
	System        json.RawMessage `json:"system,omitempty"`
	Thinking      json.RawMessage `json:"thinking,omitempty"`
	StopSequences []string        `json:"stop_sequences,omitempty"`
}

type controlResponsesBody struct {
	controlOptions
	Input           json.RawMessage `json:"input"`
	MaxOutputTokens *int            `json:"max_output_tokens,omitempty"`
}

type controlChatBody struct {
	controlOptions
	Messages            json.RawMessage `json:"messages"`
	MaxTokens           *int            `json:"max_tokens,omitempty"`
	MaxCompletionTokens *int            `json:"max_completion_tokens,omitempty"`
}

func validControlTokenLimit(limit *int) bool {
	return limit != nil && *limit > 0 && *limit <= 2147483647
}

func validateControlPrompt(endpoint model.EndpointKind, body []byte, nonce string) error {
	var fields map[string]json.RawMessage
	if decodeControlJSON(body, &fields) != nil || fields == nil {
		return errCLIPrivateInput
	}
	for _, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errCLIPrivateInput
		}
	}
	var input json.RawMessage
	valid := false
	switch endpoint {
	case model.EndpointMessages, model.EndpointCountTokens:
		var request controlAnthropicBody
		if decodeControlJSON(body, &request) != nil || !request.controlOptions.valid() ||
			(request.TopK != nil && (*request.TopK < 0 || *request.TopK > 2147483647)) || len(request.StopSequences) != 0 ||
			!validControlSystem(request.System) || !validControlThinking(request.Thinking) {
			return errCLIPrivateInput
		}
		if endpoint == model.EndpointCountTokens {
			// The count endpoint has no generation or streaming options.
			for _, name := range []string{"max_tokens", "stream", "temperature", "top_p", "top_k", "thinking", "stop_sequences"} {
				if _, exists := fields[name]; exists {
					return errCLIPrivateInput
				}
			}
			valid = true
		} else {
			valid = validControlTokenLimit(request.MaxTokens)
		}
		input = request.Messages
	case model.EndpointResponses:
		var request controlResponsesBody
		if decodeControlJSON(body, &request) != nil || !request.controlOptions.valid() {
			return errCLIPrivateInput
		}
		valid, input = validControlTokenLimit(request.MaxOutputTokens), request.Input
	case model.EndpointChatCompletions:
		var request controlChatBody
		if decodeControlJSON(body, &request) != nil || !request.controlOptions.valid() {
			return errCLIPrivateInput
		}
		valid = (validControlTokenLimit(request.MaxTokens) && request.MaxCompletionTokens == nil) ||
			(validControlTokenLimit(request.MaxCompletionTokens) && request.MaxTokens == nil)
		input = request.Messages
	default:
		return errCLIPrivateInput
	}
	if !valid {
		return errCLIPrivateInput
	}
	return validateControlMessages(endpoint, input, "1+1=? control:"+nonce)
}

func validControlSystem(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text == controlSystemPrompt
	}
	var blocks []struct {
		Type         string          `json:"type"`
		Text         string          `json:"text"`
		CacheControl json.RawMessage `json:"cache_control,omitempty"`
	}
	if decodeControlJSON(raw, &blocks) != nil || len(blocks) != 1 || blocks[0].Type != "text" || blocks[0].Text != controlSystemPrompt {
		return false
	}
	if len(blocks[0].CacheControl) == 0 {
		return true
	}
	var cache struct {
		Type string `json:"type"`
	}
	return decodeControlJSON(blocks[0].CacheControl, &cache) == nil && cache.Type == "ephemeral"
}

func validControlThinking(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	var thinking struct {
		Type string `json:"type"`
	}
	return decodeControlJSON(raw, &thinking) == nil && thinking.Type == "disabled"
}
