package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/279814/relay-gate/internal/model"
)

const controlProfile220 = "claude-code-2.1.220-windows-isolated-v1"
const control220ExecutableSHA = "af5bf1f1b2aadffc768eccd787084c6fdf9ba81624cbe96c1c6d9ac1a1550231"

func selectControlProfile(version string, raw json.RawMessage) (string, error) {
	if version == "1" {
		if len(raw) != 0 {
			return "", errCLIPrivateInput
		}
		return "", nil
	}
	var profile string
	if version != "2" || json.Unmarshal(raw, &profile) != nil {
		return "", errCLIPrivateInput
	}
	switch profile {
	case "legacy-format2-v1":
		return "", nil
	case controlProfile220:
		return profile, nil
	default:
		return "", errCLIPrivateInput
	}
}

func captureMatchesControlProfile(profile string, capture controlCapture) bool {
	if profile == "" {
		// Presence matters: null/empty new fields do not extend format 2.
		return capture.FormatVersion == 2 && len(capture.Profile) == 0 && len(capture.SourceExecutableSHA256) == 0
	}
	var name, executable string
	return profile == controlProfile220 && capture.FormatVersion == 3 &&
		json.Unmarshal(capture.Profile, &name) == nil && name == profile &&
		json.Unmarshal(capture.SourceExecutableSHA256, &executable) == nil && executable == control220ExecutableSHA &&
		capture.Source == "claude-code-isolated" && capture.SourceVersion == "2.1.220 (Claude Code)" &&
		capture.Protocol == "anthropic" && capture.Endpoint == "messages" &&
		capture.SecretScanVersion == "1" && capture.HeaderSHA256 != "" && capture.BodySHA256 != "" && capture.BodyBytes > 0 &&
		(capture.RequestTarget == "/v1/messages" || capture.RequestTarget == "/v1/messages?beta=true") &&
		capture.RequestLine == "POST "+capture.RequestTarget+" HTTP/1.1"
}

func control220DeviceID(nonce string) string {
	digest := sha256.Sum256([]byte("relay-gate-control-device-v1:" + nonce))
	return hex.EncodeToString(digest[:])
}

func control220SessionID(nonce string) string {
	digest := sha256.Sum256([]byte("relay-gate-control-session-v1:" + nonce))
	digest[6] = digest[6]&15 | 64
	digest[8] = digest[8]&63 | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", digest[:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16])
}

func validControl220Headers(headers []model.HeaderTemplate, nonce string, bodyBytes int) bool {
	expected := map[string]string{
		"host": "", "accept": "application/json", "accept-encoding": "identity",
		"content-type": "application/json", "content-length": strconv.Itoa(bodyBytes), "connection": "keep-alive",
		"x-api-key": "{{UPSTREAM_API_KEY}}", "user-agent": "claude-cli/2.1.220 (external, sdk-cli)",
		"x-stainless-arch": "x64", "x-stainless-lang": "js", "x-stainless-os": "Windows",
		"x-stainless-package-version": "0.94.0", "x-stainless-retry-count": "0", "x-stainless-runtime": "node",
		"x-stainless-runtime-version": "v26.3.0", "x-stainless-timeout": "600",
		"anthropic-beta": "claude-code-20250219,interleaved-thinking-2025-05-14,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,effort-2025-11-24,fallback-credit-2026-06-01",
		"anthropic-dangerous-direct-browser-access": "true", "anthropic-version": "2023-06-01", "x-app": "cli",
		"x-claude-code-session-id": control220SessionID(nonce),
	}
	if len(headers) != len(expected) {
		return false
	}
	seen := make(map[string]bool)
	for _, header := range headers {
		name := strings.ToLower(header.Name)
		value, known := expected[name]
		if !known || seen[name] || len(header.Values) != 1 {
			return false
		}
		seen[name] = true
		if name == "host" {
			if !validControlHeader(header, bodyBytes) {
				return false
			}
		} else if header.Values[0] != value {
			return false
		}
	}
	return true
}

type control220Block struct {
	Type  string          `json:"type"`
	Text  string          `json:"text"`
	Cache json.RawMessage `json:"cache_control,omitempty"`
}

func validControl220Block(block control220Block, cached bool) bool {
	if block.Type != "text" {
		return false
	}
	if !cached {
		return len(block.Cache) == 0
	}
	var cache struct {
		Type string `json:"type"`
	}
	return decodeControlJSON(block.Cache, &cache) == nil && cache.Type == "ephemeral"
}

// The billing checksum uses only the reviewed program's public seed, version
// and dedicated prompt. It never incorporates a host, account or user config.
func control220Billing(nonce string) string {
	prompt := "1+1=? control:" + nonce
	if len(prompt) <= 20 {
		return ""
	}
	material := "59cf53e54c78" + string([]byte{prompt[4], prompt[7], prompt[20]}) + "2.1.220"
	digest := sha256.Sum256([]byte(material))
	return "x-anthropic-billing-header: cc_version=2.1.220." + hex.EncodeToString(digest[:])[:3] + "; cc_entrypoint=sdk-cli;"
}

var control220Date = regexp.MustCompile(`[0-9]{4}-[0-9]{2}-[0-9]{2}`)

func validControl220Date(text, capturedAt string) bool {
	matches := control220Date.FindAllStringIndex(text, -1)
	if len(matches) != 1 {
		return false
	}
	stamp, err := time.Parse(time.RFC3339Nano, capturedAt)
	if err != nil {
		return false
	}
	date := text[matches[0][0]:matches[0][1]]
	// Local calendar fields can differ from UTC by one day. No arbitrary date
	// or extra context is admitted; the rest must match the public constructor.
	if date != stamp.UTC().Format("2006-01-02") && date != stamp.UTC().AddDate(0, 0, -1).Format("2006-01-02") && date != stamp.UTC().AddDate(0, 0, 1).Format("2006-01-02") {
		return false
	}
	normalized := text[:matches[0][0]] + "<date>" + text[matches[0][1]:]
	return controlHash([]byte(normalized)) == "01e1d5f4002869dbdac1f7d22231b35f4b67467f0fe246bdb5cbcbe1d49ed865"
}

func validateControl220Body(body []byte, nonce, capturedAt string) error {
	if !utf8.Valid(body) || !controlNoncePattern.MatchString(nonce) {
		return errCLIPrivateInput
	}
	var request struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string            `json:"role"`
			Content []control220Block `json:"content"`
		} `json:"messages"`
		System   []control220Block `json:"system"`
		Tools    json.RawMessage   `json:"tools"`
		Metadata struct {
			UserID string `json:"user_id"`
		} `json:"metadata"`
		MaxTokens int64 `json:"max_tokens"`
		Thinking  struct {
			Type string `json:"type"`
		} `json:"thinking"`
		Output struct {
			Effort string `json:"effort"`
		} `json:"output_config"`
		Stream bool `json:"stream"`
	}
	if decodeControlJSON(body, &request) != nil || request.Model == "" || len(request.Model) > 512 || strings.Contains(request.Model, "{{") || strings.ContainsAny(request.Model, "\r\n") ||
		request.MaxTokens != 64 || !request.Stream || request.Thinking.Type != "disabled" || request.Output.Effort != "low" {
		return errCLIPrivateInput
	}
	tools := bytes.TrimSpace(request.Tools)
	var items []json.RawMessage
	if len(tools) == 0 || tools[0] != '[' || decodeControlJSON(tools, &items) != nil || len(items) != 0 {
		return errCLIPrivateInput
	}
	var identity struct {
		Device  string  `json:"device_id"`
		Account *string `json:"account_uuid"`
		Session string  `json:"session_id"`
	}
	if decodeControlJSON([]byte(request.Metadata.UserID), &identity) != nil || identity.Device != control220DeviceID(nonce) || identity.Account == nil || *identity.Account != "" || identity.Session != control220SessionID(nonce) {
		return errCLIPrivateInput
	}
	if len(request.System) != 3 || !validControl220Block(request.System[0], false) || request.System[0].Text != control220Billing(nonce) ||
		!validControl220Block(request.System[1], true) || controlHash([]byte(request.System[1].Text)) != "0d7062851dd7bd7e66d4be4f12ac4951e3d2f587ec408295333a49963bd3f6b7" ||
		!validControl220Block(request.System[2], true) || request.System[2].Text != "Reply with 2 only." {
		return errCLIPrivateInput
	}
	if len(request.Messages) != 1 || request.Messages[0].Role != "user" || len(request.Messages[0].Content) != 2 {
		return errCLIPrivateInput
	}
	blocks := request.Messages[0].Content
	if !validControl220Block(blocks[0], false) || !validControl220Date(blocks[0].Text, capturedAt) || !validControl220Block(blocks[1], true) || blocks[1].Text != "1+1=? control:"+nonce {
		return errCLIPrivateInput
	}
	return nil
}
