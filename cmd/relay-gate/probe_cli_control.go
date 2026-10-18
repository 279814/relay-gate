package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probetemplate"
	"github.com/279814/relay-gate/internal/proxy"
)

const maxControlBytes = 1 << 20

type controlIsolation struct {
	Configuration    bool `json:"configuration"`
	MCP              bool `json:"mcp"`
	Hooks            bool `json:"hooks"`
	Plugins          bool `json:"plugins"`
	Environment      bool `json:"environment"`
	TemporaryWorkdir bool `json:"temporary_workdir"`
}

type controlCapture struct {
	FormatVersion          int              `json:"format_version"`
	Protocol               string           `json:"protocol"`
	Endpoint               string           `json:"endpoint"`
	Source                 string           `json:"source"`
	ControlID              string           `json:"control_id"`
	Nonce                  string           `json:"nonce"`
	CapturedAt             string           `json:"captured_at"`
	CompletedAt            string           `json:"completed_at"`
	Truncated              bool             `json:"truncated"`
	AuthenticationVerified bool             `json:"authentication_verified"`
	Isolation              controlIsolation `json:"isolation"`
	Method                 string           `json:"method"`
	RequestTarget          string           `json:"request_target"`
	Headers                json.RawMessage  `json:"headers"`
	BodyBase64             string           `json:"body_base64"`
	TestMode               bool             `json:"test_mode,omitempty"`
	SourceVersion          string           `json:"source_version,omitempty"`
	RequestLine            string           `json:"request_line,omitempty"`
	HeaderSHA256           string           `json:"header_sha256,omitempty"`
	BodySHA256             string           `json:"body_sha256,omitempty"`
	BodyBytes              int              `json:"body_bytes,omitempty"`
	SecretScanVersion      string           `json:"secret_scan_version,omitempty"`
}

type validatedControl struct {
	entry    controlEntry
	body     []byte
	headers  []model.HeaderTemplate
	auth     model.EndpointAuthProfile
	rawQuery string
}

func decodeControlJSON(data []byte, value any) error {
	if err := uniqueControlJSON(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errCLIPrivateInput
	}
	var tail any
	if decoder.Decode(&tail) != io.EOF {
		return errCLIPrivateInput
	}
	return nil
}

// Duplicate metadata/input keys can hide a different conversation from a
// last-key-wins decoder. This is input-file validation, not a response parser.
func uniqueControlJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 32 {
			return errCLIPrivateInput
		}
		token, err := decoder.Token()
		if err != nil {
			return errCLIPrivateInput
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return errCLIPrivateInput
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errCLIPrivateInput
				}
				seen[name] = true
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errCLIPrivateInput
		}
		_, err = decoder.Token()
		if err != nil {
			return errCLIPrivateInput
		}
		return nil
	}
	if err := visit(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errCLIPrivateInput
	}
	return nil
}

func controlHash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func controlFresh(entry controlEntry, now time.Time) bool {
	captured, e1 := time.Parse(time.RFC3339Nano, entry.CapturedAt)
	completed, e2 := time.Parse(time.RFC3339Nano, entry.CompletedAt)
	return e1 == nil && e2 == nil && !completed.Before(captured) && !completed.After(now) && now.Sub(completed) <= controlFreshness
}

var controlNoncePattern = regexp.MustCompile(`^[a-f0-9]{16,64}$`)

func loadControlManifest(path, root string, now time.Time, knownSecrets ...string) (*controlManifest, error) {
	data, err := readCLIPrivateFile(path, root, maxControlBytes)
	if err != nil {
		return nil, err
	}
	var manifest controlManifest
	if err := decodeControlJSON(data, &manifest); err != nil {
		return nil, err
	}
	if manifest.Version != "1" || len(manifest.Entries) == 0 || len(manifest.Entries) > 128 {
		return nil, errCLIPrivateInput
	}
	seen := map[string]bool{}
	for index := range manifest.Entries {
		entry := &manifest.Entries[index]
		endpoint := model.EndpointKind(entry.Endpoint)
		if !endpoint.Valid() || endpoint == model.EndpointModels || entry.Alias == "" || !controlNoncePattern.MatchString(entry.Nonce) || entry.ControlID == "" || len(entry.ControlID) > 128 ||
			entry.Truncated || entry.SecretScan != "1" || !controlFresh(*entry, now) || entry.BodyBytes < 0 || entry.BodyBytes > maxControlBytes {
			return nil, errCLIPrivateInput
		}
		key := entry.Alias + "|" + entry.Endpoint
		if seen[key] {
			return nil, errCLIPrivateInput
		}
		seen[key] = true
		if entry.Source != "claude-code-isolated" && entry.Source != "cc-switch-isolated" {
			return nil, errCLIPrivateInput
		}
		if (endpoint == model.EndpointMessages || endpoint == model.EndpointCountTokens) && (entry.Protocol != string(model.ProtoAnthropic) || entry.Source != "claude-code-isolated") {
			return nil, errCLIPrivateInput
		}
		if endpoint == model.EndpointResponses && (entry.Protocol != string(model.ProtoOpenAIResponses) || entry.Source != "cc-switch-isolated") {
			return nil, errCLIPrivateInput
		}
		if endpoint == model.EndpointChatCompletions && (entry.Protocol != string(model.ProtoOpenAIChat) || entry.Source != "cc-switch-isolated") {
			return nil, errCLIPrivateInput
		}
		if filepath.IsAbs(entry.FixturePath) || entry.FixturePath == "" {
			return nil, errCLIPrivateInput
		}
		fixturePath := filepath.Join(filepath.Dir(path), entry.FixturePath)
		rel, err := filepath.Rel(filepath.Dir(path), fixturePath)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, errCLIPrivateInput
		}
		fixtureData, err := readCLIPrivateFile(fixturePath, root, maxControlBytes*2)
		if err != nil {
			return nil, err
		}
		var capture controlCapture
		if err := decodeControlJSON(fixtureData, &capture); err != nil {
			return nil, err
		}
		if capture.FormatVersion != 2 || capture.TestMode || capture.Protocol != entry.Protocol || capture.Endpoint != entry.Endpoint || capture.Source != entry.Source ||
			capture.ControlID != entry.ControlID || capture.Nonce != entry.Nonce || capture.CapturedAt != entry.CapturedAt || capture.CompletedAt != entry.CompletedAt ||
			capture.Truncated || !capture.AuthenticationVerified || capture.Isolation != (controlIsolation{true, true, true, true, true, true}) {
			return nil, errCLIPrivateInput
		}
		body, err := base64.StdEncoding.Strict().DecodeString(capture.BodyBase64)
		if err != nil || len(body) != entry.BodyBytes || controlHash(body) != entry.BodySHA256 || controlHash(capture.Headers) != entry.HeaderSHA256 {
			return nil, errCLIPrivateInput
		}
		for _, secret := range knownSecrets {
			if secret != "" && (bytes.Contains(body, []byte(secret)) || bytes.Contains(capture.Headers, []byte(secret))) {
				return nil, errCLIPrivateInput
			}
		}
		if (capture.HeaderSHA256 != "" && capture.HeaderSHA256 != entry.HeaderSHA256) || (capture.BodySHA256 != "" && capture.BodySHA256 != entry.BodySHA256) || (capture.BodyBytes != 0 && capture.BodyBytes != entry.BodyBytes) || (capture.SecretScanVersion != "" && capture.SecretScanVersion != "1") {
			return nil, errCLIPrivateInput
		}
		var headers []model.HeaderTemplate
		if err := decodeControlJSON(capture.Headers, &headers); err != nil {
			return nil, err
		}
		if len(headers) > 128 {
			return nil, errCLIPrivateInput
		}
		loaded := &validatedControl{entry: *entry, body: body}
		rawHeaders := http.Header{}
		for _, header := range headers {
			for _, value := range header.Values {
				rawHeaders.Add(header.Name, value)
			}
		}
		safeHeaders := proxy.PrepareOutboundHeaders(rawHeaders, model.Protocol(entry.Protocol))
		for _, header := range headers {
			name := http.CanonicalHeaderKey(header.Name)
			if name == "Cookie" || name == "Set-Cookie" || name == "X-Admin-Password" || name == "Proxy-Authorization" {
				return nil, errCLIPrivateInput
			}
			if model.IsAuthHeader(name) {
				if loaded.auth.Mode != "" || len(header.Values) != 1 {
					return nil, errCLIPrivateInput
				}
				loaded.auth.SecretRef = "upstream_api_key"
				switch {
				case name == "Authorization" && header.Values[0] == "Bearer {{UPSTREAM_API_KEY}}":
					loaded.auth.Mode = model.AuthModeBearer
				case name == "X-Api-Key" && header.Values[0] == "{{UPSTREAM_API_KEY}}":
					loaded.auth.Mode = model.AuthModeXAPIKey
				case name == "Api-Key" && header.Values[0] == "{{UPSTREAM_API_KEY}}":
					loaded.auth.Mode = model.AuthModeAPIKey
				default:
					return nil, errCLIPrivateInput
				}
				continue
			}
			// Reuse the production forwarding protection, including headers named
			// by Connection and trusted-edge metadata. Never create a CLI variant.
			if _, kept := safeHeaders[name]; !kept {
				continue
			}
			loaded.headers = append(loaded.headers, header)
		}
		if loaded.auth.Mode == "" {
			return nil, errCLIPrivateInput
		}
		target, err := url.ParseRequestURI(capture.RequestTarget)
		if err != nil || target.IsAbs() || target.Path != endpoint.CanonicalPath() || target.Fragment != "" || capture.Method != endpoint.Method() {
			return nil, errCLIPrivateInput
		}
		loaded.rawQuery = target.RawQuery
		if err := validateControlPrompt(endpoint, body, entry.Nonce); err != nil {
			return nil, err
		}
		profile := model.TimeoutL2Standard
		if endpoint == model.EndpointModels {
			profile = model.TimeoutL1
		} else if endpoint == model.EndpointCountTokens {
			profile = model.TimeoutCountTokens
		}
		if _, err := probetemplate.Compile(endpoint, model.ProbeRecipeVersion{Method: capture.Method, FixedRawQuery: loaded.rawQuery, Headers: loaded.headers, Body: body, BodyIsText: true, TimeoutProfile: profile}); err != nil {
			return nil, errCLIPrivateInput
		}
		entry.loaded = loaded
	}
	return &manifest, nil
}

// Verify the dedicated one-turn control, not an arbitrary successful history.
// Native SDK numeric/boolean options and isolated system metadata may remain;
// user input is exactly the nonce prompt, with no attachments/tool results.
func validateControlPrompt(endpoint model.EndpointKind, body []byte, nonce string) error {
	if endpoint == model.EndpointModels {
		if len(body) != 0 {
			return errCLIPrivateInput
		}
		return nil
	}
	if _, err := proxy.ExtractModel(body); err != nil {
		return errCLIPrivateInput
	}
	var fields map[string]json.RawMessage
	if err := decodeControlJSON(body, &fields); err != nil {
		return err
	}
	allowed := map[string]bool{"model": true, "messages": true, "input": true, "stream": true, "max_tokens": true, "max_output_tokens": true, "max_completion_tokens": true, "temperature": true, "top_p": true, "top_k": true, "system": true, "metadata": true, "thinking": true, "stop_sequences": true}
	for key := range fields {
		if !allowed[key] {
			return errCLIPrivateInput
		}
	}
	prompt := "1+1=? control:" + nonce
	input := fields["messages"]
	if endpoint == model.EndpointResponses {
		input = fields["input"]
		var text string
		if json.Unmarshal(input, &text) == nil && text == prompt {
			return nil
		}
	}
	var messages []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	if err := decodeControlJSON(input, &messages); err != nil || len(messages) != 1 || messages[0].Role != "user" {
		return errCLIPrivateInput
	}
	var text string
	if json.Unmarshal(messages[0].Content, &text) == nil {
		if text != prompt {
			return errCLIPrivateInput
		}
		return nil
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := decodeControlJSON(messages[0].Content, &blocks); err != nil || len(blocks) != 1 || blocks[0].Text != prompt {
		return errCLIPrivateInput
	}
	if blocks[0].Type != "text" && !(endpoint == model.EndpointResponses && blocks[0].Type == "input_text") {
		return errCLIPrivateInput
	}
	return nil
}

func findControl(manifest *controlManifest, alias string, endpoint model.EndpointKind) *validatedControl {
	if manifest != nil {
		for _, entry := range manifest.Entries {
			if entry.Alias == alias && entry.Endpoint == string(endpoint) {
				return entry.loaded
			}
		}
	}
	return nil
}
