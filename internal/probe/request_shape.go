package probe

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

const (
	requestShapeBodyLimit   = 64 << 10
	requestShapeHeaderLimit = 16 << 10
	requestShapeBudget      = 10 * time.Millisecond
)

var publicClientAgent = regexp.MustCompile(`^(claude-cli|cc-switch|OpenAI/Python|OpenAI/JS|anthropic-python|anthropic-typescript)/([0-9]{1,2})(\.[0-9]{1,4}){1,3}( \(external, (cli|sdk-cli|claude-vscode)\))?$`)
var publicPackageVersion = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,4}){1,3}$`)

// The embedded captures are the maintained source of known protocol beta names;
// learning observes those flags, it never injects them into unrelated requests.
var learnedProtocolBetas = func() map[string]bool {
	known := map[string]bool{"prompt-caching-2024-07-31": true, "token-counting-2024-11-01": true, "fine-grained-tool-streaming-2025-05-14": true, "output-128k-2025-02-19": true}
	if templates, err := LoadBuiltinTemplates(); err == nil {
		for _, template := range templates.Templates() {
			for _, value := range strings.Split(template.Header("anthropic-beta"), ",") {
				if value = strings.TrimSpace(value); value != "" {
					known[value] = true
				}
			}
		}
	}
	return known
}()

// SanitizeRequestShape retains only protocol vocabulary, types and generated
// session placeholders. Raw business strings and their hashes never escape.
func SanitizeRequestShape(endpoint model.EndpointKind, view health.AttemptRequestView) (shape model.ClientRequestShape, reason model.RequestShapeUnavailableReason) {
	defer func() {
		if recover() != nil {
			shape, reason = model.ClientRequestShape{}, model.ShapeSanitizerFailure
		}
	}()
	fail := func(reason model.RequestShapeUnavailableReason) (model.ClientRequestShape, model.RequestShapeUnavailableReason) {
		return model.ClientRequestShape{}, reason
	}
	if !endpoint.Valid() {
		return fail(model.ShapeUnsupported)
	}
	if view.BodyTruncated {
		return fail(model.ShapeBodyTruncated)
	}
	if len(view.Body) > requestShapeBodyLimit || len(view.RawQuery) > 8192 {
		return fail(model.ShapeUnsupported)
	}
	deadline := time.Now().Add(requestShapeBudget)
	shape.ClientFamily = "generic"
	headerBytes := 0
	for name, values := range view.Header {
		headerBytes += len(name)
		for _, value := range values {
			// Repeated empty values still consume wire and slice space.
			headerBytes += len(name) + len(value) + 4
			if headerBytes > requestShapeHeaderLimit {
				return fail(model.ShapeUnsupported)
			}
		}
		if headerBytes > requestShapeHeaderLimit {
			return fail(model.ShapeUnsupported)
		}
		name = strings.ToLower(name)
		var safe []string
		for _, value := range values {
			switch name {
			case "content-type":
				media, params, err := mime.ParseMediaType(value)
				if err != nil || media != "application/json" || (params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8")) {
					return fail(model.ShapeUnsafeValue)
				}
				safe = append(safe, "application/json")
			case "anthropic-version":
				if value != "2023-06-01" {
					return fail(model.ShapeUnsafeValue)
				}
				safe = append(safe, value)
			case "anthropic-beta":
				beta, ok := safeProtocolBetas(value)
				if !ok {
					return fail(model.ShapeUnsafeValue)
				}
				safe = append(safe, beta)
			case "user-agent":
				if match := publicClientAgent.FindStringSubmatch(value); match != nil {
					shape.ClientFamily = strings.ToLower(match[1]) + "/" + match[2]
					safe = append(safe, value)
				}
			case "x-stainless-lang":
				if !oneOf(value, "js", "python", "go", "java", "kotlin", "csharp", "ruby") {
					return fail(model.ShapeUnsafeValue)
				}
				safe = append(safe, value)
			case "x-stainless-os":
				if !oneOf(strings.ToLower(value), "linux", "windows", "macos", "android", "ios", "freebsd") {
					return fail(model.ShapeUnsafeValue)
				}
				safe = append(safe, value)
			case "x-stainless-arch":
				if !oneOf(value, "x64", "arm64", "x86", "arm", "other:unknown") {
					return fail(model.ShapeUnsafeValue)
				}
				safe = append(safe, value)
			case "accept":
				if oneOf(value, "application/json", "text/event-stream", "*/*") {
					safe = append(safe, value)
				}
			case "x-app":
				if !oneOf(value, "cli", "claude-code", "cc-switch") {
					return fail(model.ShapeUnsafeValue)
				}
				safe = append(safe, value)
			case "x-stainless-package-version", "x-stainless-runtime-version":
				if !publicPackageVersion.MatchString(strings.TrimPrefix(value, "v")) {
					return fail(model.ShapeUnsafeValue)
				}
				safe = append(safe, strings.Clone(value))
			case "x-stainless-runtime":
				if !oneOf(value, "node", "deno", "bun", "python", "go", "jvm", "dotnet", "ruby") {
					return fail(model.ShapeUnsafeValue)
				}
				safe = append(safe, value)
			case "x-stainless-retry-count":
				if !oneOf(value, "0", "1", "2", "3", "4", "5") {
					return fail(model.ShapeUnsafeValue)
				}
				safe = append(safe, value)
			case "anthropic-dangerous-direct-browser-access":
				if !oneOf(value, "true", "false") {
					return fail(model.ShapeUnsafeValue)
				}
				safe = append(safe, value)
			}
		}
		if len(safe) > 0 {
			sort.Strings(safe)
			shape.SafeHeaders = append(shape.SafeHeaders, model.HeaderTemplate{Name: name, Values: safe})
		}
	}
	shape.SafeHeaders = canonicalShapeHeaders(shape.SafeHeaders)
	query, err := url.ParseQuery(view.RawQuery)
	if err != nil || len(strings.Split(view.RawQuery, "&")) > 32 {
		return fail(model.ShapeUnsupported)
	}
	safeQuery, queryTypes := url.Values{}, map[string]string{}
	for name, values := range query {
		switch strings.ToLower(name) {
		case "api_key", "apikey", "key", "token", "access_token", "authorization":
			continue
		case "session", "session_id", "request_id":
			safeQuery.Set(name, "{{SESSION_ID}}")
			queryTypes[name] = "session"
		case "timestamp":
			safeQuery.Set(name, "{{TIMESTAMP}}")
			queryTypes[name] = "timestamp"
		case "beta":
			for _, value := range values {
				if !oneOf(value, "true", "false", "1", "0") {
					return fail(model.ShapeUnsafeValue)
				}
				safeQuery.Add(name, value)
			}
			queryTypes[name] = "bool"
		case "anthropic_beta":
			for _, value := range values {
				beta, ok := safeProtocolBetas(value)
				if !ok {
					return fail(model.ShapeUnsafeValue)
				}
				safeQuery.Add(name, beta)
			}
			queryTypes[name] = "beta"
		default:
			return fail(model.ShapeUnsafeValue)
		}
	}
	for name := range safeQuery {
		sort.Strings(safeQuery[name])
	}
	shape.FixedRawQuery = safeQuery.Encode()
	shape.QueryShapeJSON, _ = json.Marshal(queryTypes)
	shape.BodyTemplate = materializeLearnedBodyTemplate(endpoint)
	if endpoint == model.EndpointModels {
		if len(bytes.TrimSpace(view.Body)) != 0 {
			return fail(model.ShapeUnsupported)
		}
		shape.BodyShapeJSON = []byte(`{}`)
		return shape, ""
	}
	decoder := json.NewDecoder(bytes.NewReader(view.Body))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return fail(model.ShapeUnsupported)
	}
	bodyTypes := map[string]any{}
	for decoder.More() {
		if len(bodyTypes) >= 64 || time.Now().After(deadline) {
			return fail(model.ShapeUnsupported)
		}
		key, err := decoder.Token()
		if err != nil {
			return fail(model.ShapeUnsupported)
		}
		name, ok := key.(string)
		if !ok {
			return fail(model.ShapeUnsupported)
		}
		if _, duplicate := bodyTypes[name]; duplicate {
			return fail(model.ShapeUnsupported)
		}
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil {
			return fail(model.ShapeUnsupported)
		}
		switch name {
		case "model", "messages", "input", "prompt", "system", "tools", "metadata", "stop", "stop_sequences", "user", "file", "files", "attachments", "response_format":
			bodyTypes[name] = jsonShapeType(raw)
		case "max_tokens", "max_output_tokens", "max_completion_tokens", "temperature", "top_p", "top_k", "seed", "presence_penalty", "frequency_penalty":
			var number json.Number
			if err := json.Unmarshal(raw, &number); err != nil {
				return fail(model.ShapeUnsupported)
			}
			if _, err := number.Float64(); err != nil {
				return fail(model.ShapeUnsupported)
			}
			bodyTypes[name] = "number"
		case "stream", "store", "parallel_tool_calls", "include_obfuscation":
			var flag bool
			if json.Unmarshal(raw, &flag) != nil {
				return fail(model.ShapeUnsupported)
			}
			bodyTypes[name] = flag
		case "service_tier":
			var tier string
			if json.Unmarshal(raw, &tier) != nil || !oneOf(tier, "auto", "default", "flex", "priority", "standard") {
				return fail(model.ShapeUnsafeValue)
			}
			bodyTypes[name] = tier
		case "thinking", "reasoning":
			configuration, ok := safeReasoningConfiguration(name, raw)
			if !ok {
				return fail(model.ShapeUnsafeValue)
			}
			bodyTypes[name] = configuration
		default:
			return fail(model.ShapeUnsafeValue)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return fail(model.ShapeUnsupported)
	}
	if decoder.Decode(new(any)) != io.EOF || time.Now().After(deadline) {
		return fail(model.ShapeUnsupported)
	}
	if bodyTypes["model"] != "string" {
		return fail(model.ShapeUnsupported)
	}
	shape.BodyShapeJSON, _ = json.Marshal(bodyTypes)
	shape.BodyTemplate = materializeApprovedShapeBody(endpoint, shape.BodyShapeJSON)
	return shape, ""
}

// Rebuild from safe metadata instead of accepting a caller's BodyTemplate.
// Output ceilings are probe constants, never the original business budget.
func materializeApprovedShapeBody(endpoint model.EndpointKind, graph []byte) []byte {
	base := materializeLearnedBodyTemplate(endpoint)
	if endpoint == model.EndpointModels || endpoint == model.EndpointCountTokens {
		return base
	}
	var body, fields map[string]any
	if json.Unmarshal(base, &body) != nil || json.Unmarshal(graph, &fields) != nil {
		return base
	}
	for _, name := range []string{"stream", "store", "parallel_tool_calls", "include_obfuscation"} {
		if value, ok := fields[name].(bool); ok {
			body[name] = value
		}
	}
	if tier, ok := fields["service_tier"].(string); ok && oneOf(tier, "auto", "default", "flex", "priority", "standard") {
		body["service_tier"] = tier
	}
	if thinking, ok := fields["thinking"].(map[string]any); ok && endpoint == model.EndpointMessages {
		if kind, ok := thinking["type"].(string); ok && oneOf(kind, "enabled", "disabled", "adaptive") {
			configuration := map[string]any{"type": kind}
			if kind == "enabled" {
				configuration["budget_tokens"] = 1024
				body["max_tokens"] = 1025
			}
			body["thinking"] = configuration
		}
	}
	if reasoning, ok := fields["reasoning"].(map[string]any); ok && endpoint == model.EndpointResponses {
		configuration := map[string]any{}
		if effort, ok := reasoning["effort"].(string); ok && oneOf(effort, "none", "minimal", "low", "medium", "high", "xhigh") {
			configuration["effort"] = effort
		}
		if summary, ok := reasoning["summary"].(string); ok && oneOf(summary, "auto", "concise", "detailed") {
			configuration["summary"] = summary
		}
		if len(configuration) > 0 {
			body["reasoning"] = configuration
		}
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return base
	}
	return encoded
}

func jsonShapeType(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return "null"
	}
	switch raw[0] {
	case '{':
		return "object"
	case '[':
		return "array"
	case '"':
		return "string"
	case 't', 'f':
		return "bool"
	case 'n':
		return "null"
	default:
		return "number"
	}
}

func safeReasoningConfiguration(name string, raw json.RawMessage) (map[string]any, bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil || len(fields) > 4 {
		return nil, false
	}
	safe := map[string]any{}
	for key, value := range fields {
		var text string
		if key == "budget_tokens" && name == "thinking" {
			var number json.Number
			if json.Unmarshal(value, &number) != nil {
				return nil, false
			}
			safe[key] = "number"
			continue
		}
		if json.Unmarshal(value, &text) != nil {
			return nil, false
		}
		switch key {
		case "type":
			if name != "thinking" || !oneOf(text, "enabled", "disabled", "adaptive") {
				return nil, false
			}
		case "effort":
			if name != "reasoning" || !oneOf(text, "none", "minimal", "low", "medium", "high", "xhigh") {
				return nil, false
			}
		case "summary":
			if name != "reasoning" || !oneOf(text, "auto", "concise", "detailed") {
				return nil, false
			}
		default:
			return nil, false
		}
		safe[key] = text
	}
	return safe, true
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func safeProtocolBetas(value string) (string, bool) {
	parts := strings.Split(value, ",")
	if len(parts) > 16 {
		return "", false
	}
	for i, part := range parts {
		parts[i] = strings.TrimSpace(part)
		if !learnedProtocolBetas[parts[i]] {
			return "", false
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ","), true
}

func canonicalShapeHeaders(headers []model.HeaderTemplate) []model.HeaderTemplate {
	valuesByName := map[string][]string{}
	for _, header := range headers {
		name := strings.ToLower(header.Name)
		for _, value := range header.Values {
			valuesByName[name] = append(valuesByName[name], strings.Clone(value))
		}
	}
	canonical := make([]model.HeaderTemplate, 0, len(valuesByName))
	for name, values := range valuesByName {
		sort.Strings(values)
		canonical = append(canonical, model.HeaderTemplate{Name: name, Values: values})
	}
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].Name < canonical[j].Name })
	return canonical
}
