package probetemplate

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/279814/relay-gate/internal/model"
)

type ResolvedValue struct {
	Plain    []byte
	Revision int64
}

type ResolvedSecret struct {
	ID       int64
	Plain    []byte
	Revision int64
}

type ValueResolver interface {
	ResolveValue(context.Context, string) (ResolvedValue, error)
}

type TemplateContent struct {
	Method   string
	RawQuery string
	Headers  []model.HeaderTemplate
	Body     []byte
}

type RenderedRequest struct {
	Method   string
	RawQuery string
	Header   http.Header
	Body     []byte
}

type compiledPart struct {
	literal       []byte
	placeholder   string
	percentEncode bool
}

type compiledHeader struct {
	name   string
	values [][]compiledPart
}

type CompiledRecipe struct {
	method          string
	query           []compiledPart
	headers         []compiledHeader
	body            []compiledPart
	requiredSecrets []string
}

var builtInPlaceholders = map[string]struct{}{
	"UPSTREAM_API_KEY": {},
	"UPSTREAM_MODEL":   {},
	"MODEL_NAME":       {},
	"PROBE_PROMPT":     {},
	"SESSION_ID":       {},
	"TIMESTAMP":        {},
}

func Compile(endpoint model.EndpointKind, version model.ProbeRecipeVersion) (*CompiledRecipe, error) {
	if err := version.ValidateForEndpoint(endpoint); err != nil {
		return nil, err
	}
	return compileContent(endpoint, TemplateContent{
		Method:   version.Method,
		RawQuery: version.FixedRawQuery,
		Headers:  version.Headers,
		Body:     version.Body,
	})
}

func ScanRequiredSecrets(endpoint model.EndpointKind, content TemplateContent) ([]string, error) {
	compiled, err := compileContent(endpoint, content)
	if err != nil {
		return nil, err
	}
	return compiled.RequiredSecrets(), nil
}

func compileContent(endpoint model.EndpointKind, content TemplateContent) (*CompiledRecipe, error) {
	if err := validateContentMethod(endpoint, content.Method, content.Body); err != nil {
		return nil, err
	}
	required := make(map[string]struct{})
	query, err := compileRawQuery(content.RawQuery, required)
	if err != nil {
		return nil, err
	}
	headers := make([]compiledHeader, 0, len(content.Headers))
	for _, header := range content.Headers {
		if !validHeaderName(header.Name) {
			return nil, model.WrapValidation("header name 无效: %q", header.Name)
		}
		switch strings.ToLower(header.Name) {
		case "content-length", "transfer-encoding", "connection", "host":
			return nil, model.WrapValidation("recipe 不能设置受保护头 %q", header.Name)
		}
		compiled := compiledHeader{name: header.Name, values: make([][]compiledPart, 0, len(header.Values))}
		for _, value := range header.Values {
			if err := validateHeaderValue([]byte(value)); err != nil {
				return nil, model.WrapValidation("header %q: %v", header.Name, err)
			}
			parts, err := compileTemplate([]byte(value), false, required)
			if err != nil {
				return nil, model.WrapValidation("header %q: %v", header.Name, err)
			}
			compiled.values = append(compiled.values, parts)
		}
		headers = append(headers, compiled)
	}
	body, err := compileTemplate(content.Body, false, required)
	if err != nil {
		return nil, model.WrapValidation("body template: %v", err)
	}
	requiredSecrets := make([]string, 0, len(required))
	for name := range required {
		requiredSecrets = append(requiredSecrets, name)
	}
	sort.Strings(requiredSecrets)
	return &CompiledRecipe{
		method:          content.Method,
		query:           query,
		headers:         headers,
		body:            body,
		requiredSecrets: requiredSecrets,
	}, nil
}

func validateContentMethod(endpoint model.EndpointKind, method string, body []byte) error {
	if !endpoint.Valid() {
		return model.WrapValidation("endpoint 无效: %q", endpoint)
	}
	if method != strings.ToUpper(method) || (method != "GET" && method != "HEAD" && method != "POST") {
		return model.WrapValidation("method 必须是大写 GET / HEAD / POST，收到 %q", method)
	}
	if endpoint == model.EndpointModels {
		if method != "GET" && method != "HEAD" {
			return model.WrapValidation("models endpoint 只允许 GET 或 HEAD")
		}
	} else if method != "POST" {
		return model.WrapValidation("%s endpoint 只允许 POST", endpoint)
	}
	if (method == "GET" || method == "HEAD") && len(body) != 0 {
		return model.WrapValidation("GET/HEAD recipe 不能包含 body")
	}
	return nil
}

func compileRawQuery(raw string, required map[string]struct{}) ([]compiledPart, error) {
	if raw == "" {
		return nil, nil
	}
	segments := strings.Split(raw, "&")
	compiled := make([]compiledPart, 0, len(segments)*3)
	for index, segment := range segments {
		if index > 0 {
			compiled = append(compiled, compiledPart{literal: []byte("&")})
		}
		name := segment
		value := ""
		hasEquals := false
		if separator := strings.IndexByte(segment, '='); separator >= 0 {
			name, value, hasEquals = segment[:separator], segment[separator+1:], true
		}
		if strings.Contains(name, "{{") {
			return nil, model.WrapValidation("query 参数名不能包含占位符")
		}
		compiled = append(compiled, compiledPart{literal: []byte(name)})
		if !hasEquals {
			continue
		}
		compiled = append(compiled, compiledPart{literal: []byte("=")})
		parts, err := compileTemplate([]byte(value), true, required)
		if err != nil {
			return nil, model.WrapValidation("query 参数 %q: %v", name, err)
		}
		hasPlaceholder := false
		for _, part := range parts {
			hasPlaceholder = hasPlaceholder || part.placeholder != ""
		}
		if hasPlaceholder && (len(parts) != 1 || parts[0].placeholder == "") {
			return nil, model.WrapValidation("query 占位符必须占据完整参数值: %q", name)
		}
		compiled = append(compiled, parts...)
	}
	return compiled, nil
}

func compileTemplate(input []byte, percentEncode bool, required map[string]struct{}) ([]compiledPart, error) {
	parts := make([]compiledPart, 0, 4)
	for offset := 0; offset < len(input); {
		relative := bytes.Index(input[offset:], []byte("{{"))
		if relative < 0 {
			appendLiteralPart(&parts, input[offset:])
			break
		}
		start := offset + relative
		appendLiteralPart(&parts, input[offset:start])
		if start+4 <= len(input) && bytes.Equal(input[start:start+4], []byte("{{{{")) {
			appendLiteralPart(&parts, []byte("{{"))
			offset = start + 4
			continue
		}
		endRelative := bytes.Index(input[start+2:], []byte("}}"))
		if endRelative < 0 {
			return nil, model.WrapValidation("存在未闭合占位符")
		}
		end := start + 2 + endRelative
		name := string(input[start+2 : end])
		if err := validatePlaceholder(name, required); err != nil {
			return nil, err
		}
		parts = append(parts, compiledPart{placeholder: name, percentEncode: percentEncode})
		offset = end + 2
	}
	return parts, nil
}

func appendLiteralPart(parts *[]compiledPart, value []byte) {
	if len(value) == 0 {
		return
	}
	copyValue := append([]byte(nil), value...)
	if count := len(*parts); count > 0 && (*parts)[count-1].placeholder == "" {
		(*parts)[count-1].literal = append((*parts)[count-1].literal, copyValue...)
		return
	}
	*parts = append(*parts, compiledPart{literal: copyValue})
}

func validatePlaceholder(name string, required map[string]struct{}) error {
	if _, ok := builtInPlaceholders[name]; ok {
		return nil
	}
	const prefix = "SECRET:"
	if !strings.HasPrefix(name, prefix) {
		return model.WrapValidation("未知占位符 %q", name)
	}
	secretName := strings.TrimPrefix(name, prefix)
	if !validSecretName(secretName) {
		return model.WrapValidation("Secret 名称无效: %q", secretName)
	}
	required[secretName] = struct{}{}
	return nil
}

func validSecretName(name string) bool {
	if name == "" {
		return false
	}
	for _, character := range []byte(name) {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, character := range []byte(name) {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character)) {
			continue
		}
		return false
	}
	return true
}

func validateHeaderValue(value []byte) error {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("包含控制字符")
		}
	}
	return nil
}

func (compiled *CompiledRecipe) RequiredSecrets() []string {
	if compiled == nil {
		return []string{}
	}
	return append([]string(nil), compiled.requiredSecrets...)
}

func (compiled *CompiledRecipe) Render(ctx context.Context, resolver ValueResolver) (RenderedRequest, error) {
	if compiled == nil || resolver == nil {
		return RenderedRequest{}, model.WrapValidation("compiled recipe/value resolver 不能为空")
	}
	cache := make(map[string]ResolvedValue)
	resolve := func(name string) (ResolvedValue, error) {
		if value, ok := cache[name]; ok {
			return value, nil
		}
		value, err := resolver.ResolveValue(ctx, name)
		if err != nil {
			return ResolvedValue{}, fmt.Errorf("解析占位符 %q: %w", name, err)
		}
		value.Plain = append([]byte(nil), value.Plain...)
		cache[name] = value
		return value, nil
	}
	query, err := renderParts(compiled.query, resolve)
	if err != nil {
		return RenderedRequest{}, err
	}
	body, err := renderParts(compiled.body, resolve)
	if err != nil {
		return RenderedRequest{}, err
	}
	header := make(http.Header, len(compiled.headers))
	for _, compiledHeader := range compiled.headers {
		for _, valueParts := range compiledHeader.values {
			value, err := renderParts(valueParts, resolve)
			if err != nil {
				return RenderedRequest{}, err
			}
			if err := validateHeaderValue(value); err != nil {
				return RenderedRequest{}, model.WrapValidation("渲染后的 header %q %v", compiledHeader.name, err)
			}
			header.Add(compiledHeader.name, string(value))
		}
	}
	return RenderedRequest{Method: compiled.method, RawQuery: string(query), Header: header, Body: body}, nil
}

func renderParts(parts []compiledPart, resolve func(string) (ResolvedValue, error)) ([]byte, error) {
	var result []byte
	for _, part := range parts {
		if part.placeholder == "" {
			result = append(result, part.literal...)
			continue
		}
		value, err := resolve(part.placeholder)
		if err != nil {
			return nil, err
		}
		if part.percentEncode {
			result = appendPercentEncoded(result, value.Plain)
		} else {
			result = append(result, value.Plain...)
		}
	}
	return result, nil
}

func appendPercentEncoded(destination, value []byte) []byte {
	const hexUpper = "0123456789ABCDEF"
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '.' || character == '_' || character == '~' {
			destination = append(destination, character)
			continue
		}
		destination = append(destination, '%', hexUpper[character>>4], hexUpper[character&0x0f])
	}
	return destination
}
