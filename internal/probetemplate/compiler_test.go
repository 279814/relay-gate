package probetemplate

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

type mapResolver map[string]ResolvedValue

func (resolver mapResolver) ResolveValue(_ context.Context, name string) (ResolvedValue, error) {
	value, ok := resolver[name]
	if !ok {
		return ResolvedValue{}, errors.New("missing value")
	}
	return value, nil
}

func TestCompileAndRenderPreservesNonPlaceholderBytes(t *testing.T) {
	body := []byte("\x00before/{{MODEL_NAME}}/middle/{{{{/after/{{SECRET:tenant}}/\xff")
	version := model.ProbeRecipeVersion{
		Method: "POST",
		Headers: []model.HeaderTemplate{
			{Name: "X-Client", Values: []string{"cc/{{SESSION_ID}}", "static"}},
		},
		Body:           body,
		TimeoutProfile: model.TimeoutL2Standard,
	}
	compiled, err := Compile(model.EndpointMessages, version)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if got, want := compiled.RequiredSecrets(), []string{"tenant"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("required secrets = %#v, want %#v", got, want)
	}

	rendered, err := compiled.Render(context.Background(), mapResolver{
		"MODEL_NAME":    {Plain: []byte("claude-opus-5"), Revision: 1},
		"SESSION_ID":    {Plain: []byte("session-7"), Revision: 2},
		"SECRET:tenant": {Plain: []byte("tenant-secret"), Revision: 3},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	wantBody := []byte("\x00before/claude-opus-5/middle/{{/after/tenant-secret/\xff")
	if !reflect.DeepEqual(rendered.Body, wantBody) {
		t.Fatalf("body = %q, want %q", rendered.Body, wantBody)
	}
	if got := rendered.Header.Values("X-Client"); !reflect.DeepEqual(got, []string{"cc/session-7", "static"}) {
		t.Fatalf("header values = %#v", got)
	}
	if rendered.Method != "POST" {
		t.Fatalf("method = %q", rendered.Method)
	}
}

func TestScanRequiredSecretsIsSortedUniqueAcrossAllTemplateFields(t *testing.T) {
	content := TemplateContent{
		Method:   "POST",
		RawQuery: "a={{SECRET:zeta}}&b={{SECRET:alpha}}",
		Headers:  []model.HeaderTemplate{{Name: "X-Probe", Values: []string{"{{SECRET:zeta}}"}}},
		Body:     []byte(`{"key":"{{SECRET:middle}}","again":"{{SECRET:alpha}}"}`),
	}
	got, err := ScanRequiredSecrets(model.EndpointMessages, content)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"alpha", "middle", "zeta"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("required secrets = %#v, want %#v", got, want)
	}
}

func TestCompileRejectsUnsafeOrAmbiguousTemplates(t *testing.T) {
	tests := []struct {
		name    string
		content TemplateContent
	}{
		{"unknown placeholder", TemplateContent{Method: "POST", Body: []byte("{{UNKNOWN}}")}},
		{"unclosed placeholder", TemplateContent{Method: "POST", Body: []byte("{{MODEL_NAME")}},
		{"empty secret name", TemplateContent{Method: "POST", Body: []byte("{{SECRET:}}")}},
		{"invalid secret name", TemplateContent{Method: "POST", Body: []byte("{{SECRET:a/b}}")}},
		{"protected content length", TemplateContent{Method: "POST", Headers: []model.HeaderTemplate{{Name: "Content-Length", Values: []string{"1"}}}}},
		{"protected host", TemplateContent{Method: "POST", Headers: []model.HeaderTemplate{{Name: "Host", Values: []string{"example.com"}}}}},
		{"constant header newline", TemplateContent{Method: "POST", Headers: []model.HeaderTemplate{{Name: "X-Test", Values: []string{"a\nb"}}}}},
		{"query placeholder in name", TemplateContent{Method: "POST", RawQuery: "{{SECRET:key}}=v"}},
		{"query placeholder mixed with literal", TemplateContent{Method: "POST", RawQuery: "key=prefix{{SECRET:key}}"}},
		{"GET with body", TemplateContent{Method: "GET", Body: []byte("x")}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ScanRequiredSecrets(model.EndpointMessages, tc.content); !errors.Is(err, model.ErrValidation) {
				t.Fatalf("error = %v, want validation", err)
			}
		})
	}
}

func TestRenderPercentEncodesWholeQueryPlaceholderByByte(t *testing.T) {
	compiled, err := compileContent(model.EndpointMessages, TemplateContent{
		Method:   "POST",
		RawQuery: "literal=keep+this&secret={{SECRET:query}}&empty=",
	})
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := compiled.Render(context.Background(), mapResolver{
		"SECRET:query": {Plain: []byte{'a', '&', '=', ' ', '%', '+', 0xff}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := rendered.RawQuery, "literal=keep+this&secret=a%26%3D%20%25%2B%FF&empty="; got != want {
		t.Fatalf("raw query = %q, want %q", got, want)
	}
}

func TestRenderRejectsControlCharactersFromResolvedValues(t *testing.T) {
	compiled, err := compileContent(model.EndpointMessages, TemplateContent{
		Method:  "POST",
		Headers: []model.HeaderTemplate{{Name: "X-Test", Values: []string{"{{SECRET:key}}"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = compiled.Render(context.Background(), mapResolver{
		"SECRET:key": {Plain: []byte("bad\r\nInjected: yes")},
	})
	if !errors.Is(err, model.ErrValidation) {
		t.Fatalf("error = %v, want validation", err)
	}
}
