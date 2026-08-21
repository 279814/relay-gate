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

		// header **名**里的 CR/LF。值那一侧上面已有用例，名这一侧原先没有 ——
		// 而名里的换行同样是请求头注入：`X-A\r\nAuthorization` 会被拆成两个头。
		{"header name newline", TemplateContent{Method: "POST",
			Headers: []model.HeaderTemplate{{Name: "X-A\r\nAuthorization", Values: []string{"v"}}}}},
		{"header name carriage return", TemplateContent{Method: "POST",
			Headers: []model.HeaderTemplate{{Name: "X-A\rB", Values: []string{"v"}}}}},
		{"header name space", TemplateContent{Method: "POST",
			Headers: []model.HeaderTemplate{{Name: "X A", Values: []string{"v"}}}}},
		{"header name colon", TemplateContent{Method: "POST",
			Headers: []model.HeaderTemplate{{Name: "X:A", Values: []string{"v"}}}}},
		{"empty header name", TemplateContent{Method: "POST",
			Headers: []model.HeaderTemplate{{Name: "", Values: []string{"v"}}}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ScanRequiredSecrets(model.EndpointMessages, tc.content); !errors.Is(err, model.ErrValidation) {
				t.Fatalf("error = %v, want validation", err)
			}
		})
	}
}

// 逐跳头必须在编译期拒绝（P0-05 第 6 条）。
//
// 原先只硬编码拒了四个名字（Content-Length / Transfer-Encoding / Connection /
// Host），漏掉 Keep-Alive、Upgrade、TE、Trailer、Proxy-Authorization 五个。
// 放它们进 Recipe 的后果是：模板声明了一个头，而传输层按 RFC 7230 §6.1
// 把它删掉 —— 配置写了、请求里没有，且这个差异不报错。
//
// 关于「Connection 声明的头」：模板没有这个手段。Connection 本身被无条件
// 拒绝，所以无论它排在自定义头前面还是后面，编译都先在它那一项上失败。
// 下面两条用例钉的正是这一点 —— 拒绝理由必须是 Connection 自己，
// 而不需要再去解析它声明了什么（那样写出来的分支不可达）。
func TestCompileRejectsEveryHopByHopHeader(t *testing.T) {
	tests := []struct {
		name    string
		headers []model.HeaderTemplate
	}{
		{
			name: "connection before custom header",
			headers: []model.HeaderTemplate{
				{Name: "Connection", Values: []string{"X-Custom"}},
				{Name: "X-Custom", Values: []string{"v"}},
			},
		},
		{
			// 顺序反过来同样要拒：判定不该依赖头在列表里的位置。
			name: "connection after custom header",
			headers: []model.HeaderTemplate{
				{Name: "X-Custom", Values: []string{"v"}},
				{Name: "Connection", Values: []string{"keep-alive, X-Custom"}},
			},
		},
		{name: "keep-alive", headers: []model.HeaderTemplate{{Name: "Keep-Alive", Values: []string{"timeout=5"}}}},
		{name: "upgrade", headers: []model.HeaderTemplate{{Name: "Upgrade", Values: []string{"websocket"}}}},
		{name: "proxy-authorization", headers: []model.HeaderTemplate{{Name: "Proxy-Authorization", Values: []string{"Basic x"}}}},
		{name: "proxy-authenticate", headers: []model.HeaderTemplate{{Name: "Proxy-Authenticate", Values: []string{"Basic"}}}},
		{name: "te", headers: []model.HeaderTemplate{{Name: "TE", Values: []string{"trailers"}}}},
		{name: "trailer", headers: []model.HeaderTemplate{{Name: "Trailer", Values: []string{"Expires"}}}},
		{name: "transfer-encoding", headers: []model.HeaderTemplate{{Name: "Transfer-Encoding", Values: []string{"chunked"}}}},
		// 大小写不敏感：头名在 HTTP/1.1 里就是大小写不敏感的，
		// 按原样比较等于留一个只要改个大小写就能绕过的门。
		{name: "lowercase keep-alive", headers: []model.HeaderTemplate{{Name: "keep-alive", Values: []string{"x"}}}},
		{name: "mixed case upgrade", headers: []model.HeaderTemplate{{Name: "UpGrAdE", Values: []string{"x"}}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			content := TemplateContent{Method: "POST", Headers: tc.headers}
			if _, err := ScanRequiredSecrets(model.EndpointMessages, content); !errors.Is(err, model.ErrValidation) {
				t.Fatalf("error = %v, want validation", err)
			}
		})
	}
}

// 逐跳头清单必须与转发路径同源。
//
// 两处各抄一份必然分叉，而分叉的那一半是「看起来在防、实际没防」——
// 这条断言让「有人只在其中一处加了新逐跳头」直接红掉。
func TestHopByHopListIsSharedWithForwardPath(t *testing.T) {
	for _, name := range model.HopByHopHeaders {
		if !model.IsHopByHopHeader(name) {
			t.Errorf("IsHopByHopHeader 不认自己清单里的 %q", name)
		}
		content := TemplateContent{Method: "POST",
			Headers: []model.HeaderTemplate{{Name: name, Values: []string{"v"}}}}
		if _, err := ScanRequiredSecrets(model.EndpointMessages, content); !errors.Is(err, model.ErrValidation) {
			t.Errorf("逐跳头 %q 应被 recipe 编译拒绝，得到 %v", name, err)
		}
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
