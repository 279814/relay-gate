package probetemplate

import (
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

// fuzzTemplateInput 是一次编译要喂的全部模板字段。
//
// 只 fuzz body 不够：RawQuery 与 Headers 各有自己的解析规则（query 要求占位符
// 占满整个参数值、header 名与值各有一套字符白名单），而 §4.5 第 13 条要的是
// 「任意模板不 panic、错误不含输入 Secret」—— 「任意模板」包含这三个字段。
// 只喂 body 的话，query 与 header 那两条解析路径在 fuzz 里从未被走到。
type fuzzTemplateInput struct {
	endpoint    model.EndpointKind
	method      string
	rawQuery    string
	headerName  string
	headerValue string
	body        []byte
}

// fuzzTemplateFrom 把 fuzz 给的原始字节摊成一次编译的输入。
//
// selector 决定 endpoint 与 method：写死 messages+POST 会让 models 的
// 「只允许 GET/HEAD」「GET 不能带 body」两条分支永远走不到，而那两条正是
// 编译期唯一会因 endpoint 而分叉的地方。
func fuzzTemplateFrom(selector int, rawQuery, headerName, headerValue string, body []byte) fuzzTemplateInput {
	if selector < 0 {
		selector = -selector
	}
	endpoints := []model.EndpointKind{
		model.EndpointMessages,
		model.EndpointModels,
		model.EndpointResponses,
		model.EndpointChatCompletions,
		model.EndpointCountTokens,
	}
	methods := []string{"POST", "GET", "HEAD", "post", "PATCH", ""}
	return fuzzTemplateInput{
		endpoint:    endpoints[selector%len(endpoints)],
		method:      methods[(selector/len(endpoints))%len(methods)],
		rawQuery:    rawQuery,
		headerName:  headerName,
		headerValue: headerValue,
		body:        body,
	}
}

func (input fuzzTemplateInput) content() TemplateContent {
	content := TemplateContent{
		Method:   input.method,
		RawQuery: input.rawQuery,
		Body:     input.body,
	}
	if input.headerName != "" || input.headerValue != "" {
		content.Headers = []model.HeaderTemplate{{
			Name:   input.headerName,
			Values: []string{input.headerValue},
		}}
	}
	return content
}

func FuzzCompileTemplateNeverPanics(f *testing.F) {
	seeds := []struct {
		selector    int
		rawQuery    string
		headerName  string
		headerValue string
		body        []byte
	}{
		{0, "", "", "", []byte(`{"model":"{{UPSTREAM_MODEL}}"}`)},
		{0, "", "", "", []byte(`{{SECRET:tenant}}`)},
		{0, "", "", "", []byte(`{{{{literal`)},
		{0, "", "", "", []byte{0, 0xff, '{', '{', 'X', '}', '}'}},
		{0, "beta=true&key={{SECRET:tenant}}", "X-Probe", "cc/{{SESSION_ID}}", []byte(`{}`)},
		{1, "key={{UPSTREAM_API_KEY}}", "anthropic-beta", "context-1m-2025-08-07", nil},
		{0, "a={{SECRET:x}}b", "Authorization", "Bearer {{UPSTREAM_API_KEY}}", []byte(`{}`)},
		{0, "=", "X-A\r\nAuthorization", "v", []byte(`{{SECRET:}}`)},
		{2, "{{SECRET:name}}=v", "Host", "example.com", []byte(`{{UNKNOWN}}`)},
	}
	for _, seed := range seeds {
		f.Add(seed.selector, seed.rawQuery, seed.headerName, seed.headerValue, seed.body)
	}

	f.Fuzz(func(t *testing.T, selector int, rawQuery, headerName, headerValue string, body []byte) {
		input := fuzzTemplateFrom(selector, rawQuery, headerName, headerValue, body)
		compiled, err := CompileContent(input.endpoint, input.content())
		if err != nil {
			// §4.5 第 13 条：错误文本不能包含输入 Secret。编译器不知道哪段字节
			// 是 Secret，所以唯一可守的规则是「一个字节都不回显」—— 把任意一段
			// 输入抄进错误里，那段就可能是凭据，而校验错误会进 API 响应与日志。
			assertErrorQuotesNoInput(t, err, input)
			return
		}
		for _, name := range compiled.RequiredSecrets() {
			if !validSecretName(name) {
				t.Fatalf("compiler returned invalid secret name %q", name)
			}
		}
	})
}

// assertErrorQuotesNoInput 检查错误文本没有回显输入里的可疑片段。
//
// 判据是「输入里长度足够的不透明串是否原样出现在错误里」而不是逐字节比对：
// 错误文本合法地包含 endpoint 名、method 名和固定说明文字，而这些可能与输入
// 恰好相同（一个 method 为 "POST" 的输入，错误里当然会出现 POST）。
// 真正要挡的是「用户写的任意串被抄进错误」，那种串在输入里的形态就是不透明段。
//
// 系统常量要排除掉。fuzz 实测逮到过这个假阳性：错误合法地列出内置占位符清单，
// 而一个写了 `{{UPSTREAM_TYPO}}` 的输入含 "UPSTREAM"，于是判据误报。
// 那不是回显 —— 那段字节来自 builtInPlaceholders 而不是来自输入，
// 而且它是系统的公开常量，本来就不可能是凭据。
func assertErrorQuotesNoInput(t *testing.T, err error, input fuzzTemplateInput) {
	t.Helper()
	message := err.Error()
	for _, field := range []string{input.rawQuery, input.headerValue, string(input.body)} {
		for _, candidate := range opaqueRuns(field) {
			if strings.Contains(systemVocabulary(), candidate) {
				continue
			}
			if strings.Contains(message, candidate) {
				t.Fatalf("error text echoes template input %q: %s", candidate, message)
			}
		}
	}
}

// systemVocabulary 是错误消息允许包含的系统常量。
//
// 内置占位符名与凭据前缀都是公开的固定清单，不是用户数据；错误消息要告诉
// 用户「可选值是哪些」「命中了哪个已知前缀」就必须能提到它们。
func systemVocabulary() string {
	return strings.Join(builtInPlaceholderNames(), " ") + " " + strings.Join(credentialPrefixes, " ")
}

// opaqueRuns 取出输入里「够长的不透明串」，也就是凭据在输入里的形态。
//
// 门槛取 8：比 credential.go 的 minOpaqueTail（12）更严，因为这里要挡的不止
// 已知前缀的凭据，还有任何被抄进错误的用户串；而短于 8 的片段与错误文本里的
// 固定词（endpoint 名、"POST"、"query"）无法区分，比对它们只会得到假阳性。
func opaqueRuns(value string) []string {
	const minRun = 8
	var runs []string
	start := -1
	for index := 0; index <= len(value); index++ {
		if index < len(value) && isOpaqueByte(value[index]) {
			if start < 0 {
				start = index
			}
			continue
		}
		if start >= 0 && index-start >= minRun {
			runs = append(runs, value[start:index])
		}
		start = -1
	}
	return runs
}

// 未知占位符的错误不能回显占位符名。
//
// `{{glpat-ZZZZ…}}` 编译不过，而原先的错误是「未知占位符 "glpat-ZZZZ…"」——
// 于是一个把凭据误写成占位符的用户，那份凭据会进 API 响应和日志。
//
// 用**不在白名单里**的厂商前缀是关键。写 `sk-ant-` 时凭据门禁
// （credential.go 的 credentialPrefixes）会先在编译入口拦下，于是「不回显」
// 是因为**另一个原因**成立的，这条断言等于没测到。而门禁只认 10 个已知前缀，
// 任何别的厂商（GitLab、自建中转站、企业网关）的 key 都直接走到这里 ——
// 那才是 §4.5 第 13 条真正没被守住的那条路。
func TestUnknownPlaceholderErrorDoesNotEchoTheName(t *testing.T) {
	credential := "glpat-" + strings.Repeat("Z", 24)
	_, err := CompileContent(model.EndpointMessages, TemplateContent{
		Method: "POST",
		Body:   []byte("{{" + credential + "}}"),
	})
	if err == nil {
		t.Fatal("compile accepted an unknown placeholder")
	}
	if strings.Contains(err.Error(), credential) {
		t.Fatalf("error echoes the placeholder name: %s", err)
	}
}

// Secret 名无效的错误同样不能回显。
//
// 与上面是两条独立分支：`{{SECRET:<非法字符>}}` 走的是 validSecretName 那条。
func TestInvalidSecretNameErrorDoesNotEchoTheName(t *testing.T) {
	credential := "glpat-" + strings.Repeat("Y", 24) + "/slash"
	_, err := CompileContent(model.EndpointMessages, TemplateContent{
		Method: "POST",
		Body:   []byte("{{SECRET:" + credential + "}}"),
	})
	if err == nil {
		t.Fatal("compile accepted an invalid secret name")
	}
	if strings.Contains(err.Error(), credential) {
		t.Fatalf("error echoes the secret name: %s", err)
	}
}

// header 名与 query 参数名的错误也不能回显。
//
// 这两处回显的风险低于占位符名（凭据通常在值里而不是名里），但「不回显输入」
// 要成为一条可依赖的规则就不能有例外 —— 有例外的话，下一个人加校验时无法
// 从既有代码判断该不该回显。
func TestNameValidationErrorsDoNotEchoInput(t *testing.T) {
	suspicious := "glpat-" + strings.Repeat("X", 24)
	tests := []struct {
		name    string
		content TemplateContent
	}{
		{"header name", TemplateContent{
			Method:  "POST",
			Headers: []model.HeaderTemplate{{Name: suspicious + " bad", Values: []string{"v"}}},
		}},
		{"query parameter name", TemplateContent{
			Method:   "POST",
			RawQuery: suspicious + "=prefix{{SECRET:key}}",
		}},
		// 凭据门禁跑在 validHeaderName **之前**，所以它拿到的 header 名是
		// 未经校验的原始输入。回显它等于「值里的凭据被拒绝时，把名字里的
		// 另一份凭据抄进日志」—— 而一份被误配成 header 名的 key 恰恰会走这条路。
		{"credential gate header name", TemplateContent{
			Method: "POST",
			Headers: []model.HeaderTemplate{{
				Name:   suspicious,
				Values: []string{"sk-ant-" + strings.Repeat("A", 24)},
			}},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileContent(model.EndpointMessages, tc.content)
			if err == nil {
				t.Fatal("compile accepted invalid content")
			}
			if strings.Contains(err.Error(), suspicious) {
				t.Fatalf("error echoes input: %s", err)
			}
		})
	}
}

// 认证头的名字在错误里必须仍然可辨认。
//
// 与上面几条不是矛盾而是边界：`Authorization` / `x-api-key` 是**固定清单**
// （model.AuthHeaders）里的常量，不是游散输入，而这条错误的全部价值就是告诉
// 用户「哪个认证头要改成占位符」。一并脱敏的话，配了三个头的用户不知道改哪个。
func TestAuthHeaderRejectionStillNamesTheKnownHeader(t *testing.T) {
	_, err := CompileContent(model.EndpointMessages, TemplateContent{
		Method: "POST",
		Headers: []model.HeaderTemplate{{
			Name:   "Authorization",
			Values: []string{"Bearer " + strings.Repeat("k", 40)},
		}},
	})
	if err == nil {
		t.Fatal("compile accepted a literal credential in an auth header")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "authorization") {
		t.Fatalf("error does not name the auth header: %s", err)
	}
}
