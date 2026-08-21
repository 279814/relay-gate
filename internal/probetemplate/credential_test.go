package probetemplate

import (
	"errors"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

// 认证头里的字面值必须拒绝，只接受占位符（§4.5）。
//
// 这是三条写入路径（管理 API、learner、migration）共用的那道门禁。没有它，
// 一个 Recipe 可以把 `Authorization: sk-ant-xxx` 明文存进 probe_recipe_version，
// 而那张表是**不可变**的（0002 的 no_update/no_delete 触发器）—— 明文一旦
// 落进去就删不掉，只能整行留着。而 Upstream 的 api_key 是加密存的，
// 让 Recipe 开一个明文旁路等于把加密存储绕过去。
func TestScanRejectsLiteralCredentialsInAuthHeaders(t *testing.T) {
	for _, name := range model.AuthHeaders {
		t.Run(name, func(t *testing.T) {
			content := TemplateContent{Method: "POST", Headers: []model.HeaderTemplate{
				{Name: name, Values: []string{"sk-ant-api03-literal-value"}},
			}}
			_, err := ScanRequiredSecrets(model.EndpointMessages, content)
			if !errors.Is(err, model.ErrValidation) {
				t.Fatalf("认证头 %q 的字面值必须拒绝，得到 %v", name, err)
			}
			// 错误里绝不能回显命中的原值：这条错误会进 API 响应与日志。
			if strings.Contains(err.Error(), "sk-ant-api03-literal-value") {
				t.Errorf("错误文本回显了凭据原值: %v", err)
			}
		})
	}
}

// 认证头用占位符则放行 —— 这正是规格要求用户改成的写法。
func TestScanAcceptsPlaceholdersInAuthHeaders(t *testing.T) {
	cases := []string{
		"{{UPSTREAM_API_KEY}}",
		"Bearer {{UPSTREAM_API_KEY}}",
		"{{SECRET:tenant}}",
		"Bearer {{SECRET:tenant}}",
	}
	for _, value := range cases {
		t.Run(value, func(t *testing.T) {
			content := TemplateContent{Method: "POST", Headers: []model.HeaderTemplate{
				{Name: "Authorization", Values: []string{value}},
			}}
			if _, err := ScanRequiredSecrets(model.EndpointMessages, content); err != nil {
				t.Fatalf("占位符写法必须放行，得到 %v", err)
			}
		})
	}
}

// 高置信凭据前缀在**任何**位置都要拒，不只认证头。
//
// query 与 body 同样能携带 key（§3.2 提到少数站接受 ?key=<key>，
// OpenAI 兼容端点允许 key 在 body 里）。只查认证头等于留两个明文旁路。
func TestScanRejectsHighConfidenceCredentialsAnywhere(t *testing.T) {
	const key = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	cases := []struct {
		name    string
		content TemplateContent
	}{
		{"body", TemplateContent{Method: "POST", Body: []byte(`{"key":"` + key + `"}`)}},
		{"query", TemplateContent{Method: "POST", RawQuery: "key=" + key}},
		{"普通头的值", TemplateContent{Method: "POST", Headers: []model.HeaderTemplate{
			{Name: "X-Custom", Values: []string{key}}}}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := ScanRequiredSecrets(model.EndpointMessages, testCase.content)
			if !errors.Is(err, model.ErrValidation) {
				t.Fatalf("高置信凭据在 %s 里必须拒绝，得到 %v", testCase.name, err)
			}
			if strings.Contains(err.Error(), key) {
				t.Errorf("错误文本回显了凭据原值: %v", err)
			}
		})
	}
}

// 普通提示词与结构常量必须放行（§4.5 明文要求）。
//
// 这条与上面几条一样重要：一个把正常模板判成凭据的扫描器会让用户无法
// 保存合法配置，而规格明确说「不提供跳过扫描开关」—— 也就是说误报
// 没有逃生舱，只能靠扫描器本身足够准。
func TestScanAcceptsOrdinaryPromptsAndStructuralConstants(t *testing.T) {
	cases := []struct {
		name    string
		content TemplateContent
	}{
		{"最小探活 body", TemplateContent{Method: "POST",
			Body: []byte(`{"model":"claude-3-5-haiku","max_tokens":1,"stream":true,` +
				`"messages":[{"role":"user","content":"1+1=?"}]}`)}},
		{"真实 Claude Code 头", TemplateContent{Method: "POST", Headers: []model.HeaderTemplate{
			{Name: "user-agent", Values: []string{"claude-cli/2.1.220 (external, sdk-cli)"}},
			{Name: "anthropic-version", Values: []string{"2023-06-01"}},
			{Name: "anthropic-beta", Values: []string{
				"claude-code-20250219,interleaved-thinking-2025-05-14,thinking-token-count-2026-05-13"}},
			{Name: "x-stainless-package-version", Values: []string{"0.70.1"}},
		}}},
		{"beta query", TemplateContent{Method: "POST", RawQuery: "beta=true"}},
		{"含 sk- 的普通散文", TemplateContent{Method: "POST",
			Body: []byte(`{"messages":[{"role":"user","content":"怎么用 sk- 开头的 key？"}]}`)}},
		{"长 base64 图片（非凭据形状）", TemplateContent{Method: "POST",
			Body: []byte(`{"type":"image","data":"` + strings.Repeat("iVBORw0KGgo", 40) + `"}`)}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := ScanRequiredSecrets(model.EndpointMessages, testCase.content); err != nil {
				t.Fatalf("合法模板被误判成凭据（规格不提供跳过开关，误报无逃生舱）: %v", err)
			}
		})
	}
}

// 认证头里的 Bearer 前缀本身不算凭据，但后面跟字面值就算。
//
// 分清这两者是必要的：`Bearer {{UPSTREAM_API_KEY}}` 是规格推荐的写法，
// 而 `Bearer sk-xxx` 是要拒的。只看「有没有 Bearer」两者都会放行。
func TestScanDistinguishesBearerPrefixFromLiteralCredential(t *testing.T) {
	t.Run("仅 scheme 无值", func(t *testing.T) {
		content := TemplateContent{Method: "POST", Headers: []model.HeaderTemplate{
			{Name: "Authorization", Values: []string{"Bearer {{SECRET:k}}"}}}}
		if _, err := ScanRequiredSecrets(model.EndpointMessages, content); err != nil {
			t.Errorf("Bearer + 占位符应放行: %v", err)
		}
	})
	t.Run("scheme 后跟字面值", func(t *testing.T) {
		content := TemplateContent{Method: "POST", Headers: []model.HeaderTemplate{
			{Name: "Authorization", Values: []string{"Bearer abcdefghijklmnop"}}}}
		if _, err := ScanRequiredSecrets(model.EndpointMessages, content); !errors.Is(err, model.ErrValidation) {
			t.Errorf("Bearer + 字面值必须拒绝，得到 %v", err)
		}
	})
}

// 占位符后面拼字面凭据必须拒绝。
//
// 这是「整体是一个占位符」那条判据的漏洞：原判据用
// HasPrefix("{{") && HasSuffix("}}") && Count("{{")==1 认定「整体」，
// 而 `{{UPSTREAM_API_KEY}}sk-ant-AAAAAAAAAAAA}}` 三条全满足 —— 它以 {{ 开头、
// 以 }} 结尾、只含一个 {{，中间那段明文凭据却整个溜了过去。
//
// 后果与门禁完全失守等价：认证头明文进 probe_recipe_version，而那张表
// 不可变（0002 的 no_update/no_delete 触发器），落进去就删不掉。
func TestScanRejectsLiteralCredentialAfterPlaceholder(t *testing.T) {
	const tail = "sk-ant-api03-AAAAAAAAAAAAAAAA"

	cases := []string{
		"{{UPSTREAM_API_KEY}}" + tail + "}}",
		"Bearer {{SECRET:a}}" + tail + "}}",
		"{{SECRET:a}}-" + tail + "}}",
	}
	for _, value := range cases {
		t.Run(value, func(t *testing.T) {
			content := TemplateContent{Method: "POST", Headers: []model.HeaderTemplate{
				{Name: "Authorization", Values: []string{value}}}}
			_, err := ScanRequiredSecrets(model.EndpointMessages, content)
			if !errors.Is(err, model.ErrValidation) {
				t.Fatalf("占位符后拼字面凭据必须拒绝，得到 %v", err)
			}
			if strings.Contains(err.Error(), tail) {
				t.Errorf("错误文本回显了凭据原值: %v", err)
			}
		})
	}
}
