package probe

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probetemplate"
)

// fixedTime 是所有用例共用的 TIMESTAMP 输入。
//
// 写死而不是 time.Now()：渲染结果要能逐字节断言，而一个会走的时钟
// 让「渲染对不对」变成「这次跑得多快」。
var fixedTime = time.Date(2026, 8, 20, 12, 34, 56, 789_000_000, time.UTC)

func testValues() TemplateValues {
	return TemplateValues{
		UpstreamAPIKey: probetemplate.ResolvedValue{Plain: []byte("sk-up-key"), Revision: 3},
		UpstreamModel:  probetemplate.ResolvedValue{Plain: []byte("claude-3-5-haiku"), Revision: 4},
		ModelName:      probetemplate.ResolvedValue{Plain: []byte("haiku"), Revision: 5},
		ProbePrompt:    probetemplate.ResolvedValue{Plain: []byte("1+1=?"), Revision: 6},
		SessionID:      probetemplate.ResolvedValue{Plain: []byte("sess-abc"), Revision: 7},
		Timestamp:      fixedTime,
		Secrets: map[string]probetemplate.ResolvedValue{
			"tenant": {Plain: []byte("tenant-42"), Revision: 9},
		},
	}
}

// 六个内置占位符都必须能解析出来。
//
// 这条钉的是一个真实的分工缺口：URL 侧的 outbound.Values 刻意只支持
// UPSTREAM_API_KEY 与 SECRET:（模型名与 prompt 属于 body 模板，混进 URL
// 解析器只会让「谁提供什么」变模糊）。而 Recipe 渲染要的是全部六个 ——
// 少一个，一个合法的内置占位符就会在编译期通过、渲染期报「不支持」，
// 而那是配置存进去之后才发现的失败。
func TestTemplateValues_ResolvesEveryBuiltInPlaceholder(t *testing.T) {
	values := testValues()

	cases := []struct {
		placeholder string
		want        string
		revision    int64
	}{
		{"UPSTREAM_API_KEY", "sk-up-key", 3},
		{"UPSTREAM_MODEL", "claude-3-5-haiku", 4},
		{"MODEL_NAME", "haiku", 5},
		{"PROBE_PROMPT", "1+1=?", 6},
		{"SESSION_ID", "sess-abc", 7},
		{"SECRET:tenant", "tenant-42", 9},
	}
	for _, testCase := range cases {
		t.Run(testCase.placeholder, func(t *testing.T) {
			got, err := values.ResolveValue(context.Background(), testCase.placeholder)
			if err != nil {
				t.Fatalf("解析 %s 失败: %v", testCase.placeholder, err)
			}
			if string(got.Plain) != testCase.want {
				t.Errorf("%s want %q got %q", testCase.placeholder, testCase.want, got.Plain)
			}
			// revision 必须一起带出来：配置 hash 靠它判断「这份配置变了没」，
			// 恒为 0 的话改了 Secret 值也不会让 Capability 重新验证。
			if got.Revision != testCase.revision {
				t.Errorf("%s revision want %d got %d", testCase.placeholder, testCase.revision, got.Revision)
			}
		})
	}
}

// TIMESTAMP 单独一条：它不来自 ResolvedValue，而是由 time.Time 现算。
func TestTemplateValues_TimestampIsDeterministicAndRevisionless(t *testing.T) {
	values := testValues()

	got, err := values.ResolveValue(context.Background(), "TIMESTAMP")
	if err != nil {
		t.Fatalf("解析 TIMESTAMP 失败: %v", err)
	}
	// RFC3339 而不是 Unix 秒：它进的是 body 模板，而上游按 JSON 读它。
	// 毫秒精度足够，纳秒只是让同一次探活的两个占位符看起来不同。
	if want := "2026-08-20T12:34:56Z"; string(got.Plain) != want {
		t.Errorf("TIMESTAMP want %q got %q", want, got.Plain)
	}
	// 时间不是配置，没有 revision。给它一个非零值会让配置 hash
	// 每秒都变，于是 Capability 永远处于「配置变了要重验」。
	if got.Revision != 0 {
		t.Errorf("TIMESTAMP 不该有 revision，得到 %d", got.Revision)
	}
}

// 零值 Timestamp 必须失败，不能静默渲染成 0001-01-01。
//
// 那个日期是个合法的 RFC3339 串，上游会照收，于是「忘了装配时间」
// 变成一个发得出去、但内容荒谬的请求 —— 而它不报错。
func TestTemplateValues_ZeroTimestampFailsInsteadOfRenderingYearOne(t *testing.T) {
	values := testValues()
	values.Timestamp = time.Time{}

	if _, err := values.ResolveValue(context.Background(), "TIMESTAMP"); err == nil {
		t.Fatal("未装配 Timestamp 时必须报错，静默渲染成 0001-01-01 会发出一个内容荒谬的请求")
	}
}

// 未装配的内置占位符要报错，且**不能**渲染成空串。
//
// 空串是最坏的失败方式：`"model":""` 会被上游拒绝并回一个含义完全不同的
// 错误（通常是 400 参数错误），于是排查方向从「模型名没传进来」
// 变成「这个站不支持这个模型」。
func TestTemplateValues_MissingBuiltInFailsInsteadOfEmpty(t *testing.T) {
	cases := []struct {
		placeholder string
		blank       func(*TemplateValues)
	}{
		{"UPSTREAM_API_KEY", func(v *TemplateValues) { v.UpstreamAPIKey = probetemplate.ResolvedValue{} }},
		{"UPSTREAM_MODEL", func(v *TemplateValues) { v.UpstreamModel = probetemplate.ResolvedValue{} }},
		{"MODEL_NAME", func(v *TemplateValues) { v.ModelName = probetemplate.ResolvedValue{} }},
		{"PROBE_PROMPT", func(v *TemplateValues) { v.ProbePrompt = probetemplate.ResolvedValue{} }},
		{"SESSION_ID", func(v *TemplateValues) { v.SessionID = probetemplate.ResolvedValue{} }},
	}
	for _, testCase := range cases {
		t.Run(testCase.placeholder, func(t *testing.T) {
			values := testValues()
			testCase.blank(&values)

			got, err := values.ResolveValue(context.Background(), testCase.placeholder)
			if err == nil {
				t.Fatalf("%s 未装配时必须报错，得到 %q", testCase.placeholder, got.Plain)
			}
			if !errors.Is(err, ErrTemplateValue) {
				t.Errorf("应能识别为模板值缺失，得到 %v", err)
			}
		})
	}
}

// 未知占位符必须拒绝。
//
// 编译期已有白名单（probetemplate.validatePlaceholder），这里是第二道：
// 装配侧漏一个内置占位符时，症状必须是「报错」而不是「渲染成空」。
func TestTemplateValues_RejectsUnknownPlaceholder(t *testing.T) {
	values := testValues()

	for _, name := range []string{"UNKNOWN", "", "secret:tenant", "SECRET", "session_id"} {
		t.Run("占位符/"+name, func(t *testing.T) {
			if _, err := values.ResolveValue(context.Background(), name); err == nil {
				t.Errorf("占位符 %q 应被拒绝", name)
			}
		})
	}
}

// 缺失的 Secret 报错，且错误文本里**不能**有任何 Secret 明文。
//
// 这条错误会流进 route_health.last_error（落库）并显示在管理界面上。
func TestTemplateValues_MissingSecretFailsWithoutLeakingPlaintext(t *testing.T) {
	values := testValues()

	_, err := values.ResolveValue(context.Background(), "SECRET:absent")
	if err == nil {
		t.Fatal("未装配的 Secret 必须报错")
	}
	if !strings.Contains(err.Error(), "absent") {
		t.Errorf("错误应指名是哪个 Secret（否则无法排查），得到 %v", err)
	}
	// 已装配的那个 Secret 的明文绝不能出现在错误里。
	if strings.Contains(err.Error(), "tenant-42") {
		t.Errorf("错误文本泄漏了 Secret 明文: %v", err)
	}
}

// 渲染出的值不与调用方共享底层数组。
//
// 共享的话，调用方（或 probetemplate 的缓存）改一个字节就会改掉这份
// 装配好的值，而下一次渲染会用被改过的值 —— 表现为「偶发的认证失败」。
func TestTemplateValues_ResolvedPlainIsNotAliased(t *testing.T) {
	values := testValues()

	first, err := values.ResolveValue(context.Background(), "UPSTREAM_API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	first.Plain[0] = 'X'

	second, err := values.ResolveValue(context.Background(), "UPSTREAM_API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if string(second.Plain) != "sk-up-key" {
		t.Errorf("第二次解析被第一次的改动污染，得到 %q", second.Plain)
	}
}

// 端到端：六个占位符在 header、query、body 三个位置都渲染正确。
//
// 分位置测是因为三者的转义规则不同 —— query 侧逐字节 percent-encode，
// header 与 body 原样。同一个值在三处给出不同结果正是「query 侧 401
// 而 header 侧正常」这类问题的来源，而那时排查方向完全是错的。
func TestTemplateValues_RendersInHeaderQueryAndBody(t *testing.T) {
	compiled, err := probetemplate.CompileContent(model.EndpointMessages, probetemplate.TemplateContent{
		Method:   "POST",
		RawQuery: "key={{UPSTREAM_API_KEY}}&tenant={{SECRET:tenant}}",
		Headers: []model.HeaderTemplate{
			{Name: "X-Session", Values: []string{"{{SESSION_ID}}"}},
			{Name: "X-Model", Values: []string{"{{UPSTREAM_MODEL}}"}},
		},
		Body: []byte(`{"model":"{{MODEL_NAME}}","prompt":"{{PROBE_PROMPT}}","at":"{{TIMESTAMP}}"}`),
	})
	if err != nil {
		t.Fatalf("编译模板失败: %v", err)
	}

	rendered, err := compiled.Render(context.Background(), testValues())
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}

	if want := "key=sk-up-key&tenant=tenant-42"; rendered.RawQuery != want {
		t.Errorf("query want %q got %q", want, rendered.RawQuery)
	}
	if got := rendered.Header.Get("X-Session"); got != "sess-abc" {
		t.Errorf("X-Session want sess-abc got %q", got)
	}
	if got := rendered.Header.Get("X-Model"); got != "claude-3-5-haiku" {
		t.Errorf("X-Model want claude-3-5-haiku got %q", got)
	}
	wantBody := `{"model":"haiku","prompt":"1+1=?","at":"2026-08-20T12:34:56Z"}`
	if string(rendered.Body) != wantBody {
		t.Errorf("body want %q got %q", wantBody, rendered.Body)
	}
}

// query 侧的 Secret 必须逐字节 percent-encode。
//
// 不编码的话，一个含 & 或 = 的 Secret 会把自己拆成两个 query 参数 ——
// 上游收到的 key 是截断的，而请求看起来完全正常。
func TestTemplateValues_QuerySecretIsPercentEncoded(t *testing.T) {
	values := testValues()
	values.Secrets = map[string]probetemplate.ResolvedValue{
		"tenant": {Plain: []byte("a&b=c/d"), Revision: 9},
	}

	compiled, err := probetemplate.CompileContent(model.EndpointModels, probetemplate.TemplateContent{
		Method:   "GET",
		RawQuery: "tenant={{SECRET:tenant}}",
	})
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	rendered, err := compiled.Render(context.Background(), values)
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	if want := "tenant=a%26b%3Dc%2Fd"; rendered.RawQuery != want {
		t.Errorf("query 侧 Secret 必须 percent-encode，want %q got %q", want, rendered.RawQuery)
	}
}

// Secret 必须先通过 snapshot ref 校验才能降为普通值（§4.5）。
//
// 规格原文：「Probe 装配 TemplateValues 时先要求 ResolvedSecret.ID 等于
// snapshot ref 的 BoundSecretID 且 revision current，通过后才降为普通
// ResolvedValue 交给 Compile/Render；同名新 Secret 绝不自动满足旧 ref。」
//
// 为什么这条是安全边界而不是洁癖：删掉一个 Secret 再建一个同名的，
// 拿到的是不同的 ID。若按名字匹配就放行，那个 Recipe 会静默改用
// 一份**没人审核过**的凭据 —— 而它发出去的请求看起来完全正常。
func TestBindSecrets_RejectsSameNameDifferentSecretID(t *testing.T) {
	refs := []model.RequiredSecretRef{{Name: "tenant", BoundSecretID: 11}}

	resolved := map[string]probetemplate.ResolvedSecret{
		// 同名，但 ID 变了 —— 旧 Secret 被删、同名新建的情形。
		"tenant": {ID: 99, Plain: []byte("brand-new"), Revision: 1},
	}

	if _, err := BindSecrets(refs, resolved); err == nil {
		t.Fatal("同名但 secret_id 不同必须拒绝：那份凭据没有被这个 Recipe 审核过")
	}
}

func TestBindSecrets_AcceptsMatchingRefAndStripsSecretIdentity(t *testing.T) {
	refs := []model.RequiredSecretRef{{Name: "tenant", BoundSecretID: 11}}
	resolved := map[string]probetemplate.ResolvedSecret{
		"tenant": {ID: 11, Plain: []byte("tenant-42"), Revision: 9},
	}

	bound, err := BindSecrets(refs, resolved)
	if err != nil {
		t.Fatalf("ref 与 resolved 一致时应通过: %v", err)
	}
	value, ok := bound["tenant"]
	if !ok {
		t.Fatal("应含 tenant")
	}
	if string(value.Plain) != "tenant-42" || value.Revision != 9 {
		t.Errorf("绑定后的值不对: %q@%d", value.Plain, value.Revision)
	}
}

// 缺失与多余都要拒绝。
//
// 多余同样是错的：模板没引用的 Secret 出现在装配里，说明调用方拿的
// ref 清单与实际编译出的模板不是同一份 —— 而那意味着其中一份是过期的。
func TestBindSecrets_RejectsMissingAndExtraneous(t *testing.T) {
	refs := []model.RequiredSecretRef{{Name: "tenant", BoundSecretID: 11}}

	t.Run("缺失", func(t *testing.T) {
		if _, err := BindSecrets(refs, map[string]probetemplate.ResolvedSecret{}); err == nil {
			t.Error("ref 要求的 Secret 没解析出来时必须拒绝")
		}
	})

	t.Run("多余", func(t *testing.T) {
		resolved := map[string]probetemplate.ResolvedSecret{
			"tenant": {ID: 11, Plain: []byte("ok"), Revision: 9},
			"extra":  {ID: 12, Plain: []byte("nope"), Revision: 1},
		}
		if _, err := BindSecrets(refs, resolved); err == nil {
			t.Error("解析出模板没引用的 Secret 时必须拒绝：两份清单不同源")
		}
	})
}
