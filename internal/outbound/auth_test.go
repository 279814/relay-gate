package outbound

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func authProfile(mode model.AuthMode) model.EndpointAuthProfile {
	return model.EndpointAuthProfile{Mode: mode, SecretRef: "upstream_api_key", Revision: 1}
}

func authValues(key string) Values {
	return Values{UpstreamAPIKey: []byte(key), CredentialRevision: 2}
}

// inboundHeaders 造一份「客户端送来的头」，每个认证位置都塞了 relay key。
func inboundHeaders() http.Header {
	header := http.Header{}
	header.Set("Authorization", "Bearer rk-relay-key")
	header.Set("X-Api-Key", "rk-relay-key")
	header.Set("Api-Key", "rk-relay-key")
	header.Set("User-Agent", "claude-cli/2.1.220 (external, sdk-cli)")
	return header
}

func applyAuth(t *testing.T, header http.Header, profile model.EndpointAuthProfile,
	values Values) error {

	t.Helper()
	return ApplyAuth(context.Background(), header, AuthInput{Profile: profile, Values: values})
}

// ── 先删所有别名，最终只写一种（计划第 11 条前半）─────────────

// 这条钉的是「relay key 绝不能漏给上游」。三个认证位置里漏删任何一个，
// 用户的 relay key 就直接送到了公益站 —— 不报错、不失败，只有抓包才发现。
func TestApplyAuth_RemovesEveryInboundAliasFirst(t *testing.T) {
	modes := []struct {
		mode      model.AuthMode
		wantOnly  string // 最终应存在的那一个认证头
		wantValue string
	}{
		{model.AuthModeBearer, "Authorization", "Bearer sk-up"},
		{model.AuthModeXAPIKey, "X-Api-Key", "sk-up"},
		{model.AuthModeAPIKey, "Api-Key", "sk-up"},
	}
	for _, testCase := range modes {
		t.Run(string(testCase.mode), func(t *testing.T) {
			header := inboundHeaders()
			if err := applyAuth(t, header, authProfile(testCase.mode), authValues("sk-up")); err != nil {
				t.Fatalf("ApplyAuth 失败: %v", err)
			}

			// 恰好一种 profile：别的认证位置必须为空。
			for _, name := range model.AuthHeaders {
				got := header.Get(name)
				if name == testCase.wantOnly {
					if got != testCase.wantValue {
						t.Errorf("%s want %q got %q", name, testCase.wantValue, got)
					}
					continue
				}
				if got != "" {
					t.Errorf("%s 应被删除（写了两种认证方式就是在猜，"+
						"而 relay key 残留等于把它送给上游），得到 %q", name, got)
				}
			}
			// 非认证头原样保留：出站头是黑名单而非白名单（§6.5）。
			if header.Get("User-Agent") == "" {
				t.Error("非认证头不该被 ApplyAuth 碰")
			}
		})
	}
}

// 多值的认证头必须整个删掉，不是只删第一个。
func TestApplyAuth_RemovesAllValuesOfAnAlias(t *testing.T) {
	header := http.Header{}
	header.Add("Authorization", "Bearer rk-one")
	header.Add("Authorization", "Bearer rk-two")

	if err := applyAuth(t, header, authProfile(model.AuthModeXAPIKey), authValues("sk-up")); err != nil {
		t.Fatal(err)
	}
	if values := header.Values("Authorization"); len(values) != 0 {
		t.Errorf("多值 Authorization 应被整个删除，残留 %v", values)
	}
}

// ── fixed_query 不写头（计划第 11 条中段）───────────────────

// key 在 query 里的站：ApplyAuth 一个头都不该写。写了就是同时发两种认证，
// 而严格校验的站会因此 401 —— 表现为「明明 URL 里带了 key 却认证失败」。
func TestApplyAuth_FixedQueryWritesNoHeader(t *testing.T) {
	header := inboundHeaders()
	profile := authProfile(model.AuthModeFixedQuery)
	profile.QueryName = "key"

	if err := applyAuth(t, header, profile, authValues("sk-up")); err != nil {
		t.Fatalf("ApplyAuth 失败: %v", err)
	}
	for _, name := range model.AuthHeaders {
		if got := header.Get(name); got != "" {
			t.Errorf("fixed_query 模式不该写任何认证头，%s = %q", name, got)
		}
	}
}

// fixed_query 必须经**显式**的 query template 提供 key。
//
// 没有 query_name 就说明这个 profile 只声明了「key 在 query 里」而没说在哪个
// 参数里 —— 此时唯一安全的动作是 config_error：猜一个参数名会让请求带着
// 一个上游不认的参数发出去，而 key 其实根本没送到。
func TestApplyAuth_FixedQueryWithoutQueryNameIsConfigError(t *testing.T) {
	header := inboundHeaders()
	err := applyAuth(t, header, authProfile(model.AuthModeFixedQuery), authValues("sk-up"))
	if err == nil {
		t.Fatal("fixed_query 缺 query_name 必须报 config_error")
	}
	if !errors.Is(err, ErrAuthConfig) {
		t.Errorf("应可识别为 config_error，得到 %v", err)
	}
}

// ── 未校准的 auto 在写 socket 前失败（计划第 11 条后半）───────

// auto_calibrated 但还没校准过：不能猜、也不能双发。
//
// 「双发」是旧行为（legacy auto 同时发 x-api-key 与 Bearer），它对多数站有效，
// 但那是**迁移期的兼容**，不是 auto 的语义。§7.2 明确要求「校准一次只尝试
// 一个候选，不能无依据地同时发送多个认证头」。
func TestApplyAuth_UncalibratedAutoFailsBeforeSocket(t *testing.T) {
	header := inboundHeaders()
	err := applyAuth(t, header, authProfile(model.AuthModeAutoCalibrated), authValues("sk-up"))
	if err == nil {
		t.Fatal("未校准的 auto 必须失败，而不是猜一种或双发")
	}
	if !errors.Is(err, ErrAuthConfig) {
		t.Errorf("应可识别为 config_error，得到 %v", err)
	}
	// 失败也必须已经把入站认证头删干净：调用方可能忽略错误继续发
	// （不该，但 header 是共享的可变对象），此时残留的 relay key 会漏出去。
	for _, name := range model.AuthHeaders {
		if got := header.Get(name); got != "" {
			t.Errorf("失败路径同样要先删入站认证头，%s = %q", name, got)
		}
	}
}

func TestApplyAuth_CalibratedAutoUsesCalibratedMode(t *testing.T) {
	header := inboundHeaders()
	profile := authProfile(model.AuthModeAutoCalibrated)
	profile.CalibratedMode = model.AuthModeBearer

	if err := applyAuth(t, header, profile, authValues("sk-up")); err != nil {
		t.Fatalf("已校准的 auto 应可用: %v", err)
	}
	if got := header.Get("Authorization"); got != "Bearer sk-up" {
		t.Errorf("应按校准结果写 Bearer，得到 %q", got)
	}
	if header.Get("X-Api-Key") != "" {
		t.Error("校准结果只有一种，不该同时写别的")
	}
}

// legacy_auto_real_only 是迁移期的逃生舱：真实流量沿用旧的双发行为。
//
// 它必须与 auto_calibrated 区分开 —— 前者有明确的历史依据（这个站在
// schema 1 时代就是双发且能用），后者是「还不知道用哪种」。
func TestApplyAuth_LegacyAutoKeepsDualSendForRealTraffic(t *testing.T) {
	header := inboundHeaders()
	if err := applyAuth(t, header, authProfile(model.AuthModeLegacyAutoRealOnly),
		authValues("sk-up")); err != nil {
		t.Fatalf("legacy auto 对真实流量应可用: %v", err)
	}
	if got := header.Get("X-Api-Key"); got != "sk-up" {
		t.Errorf("legacy auto 应发 X-Api-Key，得到 %q", got)
	}
	if got := header.Get("Authorization"); got != "Bearer sk-up" {
		t.Errorf("legacy auto 应发 Bearer，得到 %q", got)
	}
	// 第三个位置仍不该出现：双发指的是那两个，不是「全都发」。
	if got := header.Get("Api-Key"); got != "" {
		t.Errorf("Api-Key 不在 legacy 双发之列，得到 %q", got)
	}
}

// 合成探活不能用 legacy 双发：那条记录只是「历史上这么发过」，
// 对探活而言等于无依据地同时发两种认证（§7.2 禁止）。
//
// 规范要的是 config_error 而**不是** needs_review：动作不同 —— 前者引导用户
// 去跑一次校准（P0-11），后者是「这个 URL 得有人看一眼」。混成一类会让
// 用户对着提示找不到该做什么。
func TestApplyAuth_LegacyAutoFailsClosedForSyntheticProbe(t *testing.T) {
	header := inboundHeaders()
	err := ApplyAuth(context.Background(), header, AuthInput{
		Profile: authProfile(model.AuthModeLegacyAutoRealOnly),
		Values:  authValues("sk-up"),
		Use:     ResolveSyntheticProbe,
	})
	if err == nil {
		t.Fatal("legacy 双发对合成探活必须 fail closed")
	}
	if !errors.Is(err, ErrAuthConfig) {
		t.Errorf("应是 config_error 并引导校准，得到 %v", err)
	}
	// 不该是 legacy URL 待审核那条：两者的修复动作完全不同。
	if errors.Is(err, ErrLegacyNeedsReview) {
		t.Error("认证未校准与 legacy URL 待审核是两回事，不该复用同一个哨兵")
	}
}

// ── manual_headers（§7.2 的第六种）──────────────────────────

func TestApplyAuth_ManualHeadersRenderPlaceholders(t *testing.T) {
	header := inboundHeaders()
	profile := authProfile(model.AuthModeManualHeaders)
	profile.ManualHeaders = []model.HeaderTemplate{
		{Name: "X-Custom-Auth", Values: []string{"tok {{UPSTREAM_API_KEY}}"}},
		{Name: "X-Tenant", Values: []string{"acme"}},
	}

	if err := applyAuth(t, header, profile, authValues("sk-up")); err != nil {
		t.Fatalf("ApplyAuth 失败: %v", err)
	}
	if got := header.Get("X-Custom-Auth"); got != "tok sk-up" {
		t.Errorf("占位符应被渲染，得到 %q", got)
	}
	if got := header.Get("X-Tenant"); got != "acme" {
		t.Errorf("字面值应原样写入，得到 %q", got)
	}
	// manual 模式下三个标准位置仍必须为空：manual 的意思是「这个站用自定义
	// 头认证」，再补一个标准头就是双发。
	for _, name := range model.AuthHeaders {
		if got := header.Get(name); got != "" {
			t.Errorf("manual 模式不该写标准认证头，%s = %q", name, got)
		}
	}
}

func TestApplyAuth_ManualHeadersCannotOverrideStandardAliases(t *testing.T) {
	header := inboundHeaders()
	profile := authProfile(model.AuthModeManualHeaders)
	// 用 manual 去写一个标准认证位置：这会绕过「只有一种 profile」的约束。
	profile.ManualHeaders = []model.HeaderTemplate{
		{Name: "Authorization", Values: []string{"Bearer {{UPSTREAM_API_KEY}}"}},
	}

	err := applyAuth(t, header, profile, authValues("sk-up"))
	if err == nil {
		t.Fatal("manual_headers 不该能写标准认证别名 —— 那会让『恰好一种 profile』" +
			"这条约束失效，而它是防 relay key 泄露的那道闸")
	}
	if !errors.Is(err, ErrAuthConfig) {
		t.Errorf("应可识别为 config_error，得到 %v", err)
	}
}

func TestApplyAuth_ManualHeadersRejectsProtectedHeaders(t *testing.T) {
	for _, name := range []string{"Host", "Content-Length", "Transfer-Encoding", "Connection"} {
		t.Run(name, func(t *testing.T) {
			header := inboundHeaders()
			profile := authProfile(model.AuthModeManualHeaders)
			profile.ManualHeaders = []model.HeaderTemplate{{Name: name, Values: []string{"x"}}}

			if err := applyAuth(t, header, profile, authValues("sk-up")); err == nil {
				t.Errorf("manual_headers 不该能设置受保护头 %s", name)
			}
		})
	}
}

// ── 渲染后再次校验（计划第 12 条）───────────────────────────

// 凭据里含 CR/LF/NUL/control 时必须在写 socket **之前**失败。
//
// 这不是洁癖：请求头注入就是靠 CR/LF 实现的。一个能改 Secret 值的人
// （管理界面就能改）借此可以往请求里插任意头，甚至走私第二个请求。
//
// 「写 socket 之前」是硬要求：ApplyAuth 返回错误时 RequestBytes 必须是 0、
// RoundTrip 次数必须是 0，也就是这次尝试完全没有出网。
func TestApplyAuth_RejectsCredentialsWithControlCharacters(t *testing.T) {
	bad := []struct {
		name string
		key  string
	}{
		{"CR", "sk-up\rX-Injected: 1"},
		{"LF", "sk-up\nX-Injected: 1"},
		{"CRLF", "sk-up\r\nX-Injected: 1"},
		{"NUL", "sk-up\x00"},
		{"其他 control", "sk-up\x07"},
		{"DEL", "sk-up\x7f"},
	}
	// 每种 profile 都要挡：只在一处挡的话，换个 auth_mode 就绕过去了。
	profiles := []model.AuthMode{
		model.AuthModeBearer, model.AuthModeXAPIKey, model.AuthModeAPIKey,
		model.AuthModeLegacyAutoRealOnly,
	}

	for _, testCase := range bad {
		for _, mode := range profiles {
			t.Run(testCase.name+"/"+string(mode), func(t *testing.T) {
				header := inboundHeaders()
				err := applyAuth(t, header, authProfile(mode), authValues(testCase.key))
				if err == nil {
					t.Fatal("含控制字符的凭据必须在写 socket 前失败")
				}
				if !errors.Is(err, ErrAuthConfig) {
					t.Errorf("应可识别为 config_error，得到 %v", err)
				}
				// 错误文本不得复述凭据：它会落进 last_error 并显示在 UI 上。
				if strings.Contains(err.Error(), "sk-up") {
					t.Errorf("错误文本不得包含凭据明文，得到 %q", err.Error())
				}
				// 失败时不能留下半写的认证头。
				for _, name := range model.AuthHeaders {
					if got := header.Get(name); got != "" {
						t.Errorf("失败时不该留下认证头，%s = %q", name, got)
					}
				}
			})
		}
	}
}

func TestApplyAuth_RejectsManualHeaderValueWithControlCharacters(t *testing.T) {
	header := inboundHeaders()
	profile := authProfile(model.AuthModeManualHeaders)
	profile.ManualHeaders = []model.HeaderTemplate{
		{Name: "X-Custom-Auth", Values: []string{"tok {{UPSTREAM_API_KEY}}"}},
	}

	err := applyAuth(t, header, profile, authValues("sk-up\r\nX-Injected: 1"))
	if err == nil {
		t.Fatal("渲染后的 manual header 含 CRLF 必须失败 —— 渲染前的模板是干净的，" +
			"脏东西来自 Secret 值，所以必须在渲染**之后**再验一次")
	}
	if header.Get("X-Custom-Auth") != "" {
		t.Error("失败时不该写入这个头")
	}
}

// ── 缺凭据 ────────────────────────────────────────────────

// 上游 key 为空时必须报错，绝不静默发一个无认证请求。
//
// 静默发出去会得到一个难以归因的 401：用户看到「认证失败」，而真正的问题
// 是「key 没配」。两者的修复动作完全不同。
func TestApplyAuth_MissingCredentialIsConfigError(t *testing.T) {
	for _, mode := range []model.AuthMode{
		model.AuthModeBearer, model.AuthModeXAPIKey, model.AuthModeAPIKey,
		model.AuthModeLegacyAutoRealOnly,
	} {
		t.Run(string(mode), func(t *testing.T) {
			header := inboundHeaders()
			err := applyAuth(t, header, authProfile(mode), Values{})
			if err == nil {
				t.Fatal("缺凭据必须报 config_error，不能静默发无认证请求")
			}
			if !errors.Is(err, ErrAuthConfig) {
				t.Errorf("应可识别为 config_error，得到 %v", err)
			}
		})
	}
}

func TestApplyAuth_RejectsInvalidMode(t *testing.T) {
	header := inboundHeaders()
	if err := applyAuth(t, header, authProfile("no_such_mode"), authValues("sk-up")); err == nil {
		t.Fatal("无效 auth_mode 必须报错")
	}
}

func TestApplyAuth_RejectsNilHeader(t *testing.T) {
	if err := ApplyAuth(context.Background(), nil,
		AuthInput{Profile: authProfile(model.AuthModeXAPIKey), Values: authValues("sk-up")}); err == nil {
		t.Fatal("nil header 必须报错而不是 panic")
	}
}

// Secret 引用的凭据同样走同一条校验（占位符解析失败不得泄露明文）。
func TestApplyAuth_SecretErrorNeverEchoesPlaintext(t *testing.T) {
	const plain = "super-secret-value"
	header := inboundHeaders()
	profile := authProfile(model.AuthModeManualHeaders)
	profile.ManualHeaders = []model.HeaderTemplate{
		{Name: "X-Custom-Auth", Values: []string{"{{SECRET:site-token}}"}},
	}

	err := ApplyAuth(context.Background(), header, AuthInput{
		Profile: profile,
		// 复用 resolver_test 里那个「把明文写进自己错误」的恶劣实现：
		// 两处共用一个反面样例，就不会有一处忘了检查。
		Values: leakyValues{plain: plain},
	})
	if err == nil {
		t.Fatal("Secret 解析失败应报错")
	}
	if !strings.Contains(err.Error(), "site-token") {
		t.Errorf("错误应指名占位符，得到 %v", err)
	}
	if strings.Contains(err.Error(), plain) {
		t.Errorf("错误文本不得包含 Secret 明文（它会落进 last_error 并显示在 UI 上），"+
			"得到 %q", err.Error())
	}
}
