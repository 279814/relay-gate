package model

import (
	"strings"
	"testing"
)

// base_url 带 /v1 是配置时最容易犯的错，且症状（404）看不出根因，
// 所以必须在入口挡掉并说清原因。
func TestBaseURLRejectsPath(t *testing.T) {
	bad := []string{
		"https://api.example.com/v1",
		"https://api.example.com/v1/",
		"https://api.example.com/v1/messages",
		"https://api.example.com/api",
		"api.example.com",       // 缺 scheme
		"ftp://api.example.com", // 错误 scheme
		"https://",              // 缺 host
		"https://api.example.com?x=1",
		"",
	}
	for _, u := range bad {
		t.Run(u, func(t *testing.T) {
			up := &Upstream{Name: "t", BaseURL: u, APIKey: "k"}
			up.Defaults()
			if err := up.Validate(); err == nil {
				t.Fatalf("%q 应被拒绝", u)
			}
		})
	}

	good := []string{
		"https://api.example.com",
		"https://api.example.com/", // 单个尾斜杠等价于无路径
		"http://127.0.0.1:8080",
		"https://sub.domain.example.com",
	}
	for _, u := range good {
		t.Run(u, func(t *testing.T) {
			up := &Upstream{Name: "t", BaseURL: u, APIKey: "k"}
			up.Defaults()
			if err := up.Validate(); err != nil {
				t.Fatalf("%q 应被接受，却报错：%v", u, err)
			}
		})
	}
}

// 回归测试：开了 full_url_mode 时，带路径的 base_url 必须能存进去。
//
// 曾经的 bug：校验无条件拒绝带路径的 base_url，而它自己的错误信息
// 又推荐「请开启 full_url_mode」—— 开了也存不进去，那条逃生舱是句空话。
// BuildOutboundURL 里的 FullURLMode 分支因此成了永远走不到的死代码，
// 非标准路径的站根本没法接入。
func TestBaseURLAllowsPathInFullURLMode(t *testing.T) {
	good := []string{
		"https://api.example.com/custom/chat",
		"https://api.example.com/v1/messages",
		"https://api.example.com/openai/deployments/gpt/chat/completions",
	}
	for _, u := range good {
		t.Run(u, func(t *testing.T) {
			up := &Upstream{Name: "t", BaseURL: u, APIKey: "k", FullURLMode: true}
			up.Defaults()
			if err := up.Validate(); err != nil {
				t.Fatalf("full_url_mode 下 %q 应被接受，却报错：%v", u, err)
			}
		})
	}

	// full_url_mode 放开的只是「路径」这一条，URL 本身仍必须合法 ——
	// 否则错误会推迟到出站时才暴露，那时只看到一个没头没尾的转发失败。
	bad := []string{
		"api.example.com/custom",       // 缺 scheme
		"ftp://api.example.com/custom", // 错误 scheme
		"https:///custom",              // 缺 host
		"",
	}
	for _, u := range bad {
		t.Run("bad/"+u, func(t *testing.T) {
			up := &Upstream{Name: "t", BaseURL: u, APIKey: "k", FullURLMode: true}
			up.Defaults()
			if err := up.Validate(); err == nil {
				t.Fatalf("full_url_mode 也不该放过 %q", u)
			}
		})
	}

	// 没开 full_url_mode 时仍要挡住带路径的，且错误信息要指向那个开关
	up := &Upstream{Name: "t", BaseURL: "https://api.example.com/v1", APIKey: "k"}
	up.Defaults()
	err := up.Validate()
	if err == nil {
		t.Fatal("未开 full_url_mode 时带路径应被拒绝")
	}
	if !strings.Contains(err.Error(), "full_url_mode") {
		t.Errorf("错误信息应指出可用 full_url_mode，得到：%v", err)
	}
}

// 探活头里混进鉴权头会造成「两个 key 来源」，出问题时无从排查。
func TestProbeHeadersRejectAuth(t *testing.T) {
	for _, h := range []string{"Authorization", "authorization", "x-api-key", "X-API-Key", "api-key"} {
		up := &Upstream{
			Name: "t", BaseURL: "https://a.com", APIKey: "k",
			ProbeHeaders: map[string]string{h: "sk-whatever"},
		}
		up.Defaults()
		err := up.Validate()
		if err == nil {
			t.Fatalf("probe_headers 含 %q 应被拒绝", h)
		}
		if !strings.Contains(err.Error(), "api_key") {
			t.Errorf("错误信息应说明 key 由 api_key 字段统一注入，得到：%v", err)
		}
	}

	// 非鉴权头必须放行——这正是该字段存在的目的（应对 UA 白名单站）
	up := &Upstream{
		Name: "t", BaseURL: "https://a.com", APIKey: "k",
		ProbeHeaders: map[string]string{"user-agent": "claude-cli/2.1.220 (external, sdk-cli)"},
	}
	up.Defaults()
	if err := up.Validate(); err != nil {
		t.Fatalf("user-agent 覆盖应被允许：%v", err)
	}
}

func TestUpstreamDefaults(t *testing.T) {
	u := &Upstream{Name: "t", BaseURL: "https://a.com", APIKey: "k"}
	u.Defaults()
	if u.AuthStyle != AuthAuto {
		t.Errorf("auth_style 默认应为 auto（M0 实测各站两种头都通），得到 %q", u.AuthStyle)
	}
	if u.L1Path != "/v1/models" {
		t.Errorf("l1_path 默认应为 /v1/models，得到 %q", u.L1Path)
	}
}

// probe_max_tokens 的默认值按协议不同：Responses 给 1 会被部分站直接拒绝。
func TestModelNameDefaultsPerProtocol(t *testing.T) {
	cases := map[Protocol]int{
		ProtoAnthropic:       1,
		ProtoOpenAIChat:      1,
		ProtoOpenAIResponses: 16,
	}
	for proto, want := range cases {
		m := &ModelName{Name: "m", Protocol: proto}
		m.Defaults()
		if m.ProbeMaxTokens != want {
			t.Errorf("%s 的 probe_max_tokens 默认应为 %d，得到 %d", proto, want, m.ProbeMaxTokens)
		}
		if m.ProbePrompt != "1+1=?" {
			t.Errorf("probe_prompt 默认应为 1+1=?，得到 %q", m.ProbePrompt)
		}
	}
}

// 入站路径 = 出站路径是「1:1 直通、不做协议转换」的核心（§3.1）。
func TestProtocolPath(t *testing.T) {
	want := map[Protocol]string{
		ProtoAnthropic:       "/v1/messages",
		ProtoOpenAIResponses: "/v1/responses",
		ProtoOpenAIChat:      "/v1/chat/completions",
	}
	for p, path := range want {
		if got := p.Path(); got != path {
			t.Errorf("%s 的路径应为 %s，得到 %s", p, path, got)
		}
		if !p.Valid() {
			t.Errorf("%s 应为合法协议", p)
		}
	}
	if Protocol("openai").Valid() {
		t.Error("未知协议不应通过校验")
	}
}

func TestRouteValidate(t *testing.T) {
	base := func() *Route {
		r := &Route{ModelNameID: 1, UpstreamID: 1}
		r.Defaults()
		return r
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("默认 Route 应合法：%v", err)
	}
	// priority 从 1 开始（1 最高）。0 会让选路分桶出现空洞
	r := base()
	r.Priority = 0
	r.Weight = 100
	if err := r.Validate(); err == nil {
		t.Error("priority 0 应被拒绝")
	}
	r = base()
	r.MaxConcurrency = -1
	if err := r.Validate(); err == nil {
		t.Error("max_concurrency 负数应被拒绝")
	}
	r = base()
	r.ModelNameID = 0
	if err := r.Validate(); err == nil {
		t.Error("缺 model_name_id 应被拒绝")
	}
}

func TestRouteDefaults(t *testing.T) {
	r := &Route{ModelNameID: 1, UpstreamID: 1}
	r.Defaults()
	if r.Priority != 1 || r.Weight != 100 {
		t.Errorf("默认应为 priority=1 weight=100，得到 %d/%d", r.Priority, r.Weight)
	}
	// UpstreamModel 默认必须是空 —— 空即「不映射」，body 零改动（§3.3.2）
	if r.UpstreamModel != "" {
		t.Errorf("upstream_model 默认必须为空（不映射 = body 零改动），得到 %q", r.UpstreamModel)
	}
}
