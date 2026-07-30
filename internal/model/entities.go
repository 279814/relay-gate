package model

// Upstream 是一个物理中转站。全局配一次，通过 Route 绑到多个 ModelName。
type Upstream struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	BaseURL string `json:"base_url"` // 根地址，不含 /v1。出站路径由入站请求决定（§2.1）

	// APIKey 在库里 AES-GCM 加密存储。出站 JSON 一律脱敏为 sk-abcd…wxyz，
	// 只有写入时才接受明文——避免管理接口把 key 回显出去。
	APIKey string `json:"api_key,omitempty"`

	AuthStyle   AuthStyle `json:"auth_style"`
	FullURLMode bool      `json:"full_url_mode"` // true 时 BaseURL 即完整端点，不再拼路径
	ProxyURL    string    `json:"proxy_url,omitempty"`
	Enabled     bool      `json:"enabled"`

	// L1Path 为空表示只做 TCP/TLS 握手探测。M0 实测 6 站的 /v1/models 全部 200，
	// 所以默认值可用，无需降级。
	L1Path string `json:"l1_path"`

	// ProbeHeaders 覆盖该站探活请求的头。空 = 用全局模板（§3.6.4）。
	// 给「按 UA 白名单拦截」这类站单独调指纹用。
	ProbeHeaders map[string]string `json:"probe_headers,omitempty"`

	CreatedAt int64 `json:"created_at"`
	UpdatedAt int64 `json:"updated_at"`
}

// ModelName 是客户端请求里写的那个 model 值，映射到一组 Route。
type ModelName struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Protocol  Protocol  `json:"protocol"`
	MatchMode MatchMode `json:"match_mode"`

	// IsFallback：未匹配任何 ModelName 时的兜底目标。全局至多一个。
	IsFallback bool `json:"is_fallback"`

	ProbePrompt    string `json:"probe_prompt"`
	ProbeMaxTokens int    `json:"probe_max_tokens"`

	Enabled   bool  `json:"enabled"`
	CreatedAt int64 `json:"created_at"`
	UpdatedAt int64 `json:"updated_at"`
}

// Route 把一个 ModelName 绑到一个 Upstream，带优先级与模型映射。
// 这是探活与健康状态的最小单位——「A 站的 opus-5 挂了但 gpt 还活着」
// 只有在这个粒度上才能表达（§2.3）。
type Route struct {
	ID          int64 `json:"id"`
	ModelNameID int64 `json:"model_name_id"`
	UpstreamID  int64 `json:"upstream_id"`

	Priority int `json:"priority"` // 1 最高，同优先级按 Weight 加权随机
	Weight   int `json:"weight"`

	// UpstreamModel 为空 = 不映射，body 一个字节都不改（§3.3.2 的推荐配置）。
	// M0 实测所有站的模型名原名均可用，所以默认就该是空。
	UpstreamModel string `json:"upstream_model,omitempty"`

	MaxConcurrency int  `json:"max_concurrency"` // 0 = 不限
	Enabled        bool `json:"enabled"`

	CreatedAt int64 `json:"created_at"`
	UpdatedAt int64 `json:"updated_at"`
}

// HealthState 是 Route 的运行时健康状态。
type HealthState string

const (
	// StateUnknown 视为**可用**（乐观）。重启后全部置此值，否则重启即全站不可用（§2.4）。
	StateUnknown HealthState = "unknown"
	StateAlive   HealthState = "alive"
	StateDead    HealthState = "dead"
)

// Defaults 按 M0 实测结论填充零值字段。
// 放在 model 包而不是 store 包，是因为这些默认值是业务语义，不是存储细节。
func (u *Upstream) Defaults() {
	if u.AuthStyle == "" {
		u.AuthStyle = AuthAuto
	}
	if u.L1Path == "" {
		u.L1Path = "/v1/models"
	}
}

func (m *ModelName) Defaults() {
	if m.MatchMode == "" {
		m.MatchMode = MatchExact
	}
	if m.ProbePrompt == "" {
		m.ProbePrompt = "1+1=?"
	}
	if m.ProbeMaxTokens == 0 {
		// Responses 协议给 16：实测 max_output_tokens=1 会被部分站直接拒绝。
		// 另两种协议给 1 足够——只需要首个 delta 就能判活。
		if m.Protocol == ProtoOpenAIResponses {
			m.ProbeMaxTokens = 16
		} else {
			m.ProbeMaxTokens = 1
		}
	}
}

func (r *Route) Defaults() {
	if r.Priority == 0 {
		r.Priority = 1
	}
	if r.Weight == 0 {
		r.Weight = 100
	}
}
