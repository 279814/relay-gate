// Package model 定义核心领域类型：Upstream / ModelName / Route。
// 三层结构的理由见 docs/01-需求与设计.md §2：一个物理站配一次（Upstream），
// 通过 Route 绑到多个逻辑模型（ModelName），Route 才是健康状态的最小单位。
package model

// Protocol 是入站与出站共用的协议标识。入站路径 = 出站路径，不做协议转换（§3.1）。
type Protocol string

const (
	ProtoAnthropic       Protocol = "anthropic"        // POST /v1/messages
	ProtoOpenAIResponses Protocol = "openai-responses" // POST /v1/responses
	ProtoOpenAIChat      Protocol = "openai-chat"      // POST /v1/chat/completions
)

// Path 返回该协议对应的端点路径。入站与出站是同一个值，这正是「1:1 直通」的体现。
func (p Protocol) Path() string {
	switch p {
	case ProtoAnthropic:
		return "/v1/messages"
	case ProtoOpenAIResponses:
		return "/v1/responses"
	case ProtoOpenAIChat:
		return "/v1/chat/completions"
	}
	return ""
}

func (p Protocol) Valid() bool { return p.Path() != "" }

// AuthStyle 决定出站注入哪个鉴权头（§3.2）。
type AuthStyle string

const (
	// AuthAuto 按协议推断，且两个头都发。M0 实测可用站全部同时接受
	// x-api-key 与 Bearer，所以 auto 是安全的默认值。
	AuthAuto    AuthStyle = "auto"
	AuthXAPIKey AuthStyle = "x-api-key"
	AuthBearer  AuthStyle = "bearer"
)

func (a AuthStyle) Valid() bool {
	return a == AuthAuto || a == AuthXAPIKey || a == AuthBearer
}

// MatchMode 决定入站 model 值如何匹配到 ModelName（§3.4）。
type MatchMode string

const (
	MatchExact  MatchMode = "exact"
	MatchPrefix MatchMode = "prefix"
)

func (m MatchMode) Valid() bool { return m == MatchExact || m == MatchPrefix }
