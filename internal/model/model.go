// Package model 定义核心领域类型：Upstream / ModelName / Route。
// 三层结构的理由见 docs/01-需求与设计.md §2：一个物理站配一次（Upstream），
// 通过 Route 绑到多个逻辑模型（ModelName），Route 才是健康状态的最小单位。
package model

import "strings"

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

func (p Protocol) Endpoint() (EndpointKind, bool) {
	switch p {
	case ProtoAnthropic:
		return EndpointMessages, true
	case ProtoOpenAIResponses:
		return EndpointResponses, true
	case ProtoOpenAIChat:
		return EndpointChatCompletions, true
	default:
		return "", false
	}
}

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

// AuthHeaders 是「API key 可能待在哪个头里」的**唯一**清单。
//
// 三个协议的客户端习惯不同（§3.2），所以三个位置都要认。这份清单同时被
// 四条互不相邻的路径依赖：
//   - 入站鉴权：从这些位置取 relay key 做校验
//   - 出站改写：这些位置必须**全部删除**，否则 relay key 会漏给公益站
//   - 样本脱敏：这些位置的值不能明文落库（§3.6.3b）
//   - 配置校验：probe_headers 里不许出现它们（避免两个 key 来源）
//
// 之所以集中在这里，是因为漏改任何一条的后果都不对称：漏了「出站删除」
// 就是把用户的 relay key 直接送给公益站，漏了「样本脱敏」就是明文 key 落库，
// 而两者都不会报错、不会被现有测试之外的任何东西发现。
// 将来要支持新的鉴权头位置时，**只改这里**。
var AuthHeaders = []string{
	"Authorization",
	"X-Api-Key",
	"Api-Key",
}

// IsAuthHeader 判断一个头名是否属于 AuthHeaders（大小写不敏感）。
func IsAuthHeader(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, h := range AuthHeaders {
		if strings.ToLower(h) == name {
			return true
		}
	}
	return false
}

// MatchMode 决定入站 model 值如何匹配到 ModelName（§3.4）。
type MatchMode string

const (
	MatchExact  MatchMode = "exact"
	MatchPrefix MatchMode = "prefix"
)

func (m MatchMode) Valid() bool { return m == MatchExact || m == MatchPrefix }
