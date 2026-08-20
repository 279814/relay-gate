package probe

import (
	"net/http"
	"strings"

	"github.com/279814/relay-gate/internal/model"
)

// defaultProbeHeaders 是探活请求的默认指纹，照抄真实 Claude Code 的头集合
// （抓包所得，与 scripts/probe-upstream.sh 里 M0 用的是同一套）。
//
// 为什么探活要伪装成 Claude Code：M0 实测到**按 user-agent 前缀白名单拦截**
// 的站 —— 非 `claude-cli/*` 一律 401。探活请求若长得不像 Claude Code，
// 会把一个完全可用的站判成死站，而这正是本项目要避免的核心错误
// （把好站踢出池子比发现不了死站更糟：后者只是没优化，前者是主动制造故障）。
//
// 注意 anthropic-beta **不含** context-1m：真实 Claude Code 不发这个开关，
// 加上它反而与真实请求不一致。M0 有一站被脚本标为「需 1M」，
// 已确认是误报（§9.1.1 复核点 2）。
var defaultProbeHeaders = map[string]string{
	"user-agent":     "claude-cli/2.1.220 (external, sdk-cli)",
	"x-app":          "cli",
	"accept":         "application/json",
	"content-type":   "application/json",
	"anthropic-beta": strings.Join(anthropicBetas, ","),
	"anthropic-dangerous-direct-browser-access": "true",
	// x-stainless-* 是 SDK 指纹，部分站据此识别客户端
	"x-stainless-lang":            "js",
	"x-stainless-package-version": "0.70.1",
	"x-stainless-os":              "Windows",
	"x-stainless-arch":            "x64",
	"x-stainless-runtime":         "node",
	"x-stainless-retry-count":     "0",
}

// anthropicBetas 是真实 Claude Code 发送的特性开关集合（9 项，抓包所得）。
var anthropicBetas = []string{
	"claude-code-20250219",
	"interleaved-thinking-2025-05-14",
	"thinking-token-count-2026-05-13",
	"context-management-2025-06-27",
	"prompt-caching-scope-2026-01-05",
	"mid-conversation-system-2026-04-07",
	"advanced-tool-use-2025-11-20",
	"effort-2025-11-24",
	"fallback-credit-2026-06-01",
}

// anthropicVersion 是 Anthropic 协议必需的版本头，缺失直接 400。
const anthropicVersion = "2023-06-01"

// buildHeaders 组装探活请求头。
//
// 两层叠加，后者覆盖前者：默认模板 → Upstream 级 probe_headers。
// **不含认证** —— 那是 outbound.ApplyAuth 的唯一职责（§7.2）。原先这里有
// 一份自己的 injectAuth，与转发路径那份是两套代码；而「探活用一种认证、
// 真实请求用另一种」的故障表现为「探活说站活着，但用户一直 401」，
// 极难定位，因为两条路径各自看起来都对。
//
// probe_headers 里的认证头仍然要挡掉：它是明文 JSON，让它能塞进一个
// Authorization 就等于给这个站开了第二个 key 来源，绕过加密存储。
func buildHeaders(up *model.Upstream, proto model.Protocol, stream bool) http.Header {
	h := make(http.Header, len(defaultProbeHeaders)+4)
	for k, v := range defaultProbeHeaders {
		h.Set(k, v)
	}
	if proto == model.ProtoAnthropic {
		h.Set("anthropic-version", anthropicVersion)
	}
	if stream {
		// 流式请求的 accept 与非流式不同。真实 Claude Code 走 SSE 时
		// 发的是 text/event-stream，跟着改能让探活更像真实流量。
		h.Set("accept", "text/event-stream")
	}

	// Upstream 级覆盖：给「按 UA 白名单拦截」这类站单独调指纹用（§3.6.4）。
	for k, v := range up.ProbeHeaders {
		if model.IsAuthHeader(k) {
			// 静默跳过而不是报错：这里在探活的热路径上，没有能把错误
			// 呈现给用户的位置。配置层已经拒绝了这种输入（见 model.Validate），
			// 这里是纵深防御 —— 万一有人手改了库，也不能让明文 key 生效。
			continue
		}
		if v == "" {
			// 空值语义是「删掉这个头」。有站会因为多一个头而拒绝请求，
			// 需要一个能减头的手段，而不只是加和改。
			h.Del(k)
			continue
		}
		h.Set(k, v)
	}
	return h
}

// DefaultHeaderTemplate 返回默认探活头模板的副本，供管理界面展示与编辑。
func DefaultHeaderTemplate() map[string]string {
	out := make(map[string]string, len(defaultProbeHeaders)+1)
	for k, v := range defaultProbeHeaders {
		out[k] = v
	}
	out["anthropic-version"] = anthropicVersion
	return out
}
