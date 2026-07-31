package model

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrValidation 是所有校验失败的哨兵错误，API 层据此回 400 而非 500。
var ErrValidation = errors.New("validation")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrValidation, fmt.Sprintf(format, a...))
}

// WrapValidation 供其他包构造校验错误，语义与 invalid 相同。
func WrapValidation(format string, a ...any) error {
	return invalid(format, a...)
}

func (u *Upstream) Validate() error {
	if strings.TrimSpace(u.Name) == "" {
		return invalid("name 不能为空")
	}
	if err := validateBaseURL(u.BaseURL, u.FullURLMode); err != nil {
		return err
	}
	if !u.AuthStyle.Valid() {
		return invalid("auth_style 必须是 auto / x-api-key / bearer，收到 %q", u.AuthStyle)
	}
	if u.L1Path != "" && !strings.HasPrefix(u.L1Path, "/") {
		return invalid("l1_path 必须以 / 开头，收到 %q", u.L1Path)
	}
	if u.ProxyURL != "" {
		if _, err := url.Parse(u.ProxyURL); err != nil {
			return invalid("proxy_url 不是合法 URL: %v", err)
		}
	}
	// 探活头里不允许出现鉴权头：key 由 Upstream.APIKey 统一注入，
	// 在这里再写一个会造成「两个 key 来源」，出问题时无从排查。
	for k := range u.ProbeHeaders {
		if isAuthHeader(k) {
			return invalid("probe_headers 不能包含鉴权头 %q，key 由 api_key 字段统一注入", k)
		}
	}
	return nil
}

// validateBaseURL 校验 base_url。
//
// 默认强制「协议 + 主机」且不带路径：带了 /v1 会让出站 URL 变成
// /v1/v1/messages —— 这是配置时最容易犯的错，症状是 404 且很难看出根因，
// 所以在入口就挡掉。
//
// fullURLMode 为 true 时**允许带路径**：那正是这个开关的用途（BuildOutboundURL
// 会把 base_url 当成完整端点，不再拼路径）。不放行的话，上面那句
// 「请开启 full_url_mode」的建议就是句空话 —— 开了也存不进去。
func validateBaseURL(raw string, fullURLMode bool) error {
	if strings.TrimSpace(raw) == "" {
		return invalid("base_url 不能为空")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return invalid("base_url 不是合法 URL: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return invalid("base_url 必须是 http(s):// 开头，收到 %q", raw)
	}
	if u.Host == "" {
		return invalid("base_url 缺少主机名")
	}
	if p := strings.Trim(u.Path, "/"); p != "" && !fullURLMode {
		return invalid("base_url 不能带路径（收到 %q）。填根地址即可，"+
			"出站路径由入站请求决定；若该站确实用非标准路径，请开启 full_url_mode", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return invalid("base_url 不能带 query 或 fragment")
	}
	return nil
}

func (m *ModelName) Validate() error {
	if strings.TrimSpace(m.Name) == "" {
		return invalid("name 不能为空")
	}
	if !m.Protocol.Valid() {
		return invalid("protocol 必须是 anthropic / openai-responses / openai-chat，收到 %q", m.Protocol)
	}
	if !m.MatchMode.Valid() {
		return invalid("match_mode 必须是 exact / prefix，收到 %q", m.MatchMode)
	}
	if m.ProbeMaxTokens < 1 {
		return invalid("probe_max_tokens 至少为 1，收到 %d", m.ProbeMaxTokens)
	}
	if strings.TrimSpace(m.ProbePrompt) == "" {
		return invalid("probe_prompt 不能为空")
	}
	return nil
}

func (r *Route) Validate() error {
	if r.ModelNameID <= 0 {
		return invalid("model_name_id 必须指定")
	}
	if r.UpstreamID <= 0 {
		return invalid("upstream_id 必须指定")
	}
	if r.Priority < 1 {
		return invalid("priority 最小为 1（1 最高），收到 %d", r.Priority)
	}
	if r.Weight < 1 {
		return invalid("weight 最小为 1，收到 %d", r.Weight)
	}
	if r.MaxConcurrency < 0 {
		return invalid("max_concurrency 不能为负（0 表示不限），收到 %d", r.MaxConcurrency)
	}
	return nil
}

func isAuthHeader(k string) bool {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case "authorization", "x-api-key", "api-key":
		return true
	}
	return false
}
