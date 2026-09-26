package model

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrValidation 是所有校验失败的哨兵错误，API 层据此回 400 而非 500。
var ErrValidation = errors.New("validation")

// MinRedactableKeyLen 是允许落库的最短非空上游 api_key 长度。
//
// sample.RedactText 会跳过更短的字符串（避免在 URL/正文里误伤），因此短于此
// 的 key 一旦写入，会原样出现在客户端可见的 Location 等 URI 头里。空串不在此
// 限：更新时留空表示「不改已存 key」。
const MinRedactableKeyLen = 12

// APIKeyTooShortForOutbound 报告已存非空 api_key 是否短于脱敏下限。
//
// 脏行/历史短钥不得进入选路或探活出站：一旦进 query / Authorization /
// Location，RedactText 不会遮它。空串另计（出站路径按「未配置」fail closed）。
func APIKeyTooShortForOutbound(key string) bool {
	return key != "" && len(key) < MinRedactableKeyLen
}

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
	// 空串表示更新时「不改 key」，不是短 key。非空则必须达到脱敏下限。
	if u.APIKey != "" && len(u.APIKey) < MinRedactableKeyLen {
		return invalid("api_key 长度至少为 %d（短于此无法在 Location 等 URI 头中脱敏），收到 %d",
			MinRedactableKeyLen, len(u.APIKey))
	}
	if !u.AuthStyle.Valid() {
		return invalid("auth_style 必须是 auto / x-api-key / bearer，收到 %q", u.AuthStyle)
	}
	if !u.ProbeMode.Valid() {
		return invalid("probe_mode 必须是 active 或 lazy，收到 %q", u.ProbeMode)
	}
	if u.L1Path != "" && !strings.HasPrefix(u.L1Path, "/") {
		return invalid("l1_path 必须以 / 开头，收到 %q", u.L1Path)
	}
	if err := validateProxyURL(u.ProxyURL); err != nil {
		return err
	}
	// 探活头里不允许出现鉴权头：key 由 Upstream.APIKey 统一注入，
	// 在这里再写一个会造成「两个 key 来源」，出问题时无从排查。
	for k, v := range u.ProbeHeaders {
		if IsAuthHeader(k) {
			return invalid("probe_headers 不能包含鉴权头 %q，key 由 api_key 字段统一注入", k)
		}
		if HeaderFieldHasCRLFOrNUL(k) {
			return invalid("probe_headers 头名不能含 CR/LF/NUL")
		}
		if HeaderFieldHasCRLFOrNUL(v) {
			return invalid("probe_headers 头值不能含 CR/LF/NUL（会构造出请求头注入）")
		}
	}
	return nil
}

// HeaderFieldHasCRLFOrNUL 报告配置里的头名或头值是否带 CR/LF/NUL。
//
// 这三项一旦被抄进出站 http.Header 或拼进原始请求，就是请求头注入
// （例如值 "x\r\nX-Injected: y"）。写入路径与应用路径都应拒绝或跳过。
func HeaderFieldHasCRLFOrNUL(s string) bool {
	return strings.ContainsAny(s, "\r\n\x00")
}

func (endpoint *UpstreamEndpoint) Validate() error {
	if endpoint.UpstreamID <= 0 {
		return invalid("upstream_id 必须指定")
	}
	if !endpoint.Kind.Valid() {
		return invalid("endpoint 无效: %q", endpoint.Kind)
	}
	if !endpoint.URLMode.Valid() {
		return invalid("url_mode 无效: %q", endpoint.URLMode)
	}
	switch endpoint.URLMode {
	case EndpointURLCanonical:
		if endpoint.LegacyFullURLID != 0 || endpoint.LegacyFullURLRevision != 0 {
			return invalid("canonical endpoint 不能引用 legacy full URL")
		}
	case EndpointURLLegacyExact:
		if endpoint.LegacyFullURLID <= 0 || endpoint.LegacyFullURLRevision <= 0 || !endpoint.NeedsReview {
			return invalid("legacy_exact endpoint 必须引用待审核 legacy full URL")
		}
	}
	if !endpoint.AuthProfile.Mode.Valid() {
		return invalid("auth mode 无效: %q", endpoint.AuthProfile.Mode)
	}
	if endpoint.AuthProfile.Mode == AuthModeAutoCalibrated && endpoint.AuthProfile.CalibratedMode != "" &&
		(endpoint.AuthProfile.CalibratedMode == AuthModeAutoCalibrated ||
			endpoint.AuthProfile.CalibratedMode == AuthModeLegacyAutoRealOnly ||
			!endpoint.AuthProfile.CalibratedMode.Valid()) {
		return invalid("calibrated auth mode 无效: %q", endpoint.AuthProfile.CalibratedMode)
	}
	if endpoint.AuthProfile.Mode != AuthModeLegacyAutoRealOnly && endpoint.LegacyCompatRealOnly {
		return invalid("legacy_compat_real_only 只允许 legacy auto endpoint")
	}
	if endpoint.AuthProfile.SecretRef == "" {
		return invalid("auth secret_ref 不能为空")
	}
	if HeaderFieldHasCRLFOrNUL(endpoint.AuthProfile.HeaderName) {
		return invalid("auth header_name 不能含 CR/LF/NUL")
	}
	for _, header := range endpoint.AuthProfile.ManualHeaders {
		if strings.TrimSpace(header.Name) == "" || HeaderFieldHasCRLFOrNUL(header.Name) {
			return invalid("manual auth header name 无效")
		}
		for _, value := range header.Values {
			if HeaderFieldHasCRLFOrNUL(value) {
				return invalid("manual auth header value 含控制字符")
			}
		}
	}
	if endpoint.Revision < 0 || endpoint.AuthProfile.Revision < 0 {
		return invalid("revision 不能为负")
	}
	return nil
}

// validateBaseURL 校验 base_url。
//
// 默认强制「协议 + 主机」且不带路径：带了 /v1 会让出站 URL 变成
// /v1/v1/messages —— 这是配置时最容易犯的错，症状是 404 且很难看出根因，
// 所以在入口就挡掉。
//
// fullURLMode 为 true 时**允许带路径**：那正是这个开关的用途（出站解析
// 会把 base_url 当成完整端点，不再拼路径）。不放行的话，上面那句
// 「请开启 full_url_mode」的建议就是句空话 —— 开了也存不进去。
//
// query / fragment / userinfo 一律拒绝（docs/01 §5.1、§7.1），与 full_url_mode
// 无关。固定 query 只进 Endpoint.FixedQueryTemplate；凭据不得写进 URL。
// AllowedProxyURLScheme 报告 proxy_url 的 scheme 是否允许。
//
// docs/01 §7.3 按 HTTP 代理 CONNECT 设计出站建连；空 proxy_url 表示直连，
// 非空只接受 http / https（大小写不敏感）。socks5 / file / ftp 等一律拒绝。
// 凭据（userinfo）文档明确允许，本函数不检查。
func AllowedProxyURLScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "http", "https":
		return true
	default:
		return false
	}
}

// validateProxyURL 校验上游出站代理。空串 = 直连，合法。
func validateProxyURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return invalid("proxy_url 不是合法 URL: %v", err)
	}
	if !AllowedProxyURLScheme(u.Scheme) {
		return invalid("proxy_url 必须是 http(s):// 代理，收到 scheme %q", u.Scheme)
	}
	return nil
}

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
	if u.User != nil {
		return invalid("base_url 不能包含 userinfo")
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
	// 空 / 仅空白 name 一律拒绝。prefix 模式下空串会让 strings.HasPrefix
	// 匹配任意入站 model，等于悄悄变成全量兜底。
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
