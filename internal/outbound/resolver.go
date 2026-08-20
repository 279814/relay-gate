// Package outbound 拥有出站目标的唯一定义。
//
// 存在的理由：真实转发、探活、models 与 count_tokens 原先各自拼一次 URL
// （proxy.BuildOutboundURL 三个调用方 + prober 自己的 L1 分支）。各拼一套的
// 后果不是「代码重复」这么轻——探活打通了不代表真实请求能通，而两者的差异
// 只在生产流量上才显形。规范 §7.1 把它收成一个 Resolver，本包就是它。
package outbound

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probetemplate"
)

// ValueResolver 与 ResolvedValue 是 probetemplate 的类型别名。
//
// 用别名而不是重新声明：Store 实现的是 probetemplate 的接口，若 outbound
// 另立一个同形接口，就需要一层 adapter，而 store → outbound → probetemplate
// → store 会成环。别名让三方共享同一份值契约（§4.3）。
type (
	ValueResolver = probetemplate.ValueResolver
	ResolvedValue = probetemplate.ResolvedValue
)

// ResolveUse 区分这次解析服务于真实流量还是合成探活。
//
// 不是装饰：legacy_exact 的多协议记录对真实流量必须逐字节沿用旧 URL（否则
// 升级即改变线上行为），而合成探活在同一条记录上必须 fail closed —— 一个
// 没人审核过的 URL 到底对应哪个端点是猜的，猜错会把一个好站探成死站。
type ResolveUse string

const (
	ResolveRealForward    ResolveUse = "real_forward"
	ResolveSyntheticProbe ResolveUse = "synthetic_probe"
)

func (use ResolveUse) valid() bool {
	return use == ResolveRealForward || use == ResolveSyntheticProbe
}

// ErrLegacyNeedsReview 表示这条 legacy_exact 记录不能用于合成探活。
//
// 单独一个哨兵而不是普通错误：调用方要据此把 Capability 记成
// legacy_full_url_needs_review 并且**不发网络请求**，与「配置错误」
// 是不同的动作。
var ErrLegacyNeedsReview = errors.New("legacy full URL 待人工审核，合成探活不可用")

// ResolveInput 是一次解析的全部输入。
//
// Endpoint 已经是取好的那一条记录：Resolver 不查库、不选 Route、不挑 Recipe。
// 取记录是 Provider 的事（target_provider.go）。
type ResolveInput struct {
	Upstream         *model.ProbeUpstreamConfig
	Endpoint         *model.UpstreamEndpoint
	LegacyURLs       LegacyURLResolver
	IncomingRawQuery string
	Values           ValueResolver
	Use              ResolveUse
}

// ResolvedTarget 是解析结果。
//
// RawURL 与 URL 描述同一个目标，但**必须都留着**：http.NewRequest 接受字符串
// 时会自己再解析一遍，而 escaped path 与 RawQuery 的保真只有在原字符串上
// 才成立。用 *url.URL 直接构造请求可以避免二次解析改写。
type ResolvedTarget struct {
	URL    *url.URL
	RawURL string
	// RequestHost 是要写进 Host 头的值。空表示用 URL 自己的 host。
	RequestHost string
	// OriginKey 是 scheme://authority，用于「同源」判断与连接池分组。
	OriginKey string
	// AuthProfile 是这个 Endpoint 的认证方式，交给 ApplyAuth 使用。
	//
	// 与 URL 一起返回而不是让调用方再查一次：两者来自**同一条** Endpoint
	// 记录的同一个 revision。分两次读的话，中间一次配置更新就会让请求
	// 「用新 URL 配旧认证」，而那种组合没有任何测试覆盖，症状是偶发 401。
	AuthProfile model.EndpointAuthProfile
	// ResolvedURLHash 是**配置语义**的 hash，进 Capability 身份。
	// 不含每个客户端请求都不同的 IncomingRawQuery —— 含了的话，一个普通的
	// ?beta=true 就会把同一个端点抖成两份全局能力状态。
	ResolvedURLHash string
	// RequestURLHash 是这一次实际 URL 的不可逆证据，只进单条 execution/log。
	RequestURLHash   string
	EndpointRevision int64
}

// RequestURLHasher 对最终 URL 求带密钥的摘要。由 store.Cipher 实现。
//
// 不能用裸 SHA-256：full_url_mode 允许把 key 放在 query 里（§3.2），而
// 低熵 query 的裸摘要就是一个离线枚举 oracle —— 拿到日志的人可以逐个
// 猜测并验证。
type RequestURLHasher interface {
	SumRequestURL(raw []byte) string
}

// LegacyURLResolver 按 expected revision 解密一条 legacy full URL。
// 由 store.Store 实现（ResolveLegacyURL）。
type LegacyURLResolver interface {
	ResolveLegacyURL(ctx context.Context, id, expectedRevision int64) (plain []byte, err error)
}

type Resolver struct {
	hasher RequestURLHasher
}

func NewResolver(hasher RequestURLHasher) *Resolver {
	return &Resolver{hasher: hasher}
}

// Resolve 解析出站目标（§7.1）。
//
// 顺序是刻意的：先定 origin（base_url）→ 再定 path（override 或 canonical）
// → 再渲染固定 query → 最后追加入站 RawQuery。反过来（先拼完整串再校验）
// 会让「override 跨了 origin」这种错误在字符串层面难以判定。
func (resolver *Resolver) Resolve(ctx context.Context, in ResolveInput) (ResolvedTarget, error) {
	if resolver == nil || resolver.hasher == nil {
		return ResolvedTarget{}, model.WrapValidation("resolver 未配置 URL hasher")
	}
	if in.Upstream == nil || in.Endpoint == nil {
		return ResolvedTarget{}, model.WrapValidation("resolve 缺少 upstream/endpoint 配置")
	}
	if !in.Use.valid() {
		return ResolvedTarget{}, model.WrapValidation("resolve use 无效: %q", in.Use)
	}
	if in.Endpoint.UpstreamID != in.Upstream.ID {
		return ResolvedTarget{}, model.WrapValidation("endpoint %d 不属于 upstream %d",
			in.Endpoint.ID, in.Upstream.ID)
	}
	if !in.Endpoint.Kind.Valid() {
		return ResolvedTarget{}, model.WrapValidation("endpoint 无效: %q", in.Endpoint.Kind)
	}

	base, err := parseOrigin(in.Upstream.BaseURL, "base_url")
	if err != nil {
		return ResolvedTarget{}, err
	}
	requestHost, err := validateHostOverride(in.Upstream.HostOverride)
	if err != nil {
		return ResolvedTarget{}, err
	}

	if in.Endpoint.URLMode == model.EndpointURLLegacyExact {
		return resolver.resolveLegacy(ctx, in, base, requestHost)
	}
	return resolver.resolveCanonical(ctx, in, base, requestHost)
}

func (resolver *Resolver) resolveCanonical(ctx context.Context, in ResolveInput,
	base *url.URL, requestHost string) (ResolvedTarget, error) {

	target := *base
	if override := in.Endpoint.URLOverride; override != "" {
		// 刻意不 TrimSpace 后再判空：那样一个纯空白的 override 会被当成
		// 「没配 override」而静默回落到 canonical path，把一处明显的配置
		// 错误变成一个打错地址的请求。空白由 parseOrigin 拒掉。
		parsed, err := parseOrigin(override, "url_override")
		if err != nil {
			return ResolvedTarget{}, err
		}
		if err := requireSameOrigin(base, parsed); err != nil {
			return ResolvedTarget{}, err
		}
		if parsed.RawQuery != "" {
			// 持久化只有一个固定 query 来源（§4.3）。override 里还带着 query
			// 说明写入路径没做机械拆分，此刻拼起来就是第二个来源 —— 那正是
			// 「query 有时丢、有时重复」这类难查问题的源头。
			return ResolvedTarget{}, model.WrapValidation(
				"url_override 不能带 query，固定 query 只能存在 fixed_query_template")
		}
		target.Path = parsed.Path
		target.RawPath = parsed.RawPath
	} else {
		// base_url 可能带公共路径前缀（`https://host/api` 这类网关）。必须
		// 字符串拼接而不是 ResolveReference：后者会把 /api 整段吞掉，
		// 结果打到 /v1/messages 而不是 /api/v1/messages。
		trimmed := strings.TrimRight(base.EscapedPath(), "/")
		joined := trimmed + in.Endpoint.Kind.CanonicalPath()
		parsed, err := url.Parse(joined)
		if err != nil {
			// 同 parseOrigin：不带 err 文本，它会附上完整 URL。
			return ResolvedTarget{}, model.WrapValidation("拼接 %s 的 canonical path 失败",
				in.Endpoint.Kind)
		}
		target.Path = parsed.Path
		target.RawPath = parsed.RawPath
	}

	fixedQuery, secretIdentity, err := renderFixedQuery(ctx, in)
	if err != nil {
		return ResolvedTarget{}, err
	}
	target.RawQuery = joinQuery(fixedQuery, in.IncomingRawQuery)
	target.Fragment = ""
	target.RawFragment = ""

	configIdentity := strings.Join([]string{
		"canonical",
		target.Scheme,
		target.Host,
		target.EscapedPath(),
		in.Endpoint.FixedQueryTemplate,
		secretIdentity,
		requestHost,
	}, "\x00")

	return resolver.finish(&target, requestHost, configIdentity, in.Endpoint)
}

// resolveLegacy 处理 schema 1→2 迁移出来的 exact URL。
//
// 与 canonical 的关键差别：**不拼 canonical path**。这条记录本身就是旧
// 版本实际打出去的完整 URL，改动它就是改动升级前后的线上行为。
func (resolver *Resolver) resolveLegacy(ctx context.Context, in ResolveInput,
	base *url.URL, requestHost string) (ResolvedTarget, error) {

	endpoint := in.Endpoint
	if endpoint.LegacyFullURLID <= 0 || endpoint.LegacyFullURLRevision <= 0 {
		return ResolvedTarget{}, model.WrapValidation("legacy_exact endpoint 缺少 legacy full URL 引用")
	}
	// 多协议记录（LegacyCompatRealOnly）只服务真实流量。合成探活拿不到
	// 「这个 URL 到底是哪个端点」的确证，只能 fail closed，且不发网络。
	//
	// 判定必须在解密**之前**：解密本身没有网络 IO，但它是「准备发请求」的
	// 第一步，把明文 URL 取出来之后再拒绝，就给后续改动留了一个把它用出去的口子。
	if in.Use == ResolveSyntheticProbe && endpoint.LegacyCompatRealOnly {
		return ResolvedTarget{}, fmt.Errorf("%w: endpoint %s", ErrLegacyNeedsReview, endpoint.Kind)
	}
	if in.LegacyURLs == nil {
		return ResolvedTarget{}, model.WrapValidation("缺少 legacy URL resolver")
	}

	plain, err := in.LegacyURLs.ResolveLegacyURL(ctx, endpoint.LegacyFullURLID, endpoint.LegacyFullURLRevision)
	if err != nil {
		return ResolvedTarget{}, fmt.Errorf("解析 legacy full URL: %w", err)
	}
	exact, err := parseOrigin(string(plain), "legacy full URL")
	if err != nil {
		return ResolvedTarget{}, err
	}
	if err := requireSameOrigin(base, exact); err != nil {
		return ResolvedTarget{}, err
	}

	target := *exact
	// 已捕获的 RawQuery 不再次编码，也不与 FixedQueryTemplate 混合：
	// 那份字节就是旧版本发出去的原文。
	target.RawQuery = joinQuery(exact.RawQuery, in.IncomingRawQuery)
	target.Fragment = ""
	target.RawFragment = ""

	// 解密后的 path/query 绝不进配置 hash：它可能含低熵 key，而配置 hash
	// 是裸 SHA-256（要跨进程稳定复现，不能带密钥）。只纳入 ID、revision
	// 与 store 侧已经算好的 keyed fingerprint。
	configIdentity := strings.Join([]string{
		"legacy_exact",
		base.Scheme,
		base.Host,
		fmt.Sprintf("%d/%d", endpoint.LegacyFullURLID, endpoint.LegacyFullURLRevision),
		requestHost,
	}, "\x00")

	return resolver.finish(&target, requestHost, configIdentity, endpoint)
}

func (resolver *Resolver) finish(target *url.URL, requestHost, configIdentity string,
	endpoint *model.UpstreamEndpoint) (ResolvedTarget, error) {

	raw := target.String()
	// 渲染后再验一次：Secret 明文可能带 CR/LF 或控制字符，而请求行注入
	// 正是靠它们实现的。前面的逐 byte percent-encode 已经挡住了 query 侧，
	// 这里兜的是 path 与整体形态。
	if err := validateFinalURL(raw); err != nil {
		return ResolvedTarget{}, err
	}
	digest := sha256.Sum256([]byte(configIdentity))
	return ResolvedTarget{
		URL:              target,
		RawURL:           raw,
		RequestHost:      requestHost,
		OriginKey:        target.Scheme + "://" + target.Host,
		AuthProfile:      endpoint.AuthProfile,
		ResolvedURLHash:  hex.EncodeToString(digest[:]),
		RequestURLHash:   resolver.hasher.SumRequestURL([]byte(raw)),
		EndpointRevision: endpoint.Revision,
	}, nil
}

// renderFixedQuery 渲染 Endpoint 的固定 query，并返回它的 Secret 身份串。
//
// 身份串只含 Secret **名称与 revision**，不含明文：配置 hash 要能在日志里
// 出现，而明文不能。改了 Secret 的值时 revision 会变，hash 因此失效 ——
// 这正是想要的（Capability 要重新验证），而明文不需要进来。
func renderFixedQuery(ctx context.Context, in ResolveInput) (string, string, error) {
	template := in.Endpoint.FixedQueryTemplate
	if template == "" {
		return "", "", nil
	}
	compiled, err := probetemplate.CompileContent(in.Endpoint.Kind, probetemplate.TemplateContent{
		Method:   in.Endpoint.Kind.Method(),
		RawQuery: template,
	})
	if err != nil {
		return "", "", err
	}
	required := compiled.RequiredSecrets()
	if in.Values == nil {
		if len(required) > 0 || strings.Contains(template, "{{") {
			return "", "", model.WrapValidation("fixed query 含占位符但未提供 value resolver")
		}
		return template, "", nil
	}

	// tracking resolver 包一层，把「渲染用到了哪些值的哪个 revision」记下来。
	// 不能事后再问一遍 resolver：那是第二次读取，值可能已经变了，于是
	// hash 描述的配置与实际发出去的请求对不上。
	tracker := &identityTracker{inner: in.Values}
	rendered, err := compiled.Render(ctx, tracker)
	if err != nil {
		// **不能把下层错误的文本带出去。**
		//
		// probetemplate.Render 用 %w 包装 ValueResolver 的错误，而这条错误会
		// 一路流进 route_health.last_error（落库）并显示在管理界面上。任何一个
		// 把值写进自己错误文本的 Secret 源，都会因此把明文同时写进数据库和 UI。
		// 这里只保留占位符名与错误链（供 errors.Is 判 ErrNotFound 之类），
		// 丢掉自由文本 —— 与 §4.3 「错误不包含 Secret」一致。
		return "", "", &valueError{placeholder: tracker.lastRequested, cause: err}
	}
	return rendered.RawQuery, tracker.identity(), nil
}

// valueError 报告一次占位符解析失败，但**不复述**下层错误文本。
//
// 保留 Unwrap 是为了让调用方仍能 errors.Is 出 store.ErrNotFound 这类哨兵，
// 拿到「Secret 不存在」与「数据库读不出来」的区别；而 Error() 只给
// 占位符名，不给任何可能含明文的自由文本。
type valueError struct {
	placeholder string
	cause       error
}

func (err *valueError) Error() string {
	if err.placeholder == "" {
		return "固定 query 的占位符无法解析"
	}
	return fmt.Sprintf("固定 query 的占位符 %q 无法解析", err.placeholder)
}

func (err *valueError) Unwrap() error { return err.cause }

// identityTracker 记录每个占位符解析到的 revision，供配置 hash 使用。
type identityTracker struct {
	inner ValueResolver
	seen  []string
	// lastRequested 是最近一次请求的占位符名，用于在渲染失败时指名问题所在
	// 而不必复述下层错误文本。
	lastRequested string
}

func (tracker *identityTracker) ResolveValue(ctx context.Context, name string) (ResolvedValue, error) {
	tracker.lastRequested = name
	value, err := tracker.inner.ResolveValue(ctx, name)
	if err != nil {
		return value, err
	}
	tracker.seen = append(tracker.seen, fmt.Sprintf("%s@%d", name, value.Revision))
	return value, nil
}

func (tracker *identityTracker) identity() string {
	// 不排序：CompiledRecipe.Render 按模板出现顺序解析，而模板顺序本身
	// 就是配置的一部分（固定 query 保序是 §7.1 的要求）。
	return strings.Join(tracker.seen, ",")
}

// joinQuery 把固定 query 与入站 RawQuery 接起来。
//
// 固定在前、入站在后（§7.1 第 5 条），只插一个 &，不解析、不排序、不去重：
// 同名参数由上游决定取第一个还是最后一个，我们无权替它决定。
func joinQuery(fixed, incoming string) string {
	switch {
	case fixed == "":
		return incoming
	case incoming == "":
		return fixed
	default:
		return fixed + "&" + incoming
	}
}

// parseOrigin 解析并校验一个 URL 的 origin 部分。
//
// 错误里**绝不包含 raw**。这条不是洁癖：legacy full URL 解密后可能带
// `?key=<secret>`（§3.2 明确提到这类站），而 url.Parse 的错误文本会原样附上
// 完整 URL。这些错误一路流进 route_health.last_error（落库）并显示在管理
// 界面上，所以带上 raw 就等于把明文 key 同时写进数据库和 UI。
//
// 只报字段名与失败原因，与 store 侧 maskLegacyURL 的口径一致（scheme+host
// 之外一律不回显）。
func parseOrigin(raw, field string) (*url.URL, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, model.WrapValidation("%s 不能为空", field)
	}
	if trimmed != raw {
		return nil, model.WrapValidation("%s 不能带首尾空白", field)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		// 刻意丢掉 err 的文本：net/url 会把完整 URL 拼进去。
		return nil, model.WrapValidation("%s 不是合法 URL", field)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, model.WrapValidation("%s 必须是 http(s)，收到 %q", field, parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, model.WrapValidation("%s 缺少主机名", field)
	}
	// userinfo 一律拒绝：`https://key@host/` 是把凭据放进 URL 的写法，
	// 它会被记进日志、样本与错误文本，而那几处的脱敏都按「头与 body」设计。
	if parsed.User != nil {
		return nil, model.WrapValidation("%s 不能包含 userinfo", field)
	}
	if parsed.Fragment != "" || parsed.RawFragment != "" || strings.Contains(raw, "#") {
		return nil, model.WrapValidation("%s 不能包含 fragment", field)
	}
	if _, err := validateHostPort(parsed.Host); err != nil {
		// host 不含 query，可以安全回显，它对定位问题是必要的。
		return nil, model.WrapValidation("%s 的 host %q 无效: %v", field, parsed.Host, err)
	}
	return parsed, nil
}

// requireSameOrigin 要求 override / legacy URL 与 base_url 同源。
//
// 跨 origin 必须另建 Upstream（§7.1）：Reachability 是站级结论，一个站的
// 结论代表了另一个网络目标就是错的 —— 表现为「A 站显示可用，实际请求全
// 打到 B 站并失败」。
func requireSameOrigin(base, other *url.URL) error {
	if !strings.EqualFold(base.Scheme, other.Scheme) {
		return model.WrapValidation("跨 origin：scheme %q != %q，请另建 Upstream",
			other.Scheme, base.Scheme)
	}
	if !strings.EqualFold(base.Hostname(), other.Hostname()) {
		return model.WrapValidation("跨 origin：host %q != %q，请另建 Upstream",
			other.Hostname(), base.Hostname())
	}
	if effectivePort(base) != effectivePort(other) {
		return model.WrapValidation("跨 origin：端口 %q != %q，请另建 Upstream",
			effectivePort(other), effectivePort(base))
	}
	return nil
}

// effectivePort 把省略的端口补成 scheme 默认值。
// 不补的话 `https://a.com` 与 `https://a.com:443` 会被判成跨 origin。
func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if strings.EqualFold(u.Scheme, "http") {
		return "80"
	}
	return "443"
}

// validateHostOverride 校验 Host 头覆盖值。
//
// 只允许 host[:port]：带 scheme 或 path 的值写进 Host 头会构造出一个畸形
// 请求行，而 CR/LF 就是请求头注入。发送前还会再验一次（P0-04 的 ApplyAuth
// 侧），两层都在。
func validateHostOverride(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	if strings.TrimSpace(raw) != raw {
		return "", model.WrapValidation("host_override 不能带首尾空白")
	}
	if _, err := validateHostPort(raw); err != nil {
		return "", model.WrapValidation("host_override 无效: %v", err)
	}
	return raw, nil
}

// validateHostPort 校验 host[:port] 形式。
//
// IPv6 必须单独处理：字面量本身含冒号（`[::1]`），直接交给 SplitHostPort 会
// 报「missing port」—— 而 `https://[::1]` 是一个完全合法的 base_url，旧的
// BuildOutboundURL 也接受它。不分这一支就是把 IPv6 上游整类拒之门外。
func validateHostPort(value string) (string, error) {
	if value == "" {
		return "", errors.New("不能为空")
	}
	for _, character := range []byte(value) {
		if character < 0x20 || character == 0x7f {
			return "", errors.New("含控制字符")
		}
		if character == ' ' {
			return "", errors.New("含空格")
		}
	}
	if strings.Contains(value, "://") || strings.ContainsAny(value, "/?#@\\") {
		return "", errors.New("只允许 host[:port]")
	}

	// IPv6 字面量：`[::1]` 或 `[::1]:8443`。
	if strings.HasPrefix(value, "[") {
		end := strings.IndexByte(value, ']')
		if end < 0 {
			return "", errors.New("IPv6 字面量缺少 ]")
		}
		inner := value[1:end]
		if inner == "" || net.ParseIP(inner) == nil {
			return "", errors.New("IPv6 字面量无效")
		}
		switch rest := value[end+1:]; {
		case rest == "":
			return value, nil
		case strings.HasPrefix(rest, ":"):
			return value, validatePort(rest[1:])
		default:
			return "", errors.New("IPv6 字面量后只能跟 :port")
		}
	}
	if strings.Contains(value, "]") {
		return "", errors.New("] 只能用于 IPv6 字面量")
	}

	if index := strings.LastIndexByte(value, ':'); index >= 0 {
		host, port := value[:index], value[index+1:]
		if host == "" {
			return "", errors.New("host 不能为空")
		}
		return value, validatePort(port)
	}
	return value, nil
}

func validatePort(port string) error {
	if port == "" {
		return errors.New("port 不能为空")
	}
	for _, character := range []byte(port) {
		if character < '0' || character > '9' {
			return errors.New("端口必须是数字")
		}
	}
	return nil
}

// validateFinalURL 是发送前的最后一道校验。
func validateFinalURL(raw string) error {
	for _, character := range []byte(raw) {
		if character < 0x20 || character == 0x7f {
			return model.WrapValidation("最终 URL 含控制字符")
		}
		if character == ' ' {
			return model.WrapValidation("最终 URL 含空格")
		}
	}
	if strings.Contains(raw, "#") {
		return model.WrapValidation("最终 URL 不能包含 fragment")
	}
	return nil
}
