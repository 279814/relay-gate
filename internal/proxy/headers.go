package proxy

import (
	"net/http"
	"strings"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/sample"
)

// hopByHopHeaders 是 RFC 7230 §6.1 规定的逐跳头，**禁止**跨连接转发。
// 转发它们会导致协议错误（如把上游的 keep-alive 参数当成客户端的）。
//
// 取 model 的那份唯一清单，不在这里另抄一份：Recipe 的编译期拒绝
// （probetemplate）用的是同一份，而两处各抄一份必然分叉 —— 分叉的那一半
// 是「看起来在防、实际没防」。
var hopByHopHeaders = model.HopByHopHeaders

// gatewaySessionCookie 是管理界面会话 Cookie 名，必须与 api 包的
// sessionCookie（"relay_session"）保持一致。
//
// 黑名单透传会把 Cookie 原样带给上游；会话令牌只属于本进程，绝不能
// 离开网关。只剥这一颗，其它 Cookie 继续透传 —— 不做通用 Cookie 策略。
const gatewaySessionCookie = "relay_session"

// PrepareOutboundHeaders 构造出站请求头。
//
// 规则是**黑名单**而非白名单（§3.3.3）：除本函数显式处理的那几项外，
// 入站有什么头就原样发什么头，不增、不删、不改值、不补默认值。
//
// 这不是洁癖。M0 实测到按 user-agent 前缀白名单拦截的站（非 claude-cli/*
// 一律 401），也有声明「只转发 Claude Code 流量」的站。请求头是能否被放行
// 的关键，少一个或多一个都可能被拒。
//
// **不注入认证**：那是 outbound.ApplyAuth 的唯一职责（§7.2）。本函数只
// 负责删掉入站的认证别名 —— 它必须删，否则用户的 relay key 会漏给上游；
// 但「该发哪一种」由 Endpoint 的 auth profile 决定，而那份信息在这里拿不到。
// 两件事各在一处，认证规则就只有一份实现。
//
// 已知残缺（§3.3.3）：Go 的 net/http 收到请求时即把头名规范化
// （x-api-key → X-Api-Key），且 http.Header 是无序 map，入站头序无法保留。
// 判断为可接受：HTTP/1.1 规范头名大小写不敏感，HTTP/2 更是强制全小写，
// 真实 Claude Code 直连 Anthropic 走的就是 HTTP/2；且 M0 用 curl 探测
// （头序与 Node 全然不同）各站照常放行，说明它们不做头序指纹校验。
func PrepareOutboundHeaders(in http.Header, proto model.Protocol) http.Header {
	out := make(http.Header, len(in)+2)

	// 1. Connection 里列出的头也是逐跳的，RFC 要求逐跳清理。
	//    必须先算出来，否则下面复制时会把它们带过去。
	connTokens := map[string]bool{}
	for _, v := range in.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if tok = strings.TrimSpace(tok); tok != "" {
				connTokens[http.CanonicalHeaderKey(tok)] = true
			}
		}
	}

	// 2. 全量复制，只跳过必须删的。
	//    用 textproto 的规范形式做比较，避免大小写导致漏删。
	skip := make(map[string]bool, len(hopByHopHeaders)+len(model.AuthHeaders)+3)
	for _, h := range hopByHopHeaders {
		skip[http.CanonicalHeaderKey(h)] = true
	}
	// 鉴权头必须**全部删除**，再按 auth_style 注入上游 key ——
	// 漏一个就是把用户的 relay key 直接送给公益站。
	for _, h := range model.AuthHeaders {
		skip[http.CanonicalHeaderKey(h)] = true
	}
	// Host 由 http.Request.Host 决定，不走 Header（放这里是为了防御
	// 客户端显式塞了 Host 头）。Content-Length 由 http 库按新 body 重算。
	skip["Host"] = true
	skip["Content-Length"] = true
	// 管理口令只属于本进程的 /admin/api（bearerOK），绝不能随 /v1/* 出站。
	// 不放进 AuthHeaders：那份清单是 upstream API key 位置，ApplyAuth 会
	// 按它重写；管理口令不是上游凭据，只删不写。
	skip["X-Admin-Password"] = true

	for k, vs := range in {
		ck := http.CanonicalHeaderKey(k)
		if skip[ck] || connTokens[ck] {
			continue
		}
		// 复制切片而不是共享底层数组：出站头若被后续修改，
		// 不应影响入站请求对象（样本记录还要读它）。
		cp := make([]string, len(vs))
		copy(cp, vs)
		out[ck] = cp
	}

	// 3. 剥掉本网关的管理会话 Cookie，其它 Cookie 保留。
	stripGatewaySessionCookie(out)

	// 4. 认证由 outbound.ApplyAuth 写入（§7.2）。这里只保证入站的认证头
	//    已全部删除 —— 上面的 skip 表已经做到了。
	return out
}

// stripGatewaySessionCookie 从出站 Cookie 头里去掉 gatewaySessionCookie。
// 只剩会话 Cookie 时删掉整个 Cookie 头；其它 Cookie 原样留下。
// 不记录 Cookie 值 —— 会话令牌进日志等于泄露。
func stripGatewaySessionCookie(h http.Header) {
	vals := h.Values("Cookie")
	if len(vals) == 0 {
		return
	}
	kept := make([]string, 0, len(vals))
	for _, line := range vals {
		parts := strings.Split(line, ";")
		filtered := make([]string, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			name, _, _ := strings.Cut(part, "=")
			if strings.TrimSpace(name) == gatewaySessionCookie {
				continue
			}
			filtered = append(filtered, part)
		}
		if len(filtered) > 0 {
			kept = append(kept, strings.Join(filtered, "; "))
		}
	}
	h.Del("Cookie")
	for _, v := range kept {
		h.Add("Cookie", v)
	}
}

// StripHopByHopResponse 清理上游响应里的逐跳头。
//
// 响应方向的原则是「完全不碰」（§3.3），但逐跳头是 HTTP 协议层的要求，
// 不是内容：把上游连接的 Connection: close 转给客户端会让客户端误以为
// 该关掉与**本网关**的连接。ReverseProxy 已处理这些，此函数供手写转发路径用。
func StripHopByHopResponse(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if tok = strings.TrimSpace(tok); tok != "" {
				h.Del(tok)
			}
		}
	}
	for _, k := range hopByHopHeaders {
		h.Del(k)
	}
}

// headerRelayCountTokens 是本地 count_tokens 估算响应专用的诊断头（§10.4）。
// 只允许网关在 localCountTokens 写出；上游若回同名头必须在抄给客户端前丢掉，
// 否则客户端会把上游伪造的 estimated 当成网关本地估算。
const headerRelayCountTokens = "X-Relay-Count-Tokens"

// FinalizeClientResponseHeaders 在把上游响应头写给客户端之前做最后清理：
// 逐跳头 + 本网关会话 Cookie 的 Set-Cookie + 上游伪造的 X-Relay-Count-Tokens
// + Location / Content-Location / Refresh / Link 里的凭据 query
// + 其它 Set-Cookie 值里的已知 Secret。
//
// keys 是已知 Secret（上游 key、relay key、transform secret_ref）。上游 3xx
// 常把出站 URL 原样放进 Location；Link 也可能把带 key 的 URL 放进尖括号；
// FixedQueryTemplate / legacy_exact 可能把 key 放在 query 里（§7.1）；上游
// 也可能把 key 写进 Set-Cookie —— 不脱敏就等于把上游 key 交给外部客户端。
// 脱敏复用 sample.RedactText：只替凭据值，beta=true、rel=、无关 cookie 与
// Path/HttpOnly 等属性不动。
//
// 其它 Set-Cookie 照常透传（仅遮凭据子串）；管理登录走 api 包自己的
// SetCookie，不经此路径。其它 X-Relay-* 不在这里剥 —— 成功透传不得新增
// Attempts/Half-Open，但也不该在此路径上批量抹掉；Count-Tokens 是文档明确
// 「只出现在网关生成响应」的那一个。
// 不记录 Cookie 值 —— 会话令牌进日志等于泄露。
func FinalizeClientResponseHeaders(h http.Header, keys []string) {
	StripHopByHopResponse(h)
	stripGatewaySessionSetCookie(h)
	h.Del(headerRelayCountTokens)
	sample.RedactCredentialURLHeaders(h, keys)
	sample.RedactCredentialSetCookie(h, keys)
}

// stripGatewaySessionSetCookie 丢掉 cookie-name 恰为 gatewaySessionCookie
// 的 Set-Cookie。匹配方式与出站 Cookie 剥离一致：对 cookie 名做大小写敏感
// 的全等比较，不看 value，也不做子串匹配。
func stripGatewaySessionSetCookie(h http.Header) {
	vals := h.Values("Set-Cookie")
	if len(vals) == 0 {
		return
	}
	kept := make([]string, 0, len(vals))
	for _, line := range vals {
		first, _, _ := strings.Cut(line, ";")
		name, _, _ := strings.Cut(first, "=")
		if strings.TrimSpace(name) == gatewaySessionCookie {
			continue
		}
		kept = append(kept, line)
	}
	h.Del("Set-Cookie")
	for _, v := range kept {
		h.Add("Set-Cookie", v)
	}
}
