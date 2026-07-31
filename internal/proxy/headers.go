package proxy

import (
	"net/http"
	"strings"

	"github.com/279814/relay-gate/internal/model"
)

// hopByHopHeaders 是 RFC 7230 §6.1 规定的逐跳头，**禁止**跨连接转发。
// 转发它们会导致协议错误（如把上游的 keep-alive 参数当成客户端的）。
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// PrepareOutboundHeaders 构造出站请求头。
//
// 规则是**黑名单**而非白名单（§3.3.3）：除本函数显式处理的那几项外，
// 入站有什么头就原样发什么头，不增、不删、不改值、不补默认值。
//
// 这不是洁癖。M0 实测到按 user-agent 前缀白名单拦截的站（非 claude-cli/*
// 一律 401），也有声明「只转发 Claude Code 流量」的站。请求头是能否被放行
// 的关键，少一个或多一个都可能被拒。
//
// 已知残缺（§3.3.3）：Go 的 net/http 收到请求时即把头名规范化
// （x-api-key → X-Api-Key），且 http.Header 是无序 map，入站头序无法保留。
// 判断为可接受：HTTP/1.1 规范头名大小写不敏感，HTTP/2 更是强制全小写，
// 真实 Claude Code 直连 Anthropic 走的就是 HTTP/2；且 M0 用 curl 探测
// （头序与 Node 全然不同）各站照常放行，说明它们不做头序指纹校验。
func PrepareOutboundHeaders(in http.Header, upstreamKey string,
	style model.AuthStyle, proto model.Protocol) http.Header {

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
	skip := make(map[string]bool, len(hopByHopHeaders)+len(model.AuthHeaders)+2)
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

	// 3. 注入上游鉴权。这是**必须**改的一项（§3.3.1）。
	injectAuth(out, upstreamKey, style, proto)
	return out
}

// injectAuth 按 auth_style 写入上游 key。
//
// auto 双发是刻意的：New API / One API 对 Anthropic 端点两种头都接受，
// sub2api 的行为不一定。M0 实测 4 个可用站全部同时接受 x-api-key 与 Bearer，
// 所以 auto 覆盖面最广。极少数严格校验的站显式配 auth_style 即可。
func injectAuth(h http.Header, key string, style model.AuthStyle, proto model.Protocol) {
	if key == "" {
		// 不该发生（Upstream.APIKey 是必填），但绝不能静默发一个无鉴权请求 ——
		// 那会得到一个难以归因的 401。留空让上游明确拒绝，日志里也能看出来。
		return
	}
	switch style {
	case model.AuthXAPIKey:
		h.Set("X-Api-Key", key)
	case model.AuthBearer:
		h.Set("Authorization", "Bearer "+key)
	default: // AuthAuto
		// 两个都发。顺序无关，map 本来无序。
		h.Set("X-Api-Key", key)
		h.Set("Authorization", "Bearer "+key)
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
