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

	// 3. 认证由 outbound.ApplyAuth 写入（§7.2）。这里只保证入站的认证头
	//    已全部删除 —— 上面的 skip 表已经做到了。
	return out
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
