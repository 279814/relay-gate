package proxy

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
)

// 真实 Claude Code 的头集合（M0 抓包所得）。用它做基准，
// 断言除黑名单外一个都不少、一个都不多。
func claudeCodeHeaders() http.Header {
	h := http.Header{}
	h.Set("X-Api-Key", "rk-relay-key-from-client")
	h.Set("Anthropic-Version", "2023-06-01")
	h.Set("Anthropic-Beta", "claude-code-20250219,interleaved-thinking-2025-05-14,context-management-2025-06-27")
	h.Set("Content-Type", "application/json")
	h.Set("Accept", "application/json")
	h.Set("User-Agent", "claude-cli/2.1.220 (external, sdk-cli)")
	h.Set("X-App", "cli")
	h.Set("Anthropic-Dangerous-Direct-Browser-Access", "true")
	h.Set("X-Stainless-Lang", "js")
	h.Set("X-Stainless-Package-Version", "0.94.0")
	h.Set("X-Stainless-Os", "Windows")
	h.Set("X-Stainless-Arch", "x64")
	h.Set("X-Stainless-Runtime", "node")
	h.Set("X-Stainless-Retry-Count", "0")
	h.Set("Accept-Encoding", "gzip, deflate")
	h.Set("Accept-Language", "*")
	return h
}

// applyOutboundAuth 走完整的出站头构造：透传 + 唯一的认证改写。
//
// 认证注入已从 PrepareOutboundHeaders 搬到 outbound.ApplyAuth（§7.2），
// 但「出站头集合恰好是什么」这条断言必须继续覆盖两者的**组合结果** ——
// 只测其中一半的话，删头与写头之间的衔接就没人看着了，而漏删一个认证别名
// 就是把用户的 relay key 送给公益站。
func applyOutboundAuth(t *testing.T, in http.Header, key string,
	mode model.AuthMode) http.Header {

	t.Helper()
	out := PrepareOutboundHeaders(in, model.ProtoAnthropic)
	err := outbound.ApplyAuth(context.Background(), out, outbound.AuthInput{
		Profile: model.EndpointAuthProfile{Mode: mode, SecretRef: "upstream_api_key", Revision: 1},
		Values:  outbound.Values{UpstreamAPIKey: []byte(key), CredentialRevision: 1},
	})
	if err != nil {
		t.Fatalf("ApplyAuth 失败: %v", err)
	}
	return out
}

// 核心断言：出站头集合 = 入站头集合 - 黑名单 + 恰好一个鉴权头。
// 多出或少掉任何一个头都算失败 —— 不是「关键头都在就行」，
// 那样会漏掉计划外的注入。
func TestPrepareOutboundHeaders_ExactSetDiff(t *testing.T) {
	in := claudeCodeHeaders()
	out := applyOutboundAuth(t, in, "sk-upstream-key", model.AuthModeXAPIKey)

	// 入站有、出站也该有的（黑名单之外的全部）
	wantKept := []string{
		"Anthropic-Version", "Anthropic-Beta", "Content-Type", "Accept",
		"User-Agent", "X-App", "Anthropic-Dangerous-Direct-Browser-Access",
		"X-Stainless-Lang", "X-Stainless-Package-Version", "X-Stainless-Os",
		"X-Stainless-Arch", "X-Stainless-Runtime", "X-Stainless-Retry-Count",
		"Accept-Encoding", "Accept-Language",
	}
	for _, k := range wantKept {
		if out.Get(k) != in.Get(k) {
			t.Errorf("头 %s 应原样转发：入站 %q，出站 %q", k, in.Get(k), out.Get(k))
		}
	}

	// 出站应有且仅有：wantKept + 那**一个**鉴权头。
	// x_api_key profile 只写 X-Api-Key，不再双发（§7.2）。
	wantSet := map[string]bool{}
	for _, k := range wantKept {
		wantSet[http.CanonicalHeaderKey(k)] = true
	}
	wantSet["X-Api-Key"] = true

	var unexpected []string
	for k := range out {
		if !wantSet[http.CanonicalHeaderKey(k)] {
			unexpected = append(unexpected, k)
		}
	}
	if len(unexpected) > 0 {
		sort.Strings(unexpected)
		t.Errorf("出站多出了计划外的头：%v", unexpected)
	}
	if len(out) != len(wantSet) {
		var got []string
		for k := range out {
			got = append(got, k)
		}
		sort.Strings(got)
		t.Errorf("出站头数量应为 %d，实际 %d：%v", len(wantSet), len(out), got)
	}
}

// relay key 绝不能泄露给公益站。
func TestPrepareOutboundHeaders_ReplacesKey(t *testing.T) {
	const relayKey = "rk-relay-key-from-client"
	const upKey = "sk-upstream-real-key"

	in := claudeCodeHeaders()
	in.Set("Authorization", "Bearer "+relayKey) // 两个位置都带
	in.Set("Api-Key", relayKey)                 // 非标准位置也带

	out := applyOutboundAuth(t, in, upKey, model.AuthModeXAPIKey)

	// 遍历所有头值，确认 relay key 一个字都没漏出去
	for k, vs := range out {
		for _, v := range vs {
			if strings.Contains(v, relayKey) {
				t.Errorf("relay key 泄露到出站头 %s: %q", k, v)
			}
		}
	}
	if out.Get("X-Api-Key") != upKey {
		t.Errorf("X-Api-Key 应为上游 key，得到 %q", out.Get("X-Api-Key"))
	}
	// 另两个位置必须为空：只发一种认证，且入站的 relay key 已删干净。
	for _, name := range []string{"Authorization", "Api-Key"} {
		if got := out.Get(name); got != "" {
			t.Errorf("%s 应被删除，得到 %q", name, got)
		}
	}
}

// PrepareOutboundHeaders **自己**不写认证：认证只有 ApplyAuth 一个来源（§7.2）。
//
// 它仍必须把入站的认证别名全部删掉 —— 那是 relay key 不泄露的前提，
// 而 ApplyAuth 是否被调用不该影响这一条。
func TestPrepareOutboundHeaders_StripsInboundAuthWithoutInjecting(t *testing.T) {
	in := claudeCodeHeaders()
	in.Set("Authorization", "Bearer rk-client")
	in.Set("X-Api-Key", "rk-client")
	in.Set("Api-Key", "rk-client")

	out := PrepareOutboundHeaders(in, model.ProtoAnthropic)
	for _, name := range model.AuthHeaders {
		if got := out.Get(name); got != "" {
			t.Errorf("入站认证头 %s 必须删除（否则 relay key 会漏给上游），得到 %q",
				name, got)
		}
	}
}

func TestPrepareOutboundHeaders_StripsHopByHop(t *testing.T) {
	in := claudeCodeHeaders()
	in.Set("Connection", "keep-alive")
	in.Set("Keep-Alive", "timeout=5")
	in.Set("Transfer-Encoding", "chunked")
	in.Set("TE", "trailers")
	in.Set("Trailer", "Expires")
	in.Set("Upgrade", "websocket")
	in.Set("Proxy-Authorization", "Basic abc")
	in.Set("Proxy-Authenticate", "Basic")
	// 非标准但 libcurl 仍发；漏删会被部分上游拒（与 Go ReverseProxy 同列）。
	in.Set("Proxy-Connection", "keep-alive")

	out := PrepareOutboundHeaders(in, model.ProtoAnthropic)
	for _, k := range hopByHopHeaders {
		if out.Get(k) != "" {
			t.Errorf("逐跳头 %s 不应转发，得到 %q", k, out.Get(k))
		}
	}
}

// Connection 里点名的自定义头也是逐跳的，RFC 要求逐跳清理。
func TestPrepareOutboundHeaders_StripsConnectionListedHeaders(t *testing.T) {
	in := claudeCodeHeaders()
	in.Set("Connection", "keep-alive, X-Custom-Hop, X-Another")
	in.Set("X-Custom-Hop", "should-be-dropped")
	in.Set("X-Another", "also-dropped")
	in.Set("X-Kept", "should-survive")

	out := PrepareOutboundHeaders(in, model.ProtoAnthropic)
	if out.Get("X-Custom-Hop") != "" {
		t.Error("Connection 中列出的 X-Custom-Hop 应被删除")
	}
	if out.Get("X-Another") != "" {
		t.Error("Connection 中列出的 X-Another 应被删除")
	}
	if out.Get("X-Kept") != "should-survive" {
		t.Error("未在 Connection 中列出的头应保留")
	}
}

// Content-Length 必须由 http 库按新 body 重算：改 model 后长度可能变，
// 不重算会截断 body 或让请求挂起。
func TestPrepareOutboundHeaders_DropsLengthAndHost(t *testing.T) {
	in := claudeCodeHeaders()
	in.Set("Content-Length", "12345")
	in.Set("Host", "relay.example.com")

	out := PrepareOutboundHeaders(in, model.ProtoAnthropic)
	if out.Get("Content-Length") != "" {
		t.Error("Content-Length 应交给 http 库重算")
	}
	if out.Get("Host") != "" {
		t.Error("Host 应由 Request.Host 决定，不走 Header")
	}
}

// 大小写不同的写法必须一样被删掉，否则会漏删导致 relay key 泄露。
func TestPrepareOutboundHeaders_CaseInsensitiveBlacklist(t *testing.T) {
	// 直接构造非规范大小写的 map key，模拟绕过 Header.Set 的情况
	in := http.Header{
		"authorization":     {"Bearer rk-leak"},
		"X-API-KEY":         {"rk-leak-2"},
		"api-key":           {"rk-leak-3"},
		"CONTENT-LENGTH":    {"999"},
		"transfer-encoding": {"chunked"},
		"content-type":      {"application/json"},
	}
	out := PrepareOutboundHeaders(in, model.ProtoAnthropic)

	for k, vs := range out {
		for _, v := range vs {
			if strings.Contains(v, "rk-leak") {
				t.Errorf("非规范大小写的鉴权头未被删除，relay key 泄露在 %s: %q", k, v)
			}
		}
	}
	if out.Get("Content-Length") != "" || out.Get("Transfer-Encoding") != "" {
		t.Error("非规范大小写的黑名单头未被删除")
	}
	if out.Get("Content-Type") != "application/json" {
		t.Error("content-type 应被规范化并保留")
	}
}

// 多值头（如多个 anthropic-beta）必须全部保留，不能只留第一个。
func TestPrepareOutboundHeaders_PreservesMultiValue(t *testing.T) {
	in := http.Header{}
	in.Add("Anthropic-Beta", "feature-a")
	in.Add("Anthropic-Beta", "feature-b")
	in.Add("Anthropic-Beta", "feature-c")

	out := PrepareOutboundHeaders(in, model.ProtoAnthropic)
	got := out.Values("Anthropic-Beta")
	if len(got) != 3 || got[0] != "feature-a" || got[2] != "feature-c" {
		t.Errorf("多值头应全部保留且保持顺序，得到 %v", got)
	}
}

// 出站头不能与入站共享底层数组：样本记录还要读入站请求。
func TestPrepareOutboundHeaders_DoesNotAliasInput(t *testing.T) {
	in := claudeCodeHeaders()
	out := PrepareOutboundHeaders(in, model.ProtoAnthropic)

	out.Set("User-Agent", "mutated")
	if in.Get("User-Agent") != "claude-cli/2.1.220 (external, sdk-cli)" {
		t.Error("修改出站头影响了入站请求对象")
	}
	// 反向也要成立
	in.Set("Accept", "text/plain")
	if out.Get("Accept") == "text/plain" {
		t.Error("修改入站头影响了出站头")
	}
}

// accept-encoding 必须原样转发（§3.3.4）：配合 DisableCompression=true，
// 响应体字节流原样回传，零解压零重压。
func TestPrepareOutboundHeaders_ForwardsAcceptEncoding(t *testing.T) {
	in := claudeCodeHeaders()
	in.Set("Accept-Encoding", "gzip, br, zstd")
	out := PrepareOutboundHeaders(in, model.ProtoAnthropic)
	if out.Get("Accept-Encoding") != "gzip, br, zstd" {
		t.Errorf("Accept-Encoding 应原样转发，得到 %q", out.Get("Accept-Encoding"))
	}
}

// 管理会话 Cookie 绝不能随 /v1/messages 透传到上游；其它 Cookie 与业务头照常转发。
// 管理口令只服务 /admin/api，绝不能随 /v1/* 出站。
func TestPrepareOutboundHeaders_StripsAdminPassword(t *testing.T) {
	const adminPW = "super-secret-admin-password-value"
	in := claudeCodeHeaders()
	in.Set("X-Admin-Password", adminPW)

	out := PrepareOutboundHeaders(in, model.ProtoAnthropic)
	if got := out.Get("X-Admin-Password"); got != "" {
		t.Errorf("X-Admin-Password 绝不能到达上游，得到 %q", got)
	}
	for k, vs := range out {
		for _, v := range vs {
			if strings.Contains(v, adminPW) {
				t.Errorf("管理口令泄漏到出站头 %s: %q", k, v)
			}
		}
	}
	// 非秘密的端到端头必须保留（黑名单剥离不能误伤）。
	if out.Get("Anthropic-Version") != in.Get("Anthropic-Version") {
		t.Errorf("Anthropic-Version 应原样转发，得到 %q", out.Get("Anthropic-Version"))
	}
	if out.Get("Anthropic-Beta") != in.Get("Anthropic-Beta") {
		t.Errorf("Anthropic-Beta 应原样转发，得到 %q", out.Get("Anthropic-Beta"))
	}
}

func TestPrepareOutboundHeaders_StripsGatewaySessionCookie(t *testing.T) {
	const sessionTok = "admin-session-token-must-not-leak"
	in := claudeCodeHeaders()
	in.Set("Cookie", gatewaySessionCookie+"="+sessionTok+"; unrelated=keep-me")

	out := PrepareOutboundHeaders(in, model.ProtoAnthropic)

	cookie := out.Get("Cookie")
	if strings.Contains(cookie, gatewaySessionCookie) {
		t.Errorf("出站 Cookie 仍含会话名 %q", gatewaySessionCookie)
	}
	if strings.Contains(cookie, sessionTok) {
		t.Error("出站 Cookie 仍含会话令牌")
	}
	if !strings.Contains(cookie, "unrelated=keep-me") {
		t.Errorf("无关 Cookie 应保留，得到 %q", cookie)
	}
	if out.Get("Anthropic-Version") != "2023-06-01" {
		t.Errorf("Anthropic-Version 应原样转发，得到 %q", out.Get("Anthropic-Version"))
	}

	// 仅有会话 Cookie 时整头删掉。
	only := http.Header{}
	only.Set("Cookie", gatewaySessionCookie+"="+sessionTok)
	onlyOut := PrepareOutboundHeaders(only, model.ProtoAnthropic)
	if _, ok := onlyOut["Cookie"]; ok {
		t.Errorf("仅含会话 Cookie 时应删除 Cookie 头，得到 %q", onlyOut.Get("Cookie"))
	}
}

func TestStripHopByHopResponse(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "text/event-stream")
	h.Set("Connection", "close, X-Upstream-Hop")
	h.Set("X-Upstream-Hop", "dropped")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("X-Request-Id", "req-123")

	StripHopByHopResponse(h)

	if h.Get("Connection") != "" || h.Get("Keep-Alive") != "" {
		t.Error("响应的逐跳头应被清理")
	}
	if h.Get("X-Upstream-Hop") != "" {
		t.Error("Connection 中列出的头应被清理")
	}
	if h.Get("Content-Type") != "text/event-stream" {
		t.Error("Content-Type 必须保留，否则 SSE 会被客户端误解析")
	}
	if h.Get("X-Request-Id") != "req-123" {
		t.Error("普通响应头应保留")
	}
}

// §10.4：X-Relay-Count-Tokens 只出现在网关生成的本地估算；上游同名头必须丢掉。
// 其它端到端头与其它 X-Relay-* 名保留（不在此路径批量剥离）。
func TestFinalizeClientResponseHeaders_DropsUpstreamCountTokens(t *testing.T) {
	h := http.Header{}
	h.Set(headerRelayCountTokens, "estimated")
	h.Set("X-Relay-Attempts", "2") // 不得因剥 Count-Tokens 而误删
	h.Set("X-Request-Id", "req-keep")
	h.Set("Content-Type", "application/json")
	h.Set("Connection", "close")

	FinalizeClientResponseHeaders(h, nil)

	if got := h.Get(headerRelayCountTokens); got != "" {
		t.Fatalf("X-Relay-Count-Tokens = %q, want stripped", got)
	}
	if h.Get("X-Relay-Attempts") != "2" {
		t.Error("其它 X-Relay-* 头不得被剥离")
	}
	if h.Get("X-Request-Id") != "req-keep" {
		t.Error("普通端到端头应保留")
	}
	if h.Get("Content-Type") != "application/json" {
		t.Error("Content-Type 应保留")
	}
	if h.Get("Connection") != "" {
		t.Error("逐跳头仍应被清理")
	}
}

// 上游 Set-Cookie 不能覆盖管理会话；其它 Set-Cookie 继续透传。
// 匹配与出站 Cookie 剥离相同：cookie 名大小写敏感全等，不看 value。
func TestFinalizeClientResponseHeaders_DropsGatewaySessionSetCookie(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", gatewaySessionCookie+"=evil-from-upstream; Path=/; HttpOnly")
	h.Add("Set-Cookie", "other=1")
	h.Add("Set-Cookie", "Relay_Session=case-differs") // 大小写不同，应保留
	h.Add("Set-Cookie", "prefix_"+gatewaySessionCookie+"=not-exact")
	h.Add("Set-Cookie", "keep=has-"+gatewaySessionCookie+"-in-value")
	h.Set("Connection", "close")
	h.Set("X-Request-Id", "req-keep")

	FinalizeClientResponseHeaders(h, nil)

	got := h.Values("Set-Cookie")
	for _, line := range got {
		first, _, _ := strings.Cut(line, ";")
		name, _, _ := strings.Cut(first, "=")
		if strings.TrimSpace(name) == gatewaySessionCookie {
			t.Fatalf("客户端响应仍含会话 Set-Cookie: %q", line)
		}
	}
	wantKeep := map[string]bool{
		"other=1":                    false,
		"Relay_Session=case-differs": false,
		"prefix_" + gatewaySessionCookie + "=not-exact":  false,
		"keep=has-" + gatewaySessionCookie + "-in-value": false,
	}
	for _, line := range got {
		if _, ok := wantKeep[line]; ok {
			wantKeep[line] = true
		}
	}
	for line, ok := range wantKeep {
		if !ok {
			t.Errorf("应保留的 Set-Cookie 丢失: %q；得到 %v", line, got)
		}
	}
	if h.Get("Connection") != "" {
		t.Error("逐跳头仍应被清理")
	}
	if h.Get("X-Request-Id") != "req-keep" {
		t.Error("普通响应头应保留")
	}
}

// 上游 3xx Location（及 Content-Location / Refresh）若回显出站 URL，
// FixedQueryTemplate 里的上游 key 绝不能原样到客户端；beta=true 等无关
// query 与头本身必须保留。
func TestFinalizeClientResponseHeaders_RedactsCredentialQueryInURLHeaders(t *testing.T) {
	const secret = "sk-upstream-secret-in-location"
	h := http.Header{}
	h.Set("Location", "https://up.example/v1/messages?key="+secret+"&beta=true")
	h.Set("Content-Location", "https://up.example/v1/messages?key="+secret+"&beta=true")
	h.Set("Refresh", "0; url=https://up.example/v1?key="+secret+"&beta=true")
	h.Set("X-Request-Id", "req-keep")

	FinalizeClientResponseHeaders(h, []string{secret})

	for _, name := range []string{"Location", "Content-Location", "Refresh"} {
		got := h.Get(name)
		if strings.Contains(got, secret) {
			t.Errorf("%s 回显了上游 key：%q", name, got)
		}
		if !strings.Contains(got, "beta=true") {
			t.Errorf("%s 不应丢掉无关 query：%q", name, got)
		}
	}
	if h.Get("X-Request-Id") != "req-keep" {
		t.Error("普通响应头应保留")
	}
	// 无 keys 时不得改写 Location（低层 Forward 路径）。
	plain := http.Header{}
	plain.Set("Location", "https://up.example/path?beta=true")
	FinalizeClientResponseHeaders(plain, nil)
	if plain.Get("Location") != "https://up.example/path?beta=true" {
		t.Errorf("无 keys 时 Location 应原样：%q", plain.Get("Location"))
	}
}

