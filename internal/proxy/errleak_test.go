package proxy

import (
	"net/http"
	"strings"
	"testing"
)

// 错误响应会不会把上游 key 回给客户端？
//
// 写这条测试是为了核实一个怀疑，而不是为了确认一个已知结论：
// writeForwardError 把 err.Error() 同时放进 X-Relay-Reason 头与 JSON 错误体，
// 而那个 err 来自 Transport.RoundTrip —— 内容由标准库决定，不由我们决定。
// 标准库的 *url.Error 会带上完整 URL，而 §3.2 提到少数站把 key 放在 query
// 里（full_url_mode 正是为它们准备的），于是 base_url 本身就含明文 key。
//
// 客户端是**外部**的：relay key 的持有者不该看到上游 key。样本落库那条
// 路径已经按 §3.6.3b 全面脱敏了（三组头 + 三份 body + query + URL），
// 而出站错误响应这条路径此前没有人看过。
//
// 实测结论（M6 时核实，值得留档）：**当前的安全是偶然的**。
// 同一个失败，两种发法给出的错误文本不同 ——
//
//	Transport.RoundTrip: "dial tcp 127.0.0.1:1: ... refused"
//	http.Client.Do:      "Post \"http://127.0.0.1:1/v1/messages?key=sk-…\": dial tcp ..."
//
// 带 URL 的 *url.Error 是 Client.Do 加的，而 forward.go 直接调 RoundTrip，
// 所以 key 现在到不了客户端。但这条性质不写在代码里 —— 谁哪天把出站改成
// 一个 *http.Client（完全自然的重构），上游 key 就会开始出现在客户端的
// 错误响应里，且不报任何错。所以 writeForwardError 里做一次脱敏，
// 让这条不变量由代码保证而不是由标准库的实现细节保证。
func TestErrorResponse_NeverEchoesUpstreamKeyFromURL(t *testing.T) {
	const secret = "sk-upstream-secret-in-query"

	hs := newHarness(t, nil)
	// full_url_mode + key 放 query，指向一个不会有服务的端口，
	// 让失败发生在响应头阶段（那正是我们自己写错误响应的路径）。
	hs.cfg.snap.Upstreams[10].FullURLMode = true
	hs.cfg.snap.Upstreams[10].BaseURL = "http://127.0.0.1:1/v1/messages?key=" + secret

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))

	if rec.Code == http.StatusOK {
		t.Fatalf("连不上上游却回了 200，body=%q", rec.Body.String())
	}

	// 头与 body 分开断言：两处都写了 err.Error()，漏掉任一处都是泄露。
	if reason := rec.Header().Get("X-Relay-Reason"); strings.Contains(reason, secret) {
		t.Errorf("X-Relay-Reason 回显了上游 key：%q", reason)
	}
	if body := rec.Body.String(); strings.Contains(body, secret) {
		t.Errorf("错误响应体回显了上游 key：%q", body)
	}
}
