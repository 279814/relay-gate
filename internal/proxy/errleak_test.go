package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 错误响应会不会把上游 key 回给客户端？
//
// 写这条测试是为了核实一个怀疑，而不是为了确认一个已知结论：
// writeForwardError 把 err.Error() 同时放进 X-Relay-Reason 头与 JSON 错误体，
// 而那个 err 来自 Transport.RoundTrip —— 内容由标准库决定，不由我们决定。
// 标准库的 *url.Error 会带上完整 URL，而 FixedQueryTemplate / legacy_exact
// 可能把 key 放在 query 里（§7.1；base_url 本身不允许 query，§5.1）。
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
	// FixedQueryTemplate 把 key 放进 query；base 指向不会有服务的端口，
	// 让失败发生在响应头阶段（那正是我们自己写错误响应的路径）。
	up := hs.cfg.snap.Upstreams[10]
	up.APIKey = secret
	up.FullURLMode = true
	up.BaseURL = "http://127.0.0.1:1/v1/messages"
	hs.h = hs.h.WithTargets(testTargetsWithQuery(hs.cfg, "key={{UPSTREAM_API_KEY}}"), nil)

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

// 上游 302 把出站 URL（含 FixedQueryTemplate 里的 key）放进 Location 时，
// 客户端拿到的 Location 绝不能含上游 key；beta=true 与 3xx 状态码保留。
// 样本 / 日志已脱敏，但客户端响应头此前原样透传 —— 那是外部调用方。
func TestRedirectLocation_NeverEchoesUpstreamKeyFromQuery(t *testing.T) {
	const secret = "sk-upstream-secret-in-location"

	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		// 回显本次请求 URL（含固定 query 里的 key + 入站 beta）。
		loc := "http://up.example" + r.URL.RequestURI()
		w.Header().Set("Location", loc)
		w.Header().Set("Content-Location", loc)
		w.Header().Set("Refresh", "0; url="+loc)
		w.WriteHeader(http.StatusFound)
		_, _ = w.Write([]byte(`{"redirect":true}`))
	})
	up := hs.cfg.snap.Upstreams[10]
	up.APIKey = secret
	hs.h = hs.h.WithTargets(testTargetsWithQuery(hs.cfg, "key={{UPSTREAM_API_KEY}}"), nil)

	r := httptest.NewRequest("POST",
		"/v1/messages?beta=true",
		strings.NewReader(`{"model":"claude-opus-5"}`))
	r.Header = claudeCodeHeaders()
	r.Header.Set("X-Api-Key", hs.relayPW)

	rec := httptest.NewRecorder()
	mux := http.NewServeMux()
	hs.h.Routes(mux)
	mux.ServeHTTP(rec, r)

	if rec.Code != http.StatusFound {
		t.Fatalf("状态码应仍是 302，got %d body=%q", rec.Code, rec.Body.String())
	}
	for _, name := range []string{"Location", "Content-Location", "Refresh"} {
		got := rec.Header().Get(name)
		if got == "" {
			t.Fatalf("%s 应透传给客户端", name)
		}
		if strings.Contains(got, secret) {
			t.Errorf("%s 回显了上游 key：%q", name, got)
		}
		if !strings.Contains(got, "beta=true") {
			t.Errorf("%s 不应丢掉无关 query：%q", name, got)
		}
	}
}
