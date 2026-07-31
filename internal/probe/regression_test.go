package probe

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/proxy"
)

// 「读流出错」与「假活」必须能区分开。
//
// 两者的表征相同（都是没读到有效内容），但原因相反：假活是站回了 200 却
// 不生成，读错误是超时或连接断了。混在一起报的话，排查会从「站为什么不
// 吐内容」开始，而真正该看的是「连接为什么断了」。
//
// 这个 bug 曾经存在：bufio.Scanner 把读错误藏在 Err() 里，Scan() 只返回
// false，与正常 EOF 无法区分。scanStream 不取 Err() 就把两者抹平了。
func TestL2_FirstTokenTimeoutIsNotReportedAsFakeAlive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		drainBody(r)
		// 响应头立刻回，然后一直沉默 —— 长思考的站看起来就是这样，
		// 区别只在于它最终会吐内容。
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer srv.Close()

	s := fastSettings()
	s.L2FirstTokenSec = 1
	s.L2TotalSec = 10

	out := testProber().L2(context.Background(), upstreamFor(srv.URL),
		modelNameFor(model.ProtoAnthropic), &model.Route{ID: 1}, s)

	if out.Verdict != health.VerdictUnavailable {
		t.Fatalf("首 Token 超时应判不可用，得到 %s", out.Verdict)
	}
	if out.Err == nil {
		t.Fatal("应带上失败原因")
	}
	if !errors.Is(out.Err, proxy.ErrFirstTokenTimeout) {
		t.Errorf("应归为首 Token 超时，实际错误是 %q", out.Err)
	}
	if strings.Contains(out.Err.Error(), "假活") {
		t.Errorf("超时不是假活，错误信息不该这么说：%q", out.Err)
	}
}

// 流中途被对端切断，要报「流式传输中途断开」而不是「假活」。
func TestL2_MidStreamBreakIsNotReportedAsFakeAlive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		drainBody(r)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fl, _ := w.(http.Flusher)
		// 先吐一个无效事件（心跳），确认「读到了字节但都不算有效内容」
		// 这条路径也能正确归类。
		_, _ = w.Write([]byte("event: ping\ndata: {}\n\n"))
		if fl != nil {
			fl.Flush()
		}
		panic(http.ErrAbortHandler) // 硬断连接，不走正常的 EOF
	}))
	defer srv.Close()

	s := fastSettings()
	s.L2FirstTokenSec = 5
	s.L2TotalSec = 10

	out := testProber().L2(context.Background(), upstreamFor(srv.URL),
		modelNameFor(model.ProtoAnthropic), &model.Route{ID: 1}, s)

	if out.Verdict != health.VerdictUnavailable {
		t.Fatalf("中途断流应判不可用，得到 %s", out.Verdict)
	}
	if out.Err == nil {
		t.Fatal("应带上失败原因")
	}
	if !errors.Is(out.Err, proxy.ErrStreamBroke) {
		t.Errorf("应归为中途断流，实际错误是 %q", out.Err)
	}
	if strings.Contains(out.Err.Error(), "假活") {
		t.Errorf("断流不是假活，错误信息不该这么说：%q", out.Err)
	}
}

// 真的假活（正常 EOF、无有效内容）仍然要报假活。
//
// 与上面两个测试配对：修掉误报之后，真正的假活不能跟着一起失效。
func TestL2_GenuineFakeAliveStillReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		drainBody(r)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		// 吐几个无效事件然后正常收尾 —— 这是公益站最常见的假活形态。
		_, _ = w.Write([]byte("event: ping\ndata: {}\n\nevent: ping\ndata: {}\n\n"))
	}))
	defer srv.Close()

	out := testProber().L2(context.Background(), upstreamFor(srv.URL),
		modelNameFor(model.ProtoAnthropic), &model.Route{ID: 1}, fastSettings())

	if out.Verdict != health.VerdictUnavailable {
		t.Fatalf("假活应判不可用，得到 %s", out.Verdict)
	}
	if out.Err == nil || !strings.Contains(out.Err.Error(), "假活") {
		t.Errorf("应明确报假活，实际错误是 %v", out.Err)
	}
}

// 401/403 一律致命，即使响应体里含限流关键词（§4.3）。
//
// 这个 bug 曾经存在：rateLimitMarkers 含 "quota"，而关键词分支排在 401/403
// 之前，于是「余额耗尽」的 401 被判成限流 —— 冷却 60 秒后再试，永远不判死。
// 而余额耗尽只能靠人去充值或换 key，等它自愈是等不到的。
func TestClassifyHTTP_AuthErrorIsFatalEvenWithQuotaWording(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"insufficient_quota", `{"error":{"message":"insufficient_quota","type":"invalid_request_error"}}`},
		{"exceeded your quota", `{"error":{"message":"You exceeded your current quota"}}`},
		{"额度不足", `{"error":{"message":"当前分组额度不足 quota exhausted"}}`},
		{"rate limit 字样", `{"error":{"message":"rate limit exceeded for this key"}}`},
	}
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		for _, c := range cases {
			out := ClassifyHTTP(status, nil, []byte(c.body))
			if out.Verdict != health.VerdictFatal {
				t.Errorf("HTTP %d + %s：应判致命（鉴权/配置错误），得到 %s",
					status, c.name, out.Verdict)
			}
		}
	}
}

// 但 429 与 5xx 里的限流关键词仍然要判限流，不能被上一条改坏。
func TestClassifyHTTP_RateLimitStillDetectedOutsideAuthErrors(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   health.Verdict
	}{
		{"429", 429, `{"error":{"message":"too many requests"}}`, health.VerdictRateLimited},
		{"529 overloaded", 529, `{"type":"error","error":{"type":"overloaded_error"}}`,
			health.VerdictRateLimited},
		{"400 quota", 400, `{"error":{"message":"quota exceeded"}}`, health.VerdictRateLimited},
		{"500 普通故障", 500, `{"error":"internal"}`, health.VerdictUnavailable},
		{"400 model not found", 400, `{"error":{"message":"model not found"}}`,
			health.VerdictFatal},
	}
	for _, c := range cases {
		out := ClassifyHTTP(c.status, nil, []byte(c.body))
		if out.Verdict != c.want {
			t.Errorf("%s：期望 %s，得到 %s", c.name, c.want, out.Verdict)
		}
	}
}
