package probe

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/proxy"
)

func TestClassifyHTTP(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		want    health.Verdict
		wantErr string // 期望错误信息里含这段原文
	}{
		{"200 正常", 200, `{"ok":true}`, health.VerdictOK, ""},

		// 致命类：改配置才能好，重试无意义
		{"401 鉴权失败", 401, `{"error":"invalid api key"}`, health.VerdictFatal, "invalid api key"},
		{"403 禁止", 403, `forbidden`, health.VerdictFatal, ""},
		{"400 模型不存在", 400, `{"error":{"message":"model_not_found"}}`, health.VerdictFatal, ""},
		{"404 模型不存在", 404, `{"error":"no such model: opus-9"}`, health.VerdictFatal, ""},
		{"400 invalid model", 400, `{"error":"invalid model specified"}`, health.VerdictFatal, ""},

		// 限流类：站是好的，只是这会儿满了
		{"429", 429, `{"error":"slow down"}`, health.VerdictRateLimited, ""},
		{"529 overloaded 走限流而非 5xx", 529, `{"type":"overloaded_error"}`, health.VerdictRateLimited, ""},
		{"503 里含 rate limit", 503, `{"error":"rate limit exceeded"}`, health.VerdictRateLimited, ""},
		{"400 里含 quota", 400, `{"error":"quota exhausted"}`, health.VerdictRateLimited, ""},

		// 不可用类：等它恢复
		{"500", 500, `internal error`, health.VerdictUnavailable, ""},
		{"502", 502, `bad gateway`, health.VerdictUnavailable, ""},
		{"503", 503, `unavailable`, health.VerdictUnavailable, ""},
		// 未预料到的 4xx 保守归到累计类：探活请求是我们构造的，
		// 一个意外的 400 更可能是「这站参数要求特殊」而非「站坏了」
		{"意外的 400", 400, `{"error":"missing field foo"}`, health.VerdictUnavailable, "missing field foo"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := ClassifyHTTP(tc.status, nil, []byte(tc.body))
			if out.Verdict != tc.want {
				t.Errorf("status %d body %q：期望 %s，得到 %s（err=%v）",
					tc.status, tc.body, tc.want, out.Verdict, out.Err)
			}
			if out.Status != tc.status {
				t.Errorf("Status 应原样带出，期望 %d 得到 %d", tc.status, out.Status)
			}
			if tc.wantErr != "" {
				if out.Err == nil || !contains(out.Err.Error(), tc.wantErr) {
					t.Errorf("错误信息应含上游原文 %q，得到 %v", tc.wantErr, out.Err)
				}
			}
		})
	}
}

// 限流判定必须在 5xx 之前。529 overloaded 是 5xx 但属于限流 ——
// 判错的后果是把一个「太受欢迎」的可用站累计判死。
func TestClassifyHTTP_RateLimitTakesPrecedenceOverServerError(t *testing.T) {
	out := ClassifyHTTP(500, nil, []byte(`{"error":{"type":"overloaded_error"}}`))
	if out.Verdict != health.VerdictRateLimited {
		t.Errorf("5xx 里的限流特征应判为限流，得到 %s", out.Verdict)
	}
}

// 模型不存在要在通用 4xx 之前判：同为 400，但一个要改配置、一个等恢复。
func TestClassifyHTTP_ModelNotFoundTakesPrecedenceOverGeneric4xx(t *testing.T) {
	out := ClassifyHTTP(400, nil, []byte(`{"error":{"type":"invalid_request_error","message":"model not found"}}`))
	if out.Verdict != health.VerdictFatal {
		t.Errorf("模型不存在应立即判死（UI 标「配置错误」），得到 %s", out.Verdict)
	}
}

func TestParseRetryAfter(t *testing.T) {
	tests := []struct {
		name string
		val  string
		want time.Duration
	}{
		{"秒数", "120", 120 * time.Second},
		{"缺失", "", 0},
		{"零", "0", 0},
		{"负数", "-5", 0},
		{"非数字（HTTP 日期形式不支持，回落到默认冷却）", "Wed, 21 Oct 2026 07:28:00 GMT", 0},
		// 上限保护：上游误填毫秒会把站冷藏几小时，而它早就恢复了
		{"超大值被截到上限", "999999", maxRetryAfter},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.val != "" {
				h.Set("Retry-After", tc.val)
			}
			if got := parseRetryAfter(h); got != tc.want {
				t.Errorf("Retry-After %q：期望 %v，得到 %v", tc.val, tc.want, got)
			}
		})
	}
}

func TestClassifyHTTP_PassesRetryAfterThrough(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", "300")
	out := ClassifyHTTP(429, h, []byte(`{}`))
	if out.RetryAfter != 300*time.Second {
		t.Errorf("429 应带出 Retry-After，得到 %v", out.RetryAfter)
	}
}

// 客户端断开绝不能算上游故障。这条不成立的话，用户频繁取消
// 就能把所有好站判死。
func TestClassifyTransportErr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want health.Verdict
	}{
		{"nil", nil, health.VerdictOK},
		{"客户端断开", proxy.ErrClientGone, health.VerdictIgnore},
		{"请求被取消", proxy.ErrCanceled, health.VerdictIgnore},
		{"连接失败", proxy.ErrConnect, health.VerdictUnavailable},
		{"首 Token 超时", proxy.ErrFirstTokenTimeout, health.VerdictUnavailable},
		{"流内静默", proxy.ErrStreamStalled, health.VerdictUnavailable},
		{"总超时", proxy.ErrTotalTimeout, health.VerdictUnavailable},
		{"上游未返回数据", proxy.ErrUpstreamBroke, health.VerdictUnavailable},
		{"包装过的客户端断开", errors.New("x: " + proxy.ErrClientGone.Error()), health.VerdictUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyTransportErr(tc.err).Verdict; got != tc.want {
				t.Errorf("%v：期望 %s，得到 %s", tc.err, tc.want, got)
			}
		})
	}
}

// 我们自己设的超时**必须**算上游的账。不算的话一个真死的站
// 永远攒不够失败次数，主动探活就完全失去意义。
func TestClassifyTransportErr_OwnTimeoutsCountAgainstUpstream(t *testing.T) {
	for _, err := range []error{
		proxy.ErrFirstTokenTimeout, proxy.ErrStreamStalled, proxy.ErrTotalTimeout,
	} {
		if got := ClassifyTransportErr(err).Verdict; got != health.VerdictUnavailable {
			t.Errorf("%v 应计入上游失败（否则死站永远不会被判死），得到 %s", err, got)
		}
	}
}

func TestErrFromBody_CollapsesWhitespaceAndTruncates(t *testing.T) {
	err := errFromBody(500, []byte("line one\n\n   line   two\n"))
	if got := err.Error(); got != "HTTP 500: line one line two" {
		t.Errorf("多行应压成单行便于日志，得到 %q", got)
	}

	long := make([]byte, maxErrExcerpt*2)
	for i := range long {
		long[i] = 'x'
	}
	if got := errFromBody(500, long); len(got.Error()) > maxErrExcerpt+40 {
		t.Errorf("过长的响应体应被截断，得到 %d 字节", len(got.Error()))
	}

	if got := errFromBody(503, nil).Error(); got != "HTTP 503" {
		t.Errorf("空 body 应只报状态码，得到 %q", got)
	}
}
