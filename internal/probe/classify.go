// Package probe 实现两级主动探活（§4）。
//
// L1 是 Upstream 粒度的传输层探测（零 token），L2 是 Route 粒度的模型层探测
// （消耗 token）。分两级的收益在 L1：一个站下挂着 N 个 Route 时，
// 站整体挂掉只需要探一次就能全部判死。
//
// 本包只负责「探一次、给出判定」，状态与调度归 health 包。
package probe

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/proxy"
)

// modelNotFoundMarkers 是「模型不存在」的响应体特征（§4.3 致命类）。
//
// 必须单独识别：配错 upstream_model 时上游回的是 400/404，与「站挂了」
// 的表征相同，但处置完全相反 —— 站挂了等它恢复就行，配置错了不改永远不会好。
// UI 上混在一起显示的话，用户会一直等一个永远不会自愈的故障。
var modelNotFoundMarkers = []string{
	"model_not_found",
	"model not found",
	"invalid model",
	"no such model",
	"unknown model",
	"does not exist",
}

// rateLimitMarkers 是限流的响应体特征（§4.3 限流类）。
//
// 有些站在 5xx 里表达限流（Anthropic 的 529 overloaded_error 就是），
// 只看状态码会把「太受欢迎」误判成「挂了」，然后把一个可用的站踢出池子。
var rateLimitMarkers = []string{
	"rate_limit",
	"rate limit",
	"too many requests",
	"overloaded",
	"quota",
}

// maxClassifyBody 是参与关键词判定的响应体上限。
//
// 错误响应通常只有几百字节，但公益站背后的 nginx 出错时会回整页 HTML。
// 全量扫描一个几 MB 的错误页只为找几个关键词是浪费，而特征词若真存在，
// 一定在开头的结构化错误信息里。
const maxClassifyBody = 8 << 10

// Outcome 是一次探测的完整结果。
type Outcome struct {
	Verdict health.Verdict
	Err     error
	TTFT    time.Duration
	// RetryAfter 来自 429 响应头。0 表示上游没给。
	RetryAfter time.Duration
	// Status 是上游 HTTP 状态码，0 表示连响应头都没拿到。
	Status int
}

// ClassifyHTTP 按 §4.3 把一次 HTTP 响应归类。
//
// body 是响应体（或它的开头若干字节）。判定顺序是刻意的：
// 限流要在 5xx 之前判（529 overloaded 是 5xx 但属于限流），
// 模型不存在要在通用 4xx 之前判（同为 400 但处置相反）。
func ClassifyHTTP(status int, header http.Header, body []byte) Outcome {
	if len(body) > maxClassifyBody {
		body = body[:maxClassifyBody]
	}
	lower := bytes.ToLower(body)

	switch {
	case status == http.StatusTooManyRequests:
		return Outcome{
			Verdict:    health.VerdictRateLimited,
			Err:        errFromBody(status, body),
			RetryAfter: parseRetryAfter(header),
			Status:     status,
		}

	// 鉴权错误。重试无意义，立即判死并在 UI 标「鉴权错误」。
	//
	// 必须排在下面的限流关键词之前：中转站的 401/403 响应体里很常见
	// 「insufficient_quota」「额度不足」这类措辞，而 quota 是限流特征词。
	// 顺序反了的话，一个余额耗尽的 key 会被判成限流 —— 冷却 60 秒后再试，
	// 永远攒不够失败次数，于是永远不判死。而余额耗尽只能靠人去充值或换
	// key，等它自愈是等不到的，UI 上还会显示成「限流」把人引向错误的方向。
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		return Outcome{
			Verdict: health.VerdictFatal,
			Err:     errFromBody(status, body),
			Status:  status,
		}

	// 429 之外的限流：靠响应体特征识别。放在 5xx 判定之前，
	// 否则 529 overloaded 会被当成「服务不可用」而累计判死。
	case containsAny(lower, rateLimitMarkers) && status >= 400:
		return Outcome{
			Verdict:    health.VerdictRateLimited,
			Err:        errFromBody(status, body),
			RetryAfter: parseRetryAfter(header),
			Status:     status,
		}

	case status >= 400 && status < 500 && containsAny(lower, modelNotFoundMarkers):
		return Outcome{
			Verdict: health.VerdictFatal,
			Err:     errFromBody(status, body),
			Status:  status,
		}

	case status >= 500:
		return Outcome{
			Verdict: health.VerdictUnavailable,
			Err:     errFromBody(status, body),
			Status:  status,
		}

	case status >= 400:
		// 其余 4xx：请求本身有问题（参数不合法等）。
		//
		// 归到 Unavailable 而不是 Fatal 是刻意的保守：探活请求是我们自己
		// 构造的，一个我们没预料到的 400 更可能是「这个站的参数要求特殊」
		// 而不是「站坏了」。累计判定给它两次机会，也给用户留出从样本里
		// 看出真实原因的时间。
		return Outcome{
			Verdict: health.VerdictUnavailable,
			Err:     errFromBody(status, body),
			Status:  status,
		}
	}

	return Outcome{Verdict: health.VerdictOK, Status: status}
}

// ClassifyTransportErr 把转发层的错误归类（§4.3 服务不可用类）。
//
// 复用 proxy 包的哨兵错误：真实请求与探活共用同一套判定逻辑，
// 差别只在超时值和后续动作（§3.5）。两边各写一套的话，
// 「客户端断开不算上游故障」这类规则迟早会在其中一边漏掉。
func ClassifyTransportErr(err error) Outcome {
	if err == nil {
		return Outcome{Verdict: health.VerdictOK}
	}
	// 客户端断开/取消与上游健康无关。这条判断必须在最前面：
	// 客户端断开会连带触发下面那些超时错误。
	if !proxy.IsUpstreamFault(err) {
		return Outcome{Verdict: health.VerdictIgnore, Err: err}
	}
	// 其余一律算上游的账，**包括我们自己设的超时** —— 那些超时到期
	// 正是「这个站太慢/已死」的证据。不算进去的话一个真死的站
	// 永远攒不够失败次数，主动探活就失去了意义。
	return Outcome{Verdict: health.VerdictUnavailable, Err: err}
}

// parseRetryAfter 解析 Retry-After 头（§4.3：尊重它）。
//
// 只支持秒数形式。HTTP 日期形式在中转站上没见过，且它需要依赖
// 本机时钟与上游时钟一致 —— 解析失败时回落到配置的默认冷却更稳妥。
func parseRetryAfter(h http.Header) time.Duration {
	if h == nil {
		return 0
	}
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0
	}
	// 上限保护：一个写错的 Retry-After（比如上游误填了毫秒）会把站
	// 冷藏几个小时，而它其实早就恢复了。
	if d := time.Duration(n) * time.Second; d < maxRetryAfter {
		return d
	}
	return maxRetryAfter
}

const maxRetryAfter = 30 * time.Minute

func containsAny(lowerBody []byte, markers []string) bool {
	for _, m := range markers {
		if bytes.Contains(lowerBody, []byte(m)) {
			return true
		}
	}
	return false
}

// errFromBody 组装带上游原文的错误，供 UI 显示与排查。
//
// 保留原文很重要：「400」什么也说明不了，「400: model xxx not found」
// 直接告诉用户该改哪里。
func errFromBody(status int, body []byte) error {
	msg := strings.TrimSpace(string(body))
	msg = collapseWS(msg)
	if len(msg) > maxErrExcerpt {
		msg = msg[:maxErrExcerpt] + "…"
	}
	if msg == "" {
		return errors.New("HTTP " + strconv.Itoa(status))
	}
	return errors.New("HTTP " + strconv.Itoa(status) + ": " + msg)
}

const maxErrExcerpt = 300

// collapseWS 把连续空白压成单个空格，让错误信息在单行日志里可读。
func collapseWS(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// ctxOutcome 把 context 结束的原因翻译成判定。
// 探活被取消（服务暂停、进程关闭）不是上游的问题。
func ctxOutcome(ctx context.Context, err error) (Outcome, bool) {
	if ctx.Err() == nil {
		return Outcome{}, false
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return Outcome{Verdict: health.VerdictIgnore, Err: err}, true
	}
	return Outcome{Verdict: health.VerdictUnavailable, Err: err}, true
}
