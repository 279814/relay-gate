package probe

import (
	"context"
	"net/http"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

// RetryDecider 复用统一 Classifier，在 Peek 预算内给同步重试建议。
type RetryDecider struct {
	protocol model.Protocol
}

// NewRetryDecider 按协议构造。
func NewRetryDecider(protocol model.Protocol) *RetryDecider {
	return &RetryDecider{protocol: protocol}
}

// DecidePeek 对完整受限错误前缀返回 TryNextRoute；其余 KeepAttempt。
func (d *RetryDecider) DecidePeek(ctx context.Context, status int, header http.Header, prefix []byte, complete bool) (advice health.RetryAdvice) {
	advice = health.RetryAdvice{Disposition: health.RetryKeepAttempt}
	defer func() {
		if recover() != nil {
			advice = health.RetryAdvice{Disposition: health.RetryKeepAttempt}
		}
	}()
	_ = ctx
	if d == nil {
		return advice
	}
	// 非错误状态或空前缀：保守 Keep。
	if status > 0 && status < 400 && len(prefix) == 0 {
		return advice
	}
	ct := ""
	if header != nil {
		ct = header.Get("Content-Type")
	}
	// 复用既有 HTTP / 载荷分类；完整结构化错误才换站。
	if status >= 400 {
		out := ClassifyHTTP(status, header, prefix)
		switch out.Verdict {
		case health.VerdictFatal, health.VerdictUnavailable, health.VerdictRateLimited:
			return health.RetryAdvice{
				Disposition: health.RetryTryNextRoute,
				ErrorClass:  mapVerdictClass(out),
				Scope:       model.ScopeRouteEndpoint,
			}
		}
		return advice
	}
	if !complete && len(prefix) == 0 {
		return advice
	}
	// 200 流内错误：仅当前缀可被判为错误载荷。
	if isStructuredErrorPrefix(prefix, ct) {
		return health.RetryAdvice{
			Disposition: health.RetryTryNextRoute,
			ErrorClass:  model.ErrorTransient,
			Scope:       model.ScopeRouteEndpoint,
		}
	}
	return advice
}

func mapVerdictClass(out Outcome) model.ErrorClass {
	switch out.Verdict {
	case health.VerdictFatal:
		return model.ErrorAuthRejected
	case health.VerdictRateLimited:
		return model.ErrorRateLimited
	case health.VerdictUnavailable:
		return model.ErrorTransient
	default:
		return model.ErrorTransient
	}
}

func isStructuredErrorPrefix(prefix []byte, contentType string) bool {
	if len(prefix) == 0 {
		return false
	}
	// 轻量启发式：与旧 classifyPayload 对齐的明显错误载荷。
	s := string(prefix)
	if containsFold(s, `"type":"error"`) || containsFold(s, `"error":`) {
		return true
	}
	_ = contentType
	return false
}

func containsFold(s, sub string) bool {
	return len(s) >= len(sub) && (indexFold(s, sub) >= 0)
}

func indexFold(s, sub string) int {
	// 小写 ASCII 扫描；预算内 Peek 足够。
	n, m := len(s), len(sub)
	if m == 0 || m > n {
		if m == 0 {
			return 0
		}
		return -1
	}
	for i := 0; i+m <= n; i++ {
		ok := true
		for j := 0; j < m; j++ {
			a, b := s[i+j], sub[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

var _ health.RetryDecider = (*RetryDecider)(nil)
