package health

import (
	"context"
	"net/http"

	"github.com/279814/relay-gate/internal/model"
)

// RetryDisposition 是同步 Peek 重试建议。
type RetryDisposition string

const (
	RetryKeepAttempt  RetryDisposition = "keep_attempt"
	RetryTryNextRoute RetryDisposition = "try_next_route"
)

// RetryAdvice 是 RetryDecider 的输出。
type RetryAdvice struct {
	Disposition RetryDisposition
	ErrorClass  model.ErrorClass
	Scope       model.ObservationScope
}

// RetryDecider 在客户端尚未 commit 时同步判断受限 Peek 前缀。
type RetryDecider interface {
	DecidePeek(ctx context.Context, status int, header http.Header, prefix []byte, complete bool) RetryAdvice
}

// KeepAttemptDecider 永远 KeepAttempt（no-op / 失败兜底）。
type KeepAttemptDecider struct{}

func (KeepAttemptDecider) DecidePeek(context.Context, int, http.Header, []byte, bool) RetryAdvice {
	return RetryAdvice{Disposition: RetryKeepAttempt}
}
