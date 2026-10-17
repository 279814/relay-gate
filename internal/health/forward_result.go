package health

import (
	"errors"
	"net/http"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// ResultView is the compatibility reporting boundary; production observations
// use AttemptObserver without coupling probe and proxy packages.
type ResultView struct {
	Status             int
	Err                error
	ErrBody            []byte
	Header             http.Header
	Endpoint           model.EndpointKind
	TTFT               time.Duration
	BytesWritten       int64
	SemanticSeen       bool
	HalfOpen           bool
	CapabilityObserved bool
}

type ResultReporter interface {
	ReportResult(int64, uint64, *ResultView)
	TriggerProbe(int64)
}

var (
	ErrConnect           = errors.New("连接上游失败")
	ErrFirstTokenTimeout = errors.New("首 Token 超时")
	ErrStreamStalled     = errors.New("流内静默超时")
	ErrTotalTimeout      = errors.New("超过总时限")
	ErrUpstreamBroke     = errors.New("上游未返回任何数据即断开")
	ErrStreamBroke       = errors.New("流式传输中途断开")
	ErrClientGone        = errors.New("客户端已断开")
	ErrCanceled          = errors.New("请求被取消")
)

func IsUpstreamFault(err error) bool {
	return err != nil && !errors.Is(err, ErrClientGone) && !errors.Is(err, ErrCanceled)
}
