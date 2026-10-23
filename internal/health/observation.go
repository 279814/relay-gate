package health

// P0-13：proxy↔probe 中立观察面。proxy 只依赖本包接口；probe 提供实现。

import (
	"context"
	"net/http"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
)

// AttemptTarget 标识一次即将发出的真实 Attempt。
type AttemptTarget struct {
	ExecutionID      string
	ReqID            string
	Attempt          int
	Protocol         model.Protocol
	Endpoint         model.EndpointKind
	UpstreamID       int64
	RouteID          int64
	HealthGeneration uint64
	Config           AttemptConfigFacts
}

// AttemptConfigFacts 是该次 Attempt 已固定的配置身份（proxy 原样复制，不造 token）。
type AttemptConfigFacts struct {
	Generation                      uint64
	EndpointID                      int64
	UpstreamNetworkRevision         int64
	UpstreamCredentialRevision      int64
	UpstreamCreatedAt               int64
	RouteCreatedAt                  int64
	EndpointRevision                int64
	AuthProfileRevision             int64
	ModelCapabilityRevision         int64
	RouteCapabilityRevision         int64
	RequestTransformRevision        int64
	PolicySelector                  model.EvidencePolicySelector
	ReachabilitySettingsFingerprint string
	CapabilitySettingsFingerprint   string
	ResolvedURLHash                 string
}

// AttemptRequestView 只在 PrepareAttempt / TryRequest 同步调用期间有效。
type AttemptRequestView struct {
	Header        http.Header
	RawQuery      string
	Body          []byte
	BodyTruncated bool
}

// AttemptFinish 是 Attempt 终态。
type AttemptFinish struct {
	ReadErr         error
	ClientCanceled  bool
	ServiceCanceled bool
	ClientCommitted bool
	HalfOpen        bool
	ConfigError     bool
	ConfigFacts     *AttemptConfigFacts
}

// AttemptObserver 旁路观察响应；不得改变转发字节。
type AttemptObserver interface {
	TryHeaders(status int, header http.Header, at time.Time) bool
	TryChunk(chunk []byte, at time.Time) bool
	Finish(v AttemptFinish)
}

// AttemptObserverFactory 在 RoundTrip 前构造 instrumentation。
type AttemptObserverFactory interface {
	PrepareAttempt(ctx context.Context, target AttemptTarget, request AttemptRequestView) AttemptInstrumentation
}

// AttemptRequestObserver accepts the final outbound view before socket write.
// Local configuration failures can still use the earlier instrumentation.
type AttemptRequestObserver interface{ TryRequest(AttemptRequestView) }

// ResponseProgress is a bounded, read-only summary of original upstream wire.
// Incomplete means semantic timing is unavailable; it never proves an upstream
// failure. A compressed response uses the existing observer worker to decode.
type ResponseProgress struct {
	FirstEventAt    time.Time
	FirstSemanticAt time.Time
	LastSemanticAt  time.Time
	Incomplete      model.ObserverIncompleteReason
}

type AttemptResponseProgress interface {
	ResponseProgress() ResponseProgress
	ProgressChanges() <-chan struct{}
}

// AttemptInstrumentation 捆绑 Observer、同步 RetryDecider 与共享 Trace。
type AttemptInstrumentation struct {
	ObservationPrepared bool
	Observer            AttemptObserver
	Retry               RetryDecider
	Trace               *outbound.AttemptTrace
}

// NoopInstrumentation 在准备失败时返回：KeepAttempt、nil Trace。
func NoopInstrumentation() AttemptInstrumentation {
	return AttemptInstrumentation{
		Observer: noopObserver{},
		Retry:    KeepAttemptDecider{},
		Trace:    nil,
	}
}

type noopObserver struct{}

func (noopObserver) TryHeaders(int, http.Header, time.Time) bool { return false }
func (noopObserver) TryChunk([]byte, time.Time) bool             { return false }
func (noopObserver) Finish(AttemptFinish)                        {}

// Compile-time interface satisfaction helpers for probe implementations.
var (
	_ AttemptObserver = noopObserver{}
)
