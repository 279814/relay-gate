package probe

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

// RetryDecider parses a bounded prefix independently of asynchronous observation.
type RetryDecider struct{ protocol model.Protocol }

func NewRetryDecider(protocol model.Protocol) *RetryDecider { return &RetryDecider{protocol: protocol} }

func (d *RetryDecider) DecidePeek(ctx context.Context, status int, header http.Header, prefix []byte, complete bool) (advice health.RetryAdvice) {
	advice.Disposition = health.RetryKeepAttempt
	defer func() {
		if recover() != nil {
			advice = health.RetryAdvice{Disposition: health.RetryKeepAttempt}
		}
	}()
	if d == nil || ctx.Err() != nil || len(prefix) > 64<<10 {
		return advice
	}
	endpoint, ok := d.protocol.Endpoint()
	if !ok {
		return advice
	}
	now := time.Now()
	classifier := NewResponseClassifier(ObserveReal, endpoint, status, header, now)
	if status >= 400 {
		decision := classifier.Finish(nil, nil)
		if decision.ErrorClass != model.ErrorIgnored {
			return health.RetryAdvice{Disposition: health.RetryTryNextRoute, ErrorClass: decision.ErrorClass, Scope: decision.Scope}
		}
		return advice
	}
	if len(prefix) == 0 {
		return advice
	}
	encoding := header.Get("Content-Encoding")
	if encoding != "" && encoding != "identity" {
		if !complete {
			return advice
		}
		reader, err := NewContentDecoder(encoding, bytes.NewReader(prefix), ContentCodingLimits{MaxEncodedBytes: 64 << 10, MaxDecodedBytes: 64 << 10, MaxWorkUnits: 256})
		if err != nil {
			return advice
		}
		decoded, err := io.ReadAll(reader)
		_ = reader.Close()
		if err != nil {
			return advice
		}
		prefix = decoded
	}
	decoder, err := NewDecoder(DecoderSpec{Endpoint: endpoint, Protocol: d.protocol}, WireAuto, 64<<10, 64<<10)
	if err != nil {
		return advice
	}
	events, err := decoder.Feed(prefix)
	if err != nil {
		return advice
	}
	if complete {
		tail, finishErr := decoder.Finish()
		if finishErr != nil {
			return advice
		}
		events = append(events, tail...)
	}
	for _, event := range events {
		classifier.Observe(event)
	}
	if ctx.Err() != nil || time.Since(now) > 5*time.Millisecond || classifier.semanticSeen || classifier.remoteError == nil {
		return advice
	}
	decision := classifier.Finish(nil, nil)
	if decision.ErrorClass == model.ErrorIgnored || decision.ErrorClass == model.ErrorPartial {
		return advice
	}
	return health.RetryAdvice{Disposition: health.RetryTryNextRoute, ErrorClass: decision.ErrorClass, Scope: decision.Scope}
}

var _ health.RetryDecider = (*RetryDecider)(nil)
