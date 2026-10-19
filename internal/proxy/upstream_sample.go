package proxy

import (
	"io"
	"net/http"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// One existing HeadTail owns the original upstream bytes. Client shadow output
// remains on RespTee; the sample never receives transformed or synthetic bytes.
type upstreamSampleCapture struct {
	sink     io.Writer
	status   int
	header   http.Header
	complete bool
}

func (c *upstreamSampleCapture) Write(p []byte) (int, error) {
	if c == nil || c.sink == nil {
		return len(p), nil
	}
	return c.sink.Write(p)
}
func (c *upstreamSampleCapture) view() string {
	if c == nil {
		return "unknown"
	}
	if c.status == 0 {
		return "no_response"
	}
	if !c.complete {
		return "upstream_attempt_prefix"
	}
	return "upstream_response"
}

type upstreamSampleBody struct {
	io.ReadCloser
	capture *upstreamSampleCapture
}

func (b upstreamSampleBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		_, _ = b.capture.Write(p[:n])
	}
	if err == io.EOF {
		b.capture.complete = true
	}
	return n, err
}

func (h *Handler) rawSampleAttempt(la *liveAttempt, metadata model.AttemptMetadata, keys []string, inModel string, recvAt time.Time, settings model.Settings) *model.SampleAttempt {
	res := *la.at.Result()
	if la.capture != nil {
		res.Status = la.capture.status
		res.RespHeaders = la.capture.header
	}
	a := h.sampleAttempt(la.cand, la.body, la.header, la.url, la.tee, &res, keys, inModel, recvAt, settings)
	a.Metadata = metadata
	a.ResponseCaptureView = la.capture.view()
	a.Metadata.ResponseView = a.ResponseCaptureView
	if la.capture != nil && la.capture.status > 0 && !la.capture.complete {
		a.Truncated |= model.TruncRespBody
	}
	return a
}
