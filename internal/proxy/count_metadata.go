package proxy

import (
	"io"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

type countAttemptLogs struct {
	reqID  string
	recvAt time.Time
	rows   []*model.RequestLog
}

func (h *Handler) recordCountAttemptLogs(pre *preambleResult) {
	if pre.countLogs == nil || h.logs == nil || !pre.settings.RequestLogEnabled {
		return
	}
	for _, row := range pre.countLogs.rows {
		row.Attempts = len(pre.countLogs.rows)
		row.Metadata.Attempts = row.Attempts
		h.logs.Record(row)
	}
}

// The existing Observer receives original chunks at their actual read time.
// No second Decoder, response buffer, or protocol classifier is introduced.
type countObservedReader struct {
	io.ReadCloser
	res      *Result
	observer health.AttemptObserver
}

func (r *countObservedReader) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		at := time.Now()
		if r.res.FirstByteAt.IsZero() {
			r.res.FirstByteAt = at
		}
		if r.observer != nil {
			r.observer.TryChunk(p[:n], at)
		}
	}
	return n, err
}
