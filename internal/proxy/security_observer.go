package proxy

import (
	"net/http"
	"sync"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/security"
)

// The proxy bridges interfaces because health's persistence already depends on
// security. Retry and Trace remain on the original instrumentation untouched.
func wrapSecurityObserver(next health.AttemptObserver, capture *security.Capture) health.AttemptObserver {
	return &securityObserver{next: next, capture: capture}
}

type securityObserver struct {
	next    health.AttemptObserver
	capture *security.Capture
	finish  sync.Once
}

func (o *securityObserver) TryHeaders(status int, header http.Header, at time.Time) (accepted bool) {
	o.capture.TryHeaders(header)
	defer func() { _ = recover() }()
	if o.next != nil {
		return o.next.TryHeaders(status, header, at)
	}
	return false
}

func (o *securityObserver) TryChunk(chunk []byte, at time.Time) (accepted bool) {
	o.capture.TryChunk(chunk)
	defer func() { _ = recover() }()
	if o.next != nil {
		return o.next.TryChunk(chunk, at)
	}
	return false
}

func (o *securityObserver) TryRequest(view health.AttemptRequestView) {
	o.capture.TryRequest(view.Body, view.BodyTruncated)
	defer func() { _ = recover() }()
	if next, ok := o.next.(health.AttemptRequestObserver); ok {
		next.TryRequest(view)
	}
}

func (o *securityObserver) Finish(view health.AttemptFinish) {
	defer func() { _ = recover() }()
	o.finish.Do(func() {
		defer o.capture.Complete(view.ClientCommitted)
		if o.next != nil {
			o.next.Finish(view)
		}
	})
}

func (o *securityObserver) ResponseProgress() (progress health.ResponseProgress) {
	progress.Incomplete = model.ObserverPrepareFailure
	defer func() {
		if recover() != nil {
			progress.Incomplete = model.ObserverPanic
		}
	}()
	if next, ok := o.next.(health.AttemptResponseProgress); ok {
		return next.ResponseProgress()
	}
	return progress
}

func (o *securityObserver) ProgressChanges() (changes <-chan struct{}) {
	defer func() { _ = recover() }()
	if next, ok := o.next.(health.AttemptResponseProgress); ok {
		return next.ProgressChanges()
	}
	return nil
}
