package proxy

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

func prepareInstrumentation(factory health.AttemptObserverFactory, ctx context.Context, target health.AttemptTarget, request health.AttemptRequestView) (instrumentation health.AttemptInstrumentation) {
	instrumentation = health.NoopInstrumentation()
	defer func() { _ = recover() }()
	if factory == nil {
		return instrumentation
	}
	prepared := factory.PrepareAttempt(ctx, target, request)
	if prepared.Observer != nil {
		prepared.Observer = &isolatedObserver{observer: prepared.Observer}
	}
	return prepared
}

// A faulty optional observer must not interrupt forwarding or manufacture a
// retry. Finish is delivered at most once, including unwinding panic paths.
type isolatedObserver struct {
	observer health.AttemptObserver
	finish   sync.Once
}

func (observer *isolatedObserver) TryHeaders(status int, header http.Header, at time.Time) (accepted bool) {
	defer func() { _ = recover() }()
	return observer.observer.TryHeaders(status, header, at)
}

func (observer *isolatedObserver) TryChunk(chunk []byte, at time.Time) (accepted bool) {
	defer func() { _ = recover() }()
	return observer.observer.TryChunk(chunk, at)
}

func (observer *isolatedObserver) TryRequest(view health.AttemptRequestView) {
	defer func() { _ = recover() }()
	if requestObserver, ok := observer.observer.(health.AttemptRequestObserver); ok {
		requestObserver.TryRequest(view)
	}
}

func (observer *isolatedObserver) Finish(view health.AttemptFinish) {
	defer func() { _ = recover() }()
	observer.finish.Do(func() { observer.observer.Finish(view) })
}

func (observer *isolatedObserver) ResponseProgress() (progress health.ResponseProgress) {
	progress.Incomplete = model.ObserverPrepareFailure
	defer func() {
		if recover() != nil {
			progress.Incomplete = model.ObserverPanic
		}
	}()
	if source, ok := observer.observer.(health.AttemptResponseProgress); ok {
		return source.ResponseProgress()
	}
	return progress
}

func (observer *isolatedObserver) ProgressChanges() (changes <-chan struct{}) {
	defer func() { _ = recover() }()
	if source, ok := observer.observer.(health.AttemptResponseProgress); ok {
		return source.ProgressChanges()
	}
	return nil
}

// observerTee is attached after the normal writer/Flush and to discard drains.
// Observation never changes bytes or propagates a callback failure upstream.
type observerTee struct{ observer health.AttemptObserver }

func (tee observerTee) Write(body []byte) (n int, err error) {
	n = len(body)
	defer func() { _ = recover() }()
	tee.observer.TryChunk(body, time.Now())
	return n, nil
}

// Transforms must consume the original upstream reader. This bounded callback
// is installed before decoding/rewriting, so injected output cannot prove health.
type observedUpstreamBody struct {
	io.ReadCloser
	observer  observerTee
	readError *error
	wire      *wireEvidence
}

func (body observedUpstreamBody) Read(p []byte) (int, error) {
	n, err := body.ReadCloser.Read(p)
	if err != nil && err != io.EOF && body.readError != nil {
		*body.readError = err
	}
	if n > 0 {
		if body.observer.observer != nil {
			_, _ = body.observer.Write(p[:n])
		}
		body.wire.feed(p[:n], time.Now())
	}
	if err == io.EOF {
		body.wire.finish()
	}
	return n, err
}
