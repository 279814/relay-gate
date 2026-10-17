package proxy

import (
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type blockedRequestBody struct {
	reader           io.Reader
	entered, release chan struct{}
	once             sync.Once
}

func (b *blockedRequestBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return b.reader.Read(p)
}
func (b *blockedRequestBody) Close() error { return nil }

func TestQuiesce_DrainsRequestStillInsidePreamble(t *testing.T) {
	hs := newHarness(t, nil)
	quiescer, ok := any(hs.h).(interface {
		Quiesce(context.Context) (func(), error)
	})
	if !ok {
		t.Fatal("handler has no full-admission quiesce fence")
	}
	blocked := &blockedRequestBody{reader: strings.NewReader(`{"model":"claude-opus-5","messages":[]}`), entered: make(chan struct{}), release: make(chan struct{})}
	req := hs.anthropicRequest("")
	req.Body = blocked
	response := make(chan *httptest.ResponseRecorder, 1)
	go func() { response <- hs.serve(req) }()
	<-blocked.entered
	if _, open, _ := hs.health.stats(); open != 0 {
		t.Fatal("fixture must still be before TryAcquire")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	type result struct {
		release func()
		err     error
	}
	drained := make(chan result, 1)
	go func() { release, err := quiescer.Quiesce(ctx); drained <- result{release, err} }()
	deadline := time.Now().Add(time.Second)
	for {
		if got := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`)); got.Code == 503 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("frozen admission accepted new requests")
		}
	}
	select {
	case <-drained:
		t.Fatal("drain missed request inside preamble")
	default:
	}
	close(blocked.release)
	<-response
	value := <-drained
	if value.err != nil {
		t.Fatal(value.err)
	}
	if got := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`)); got.Code != 503 {
		t.Fatalf("fence released early: %d", got.Code)
	}
	value.release()
	value.release()
	if got := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`)); got.Code != 200 {
		t.Fatalf("released admission status=%d", got.Code)
	}
}

func TestQuiesce_TimeoutReleasesAdmissionFence(t *testing.T) {
	hs := newHarness(t, nil)
	quiescer, ok := any(hs.h).(interface {
		Quiesce(context.Context) (func(), error)
	})
	if !ok {
		t.Fatal("handler has no full-admission quiesce fence")
	}
	blocked := &blockedRequestBody{reader: strings.NewReader(`{"model":"claude-opus-5"}`), entered: make(chan struct{}), release: make(chan struct{})}
	req := hs.anthropicRequest("")
	req.Body = blocked
	done := make(chan struct{})
	go func() { hs.serve(req); close(done) }()
	<-blocked.entered
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := quiescer.Quiesce(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("drain error=%v", err)
	}
	if got := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`)); got.Code != 200 {
		t.Fatalf("failed drain kept admission frozen: %d", got.Code)
	}
	close(blocked.release)
	<-done
}
