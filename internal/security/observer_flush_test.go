package security

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type blockedFindingSink struct {
	started chan struct{}
	release chan struct{}
	written atomic.Int32
}

func (s *blockedFindingSink) Record(f Finding) Finding {
	select {
	case s.started <- struct{}{}:
	default:
	}
	<-s.release
	s.written.Add(1)
	return f
}

func TestObserverFlushWaitsForEncryptedEvidenceWriterAndCanCancel(t *testing.T) {
	sink := &blockedFindingSink{started: make(chan struct{}, 2), release: make(chan struct{})}
	observer := NewObserver(sink, 1, nil)
	defer observer.Close()
	defer close(sink.release)
	observer.Enqueue(ObserveJob{Body: []byte(`<script>alert(1)</script>`)})
	select {
	case <-sink.started:
	case <-time.After(time.Second):
		t.Fatal("fixture finding was not admitted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := observer.Flush(ctx); !errors.Is(err, context.DeadlineExceeded) || sink.written.Load() != 0 {
		t.Fatalf("Flush did not wait/cancel: %v", err)
	}
	// A canceled queued barrier cannot turn the next producer into a blocking
	// operation, even with a full queue and a blocked evidence sink.
	returned := make(chan struct{})
	go func() { observer.Enqueue(ObserveJob{Body: []byte(`<script>alert(2)</script>`)}); close(returned) }()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("security enqueue blocked during Flush")
	}
	if observer.Dropped() != 1 {
		t.Fatal("saturated security queue was not counted")
	}
}

func TestObserverFlushAcknowledgesAllEarlierFindings(t *testing.T) {
	sink := &blockedFindingSink{started: make(chan struct{}, 2), release: make(chan struct{})}
	close(sink.release)
	observer := NewObserver(sink, 2, nil)
	observer.Enqueue(ObserveJob{Body: []byte(`<script>alert(1)</script>`)})
	if err := observer.Flush(context.Background()); err != nil || sink.written.Load() == 0 {
		t.Fatalf("barrier acknowledged before evidence persistence: %v", err)
	}
	observer.Close()
	if err := observer.Flush(context.Background()); err != nil {
		t.Fatalf("closed, drained observer should already be flushed: %v", err)
	}
}
