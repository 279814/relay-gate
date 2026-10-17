package sample

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

func TestRecorders_FlushWaitsForEarlierWritesAndCanBeCanceled(t *testing.T) {
	for _, kind := range []string{"samples", "request logs"} {
		t.Run(kind, func(t *testing.T) {
			blocked := make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(blocked) }) }
			var recorder any
			var record func()
			var count func() int
			var closeRecorder func()
			if kind == "samples" {
				w := &fakeWriter{block: blocked}
				r := newTestRecorder(w, testSettings())
				recorder, count, closeRecorder = r, w.count, r.Close
				record = func() { r.Record(&model.Sample{ReqID: "flush-sample"}) }
			} else {
				w := &fakeLogWriter{block: blocked}
				r := newTestLogRecorder(w, testLogSettings())
				recorder, count, closeRecorder = r, w.count, r.Close
				record = func() { r.Record(&model.RequestLog{ReqID: "flush-log"}) }
			}
			t.Cleanup(func() { closeRecorder() })
			t.Cleanup(unblock)
			flush, ok := recorder.(interface{ Flush(context.Context) error })
			if !ok {
				t.Fatal("recorder cannot establish a rotation write barrier")
			}
			record()
			record()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			if err := flush.Flush(ctx); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("blocked writes must keep the barrier pending until cancellation: %v", err)
			}
			if count() != 0 {
				t.Fatal("blocked writer unexpectedly completed")
			}
			unblock()
			ctx, cancel = context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := flush.Flush(ctx); err != nil {
				t.Fatal(err)
			}
			if count() != 2 {
				t.Fatalf("flush returned before preceding records were written: count=%d", count())
			}
			closeRecorder()
			if err := flush.Flush(ctx); err != nil {
				t.Fatalf("already drained recorder must remain flushable: %v", err)
			}
		})
	}
}
