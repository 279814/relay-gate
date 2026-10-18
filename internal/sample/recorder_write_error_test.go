package sample

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

type quotaFailureWriter struct{ *fakeWriter }

func (w quotaFailureWriter) InsertSampleWithinQuota(s *model.Sample, _ int64) (bool, error) {
	err := w.InsertSample(s)
	return err == nil, err
}

func TestRecorder_WriteFailureCountsGroupOnceAndKeepsErrorAlert(t *testing.T) {
	for _, kind := range []string{"plain", "quota"} {
		t.Run(kind, func(t *testing.T) {
			w := &fakeWriter{failNth: 2}
			var writer Writer = w
			if kind == "quota" {
				writer = quotaFailureWriter{w}
			}
			var log bytes.Buffer
			r := NewRecorder(writer, testSettings(), newLiveSettings(testSettings()),
				slog.New(slog.NewJSONHandler(&log, nil)))
			for i := 0; i < 4; i++ {
				r.Record(&model.Sample{RouteID: int64(i), Attempts: []*model.SampleAttempt{{}, {}, {}}})
			}
			r.Close()
			if written, dropped := r.Stats(); written != 3 || dropped != 1 {
				t.Errorf("one failed group with 3 attempts must count once: written=%d dropped=%d", written, dropped)
			}
			if got := w.calls.Load(); got != 4 || w.count() != 3 {
				t.Errorf("failure must not retry or stop subsequent groups: calls=%d successes=%d", got, w.count())
			}
			var event struct {
				Level   string `json:"level"`
				Message string `json:"msg"`
				Dropped int    `json:"dropped_total"`
			}
			if err := json.Unmarshal(bytes.TrimSpace(log.Bytes()), &event); err != nil {
				t.Fatalf("must retain exactly one write error alert: %v; log=%s", err, log.String())
			}
			if event.Level != "ERROR" || event.Message != "样本落库失败" || event.Dropped != 1 {
				t.Errorf("write failure must remain high priority and include dropped total: %+v", event)
			}
		})
	}
}

type mixedDropWriter struct {
	*fakeWriter
	started chan struct{}
	release chan struct{}
}

func (w *mixedDropWriter) InsertSampleWithinQuota(s *model.Sample, _ int64) (bool, error) {
	switch s.ReqID {
	case "write-error":
		w.calls.Add(1)
		close(w.started)
		<-w.release
		return false, errors.New("simulated disk full")
	case "quota-skip":
		w.calls.Add(1)
		return false, nil
	default:
		err := w.InsertSample(s)
		return err == nil, err
	}
}

func TestRecorder_QueueQuotaAndWriteDropsAreCountedOnce(t *testing.T) {
	w := &mixedDropWriter{fakeWriter: &fakeWriter{}, started: make(chan struct{}), release: make(chan struct{})}
	s := testSettings()
	s.SampleQueueSize = 1
	r := newTestRecorder(w, s)
	var release sync.Once
	unblock := func() { release.Do(func() { close(w.release) }) }
	t.Cleanup(func() { unblock(); r.Close() })
	r.Record(&model.Sample{ReqID: "write-error"})
	select {
	case <-w.started:
	case <-time.After(time.Second):
		t.Fatal("writer did not start")
	}
	// One group is in flight and one fits in the queue. The third must return
	// immediately and never be passed to either database insertion method.
	start := time.Now()
	r.Record(&model.Sample{ReqID: "quota-skip"})
	r.Record(&model.Sample{ReqID: "queue-drop"})
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("Record blocked behind a failing disk writer: %v", elapsed)
	}
	unblock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := r.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	r.Record(&model.Sample{ReqID: "success-after-errors"})
	if err := r.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	r.Close()
	if written, dropped := r.Stats(); written != 1 || dropped != 3 {
		t.Fatalf("4 groups must partition into 1 success and 3 distinct drops: written=%d dropped=%d", written, dropped)
	}
	if got := w.calls.Load(); got != 3 || w.count() != 1 {
		t.Fatalf("queue drops must never reach the writer and failed writes must not retry: calls=%d successes=%d", got, w.count())
	}
}
