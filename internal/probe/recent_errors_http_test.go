package probe

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

func TestRecentErrorsHTTP200CanonicalFailures(t *testing.T) {
	for _, tc := range []struct {
		name, contentType, body string
		class                   model.ErrorClass
	}{
		{"structured error", "application/json", `{"type":"error","error":{"type":"authentication_error","message":"private response sentence"}}`, model.ErrorAuthRejected},
		{"missing end", "text/event-stream", "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n", model.ErrorPartial},
		{"no semantic content", "application/json", `{"type":"message","content":[]}`, model.ErrorFakeAlive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTrafficPrivacyHarness(t, func(w http.ResponseWriter, r *http.Request) {
				drainBody(r)
				w.Header().Set("Content-Type", tc.contentType)
				_, _ = io.WriteString(w, tc.body)
			})
			h.request(t)
			h.flush(t)
			execution := h.execution(t)
			if execution.Success || execution.ErrorClass != tc.class || execution.StatusCode != http.StatusOK {
				t.Fatalf("canonical fixture = %+v", execution)
			}
			logs, err := h.store.ListRequestLogs(store.RequestLogFilter{})
			if err != nil || len(logs) != 1 {
				t.Fatalf("logs=%+v err=%v", logs, err)
			}
			if logs[0].Outcome != model.OutcomeOK || logs[0].Metadata.ExecutionID != execution.ID {
				t.Fatalf("client outcome or exact correlation changed: %+v", logs[0])
			}
			for _, class := range []model.ErrorClass{"", tc.class} {
				page, err := h.store.ListRecentErrors(context.Background(), store.RecentErrorFilter{ErrorClass: class})
				if err != nil || page.FailedCount != 1 || len(page.Logs) != 1 {
					t.Fatalf("HTTP 200 canonical failure omitted (class=%q): count=%d rows=%d err=%v", class, page.FailedCount, len(page.Logs), err)
				}
				row := page.Logs[0]
				if row.ID != logs[0].ID || row.Outcome != model.OutcomeOK || row.Metadata.ExecutionID != execution.ID || !row.Metadata.ExecutionStored {
					t.Fatalf("recent error lost original outcome/exact execution: %+v", row)
				}
				assertPrivateValuesAbsent(t, "recent errors metadata", page, "private response sentence", "private request text", h.up.APIKey)
			}
		})
	}
}

type delayedRecentErrorRecorder struct {
	ExecutionRecorder
	entered chan struct{}
	release chan struct{}
}

func (r *delayedRecentErrorRecorder) Record(ctx context.Context, observation *model.ProbeObservation) (model.ProbeApplyResult, error) {
	close(r.entered)
	select {
	case <-ctx.Done():
		return model.ProbeApplyResult{}, ctx.Err()
	case <-r.release:
		return r.ExecutionRecorder.Record(ctx, observation)
	}
}

func TestRecentErrorsHTTPWaitsForActualObservationCommit(t *testing.T) {
	h := newTrafficPrivacyHarness(t, func(w http.ResponseWriter, r *http.Request) {
		drainBody(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"type":"error","error":{"type":"authentication_error"}}`)
	})
	delayed := &delayedRecentErrorRecorder{ExecutionRecorder: h.manager.record, entered: make(chan struct{}), release: make(chan struct{})}
	h.manager.record = delayed
	t.Cleanup(func() {
		select {
		case <-delayed.release:
		default:
			close(delayed.release)
		}
	})
	h.request(t) // The persistence worker may block; forwarding must still finish.
	select {
	case <-delayed.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("observer did not reach persistence worker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	release, err := h.handler.Quiesce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := h.logs.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	logs, err := h.store.ListRequestLogs(store.RequestLogFilter{})
	if err != nil || len(logs) != 1 || logs[0].Metadata.CapabilityEffect != "pending" {
		t.Fatalf("expected durable log before observation: %+v %v", logs, err)
	}
	page, err := h.store.ListRecentErrors(ctx, store.RecentErrorFilter{})
	if err != nil || page.FailedCount != 0 || len(page.Logs) != 0 {
		t.Fatalf("uncommitted observation guessed a failure: %+v %v", page, err)
	}
	close(delayed.release)
	if err := h.manager.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	page, err = h.store.ListRecentErrors(ctx, store.RecentErrorFilter{ErrorClass: model.ErrorAuthRejected})
	if err != nil || page.FailedCount != 1 || len(page.Logs) != 1 || page.Logs[0].ID != logs[0].ID {
		t.Fatalf("committed observation did not join original log: %+v %v", page, err)
	}
}
