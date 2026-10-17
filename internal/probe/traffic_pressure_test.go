package probe

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/andybalholm/brotli"
)

func TestTrafficHTTP_CompressedOutputBudgetDoesNotChangeForwarding(t *testing.T) {
	for _, coding := range []string{"gzip", "br"} {
		t.Run(coding, func(t *testing.T) {
			var output bytes.Buffer
			var encoder io.WriteCloser
			if coding == "gzip" {
				encoder = gzip.NewWriter(&output)
			} else {
				encoder = brotli.NewWriter(&output)
			}
			_, _ = io.WriteString(encoder, strings.Repeat(" ", trafficDecodedLimit+1024))
			_ = encoder.Close()
			wire := output.Bytes()
			h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Encoding", coding)
				_, _ = w.Write(wire)
			})
			if got := h.request(t); !bytes.Equal(got, wire) {
				t.Fatal("decoder budget changed compressed response")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := h.manager.Flush(ctx); err != nil {
				t.Fatal(err)
			}
			execution := h.execution(t)
			budgetHit := execution.ObserverIncompleteReason == model.ObserverOutputLimit || execution.ObserverIncompleteReason == model.ObserverDeadline
			if !execution.ObserverIncomplete || !budgetHit || execution.CapabilityDisposition != model.ApplyNotApplicable || execution.ResponseBytes != int64(len(wire)) {
				t.Fatalf("compressed limit fallback: reason=%s cap=%s bytes=%d", execution.ObserverIncompleteReason, execution.CapabilityDisposition, execution.ResponseBytes)
			}
			if stats := h.manager.Stats(); stats.FullObserversInFlight != 0 || stats.ObserverBytesInFlight != 0 {
				t.Fatalf("budget leaked resources: %+v", stats)
			}
		})
	}
}

func TestTrafficHTTP_DatabaseWaitNeverDelaysClientResponse(t *testing.T) {
	h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"type":"message","content":[{"type":"text","text":"ok"}]}`)
	})
	pause := pausedTrafficRecorder{h.manager.record, make(chan struct{}), make(chan struct{})}
	h.manager.record = pause
	defer close(pause.release)
	delivered := make(chan struct{})
	go func() { h.request(t); close(delivered) }()
	select {
	case <-pause.entered:
	case <-time.After(time.Second):
		t.Fatal("persistence did not start")
	}
	select {
	case <-delivered:
	case <-time.After(time.Second):
		t.Fatal("database wait blocked the HTTP client")
	}
}

func TestTrafficLimits_FullPersistenceQueueDropsWithoutLeaking(t *testing.T) {
	h := newCountTrafficHarness(t)
	for i := 0; i < persistQueueCap; i++ {
		h.manager.queue <- trafficWrite{}
	}
	observer := h.begin()
	observer.TryHeaders(401, nil, time.Now())
	observer.TryChunk([]byte(`{"error":{"type":"authentication_error"}}`), time.Now())
	finished := make(chan struct{})
	go func() { observer.Finish(health.AttemptFinish{}); close(finished) }()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("Finish waited for persistence capacity")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		stats := h.manager.Stats()
		if stats.DroppedByPersistence == 1 && stats.FullObserversInFlight == 0 && stats.ObserverBytesInFlight == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("full queue did not drop/release: %+v", h.manager.Stats())
}
