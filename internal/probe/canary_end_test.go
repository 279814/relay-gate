package probe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

func TestCanaryWaitsForResponseEOFAndRejectsOutputAfterProtocolEnd(t *testing.T) {
	prefix, tail := make(chan struct{}), make(chan struct{})
	h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		nonce := canaryRequestNonce(t, body, model.EndpointMessages)
		w.Header().Set("Content-Type", "text/event-stream")
		args := fmt.Sprintf(`{"nonce":%q}`, nonce)
		_, _ = fmt.Fprintf(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"one\",\"name\":\"relay_canary_noop\",\"input\":{}}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":%q}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n", args)
		w.(http.Flusher).Flush()
		close(prefix)
		<-tail
		_, _ = io.WriteString(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"unexpected extra output\"}}\n\n")
	})
	approveCanaryEndpoint(t, h)
	service := manualAuthProbeService(t, h, h.store)
	type result struct {
		execution model.ProbeExecution
		err       error
	}
	done := make(chan result, 1)
	go func() {
		execution, err := service.RunCanary(context.Background(), h.route.ID)
		done <- result{execution, err}
	}()
	select {
	case <-prefix:
	case <-time.After(2 * time.Second):
		close(tail)
		t.Fatal("Canary did not receive normal protocol end prefix")
	}
	select {
	case early := <-done:
		close(tail)
		t.Fatalf("Canary declared final verdict before bounded response EOF: %+v %v", early.execution.Canary, early.err)
	case <-time.After(40 * time.Millisecond):
		close(tail)
	}
	select {
	case actual := <-done:
		if actual.err != nil || actual.execution.Canary == nil || actual.execution.Canary.Verdict != "violation" || actual.execution.ExpectedCancel {
			t.Fatalf("extra post-end output missed: %+v %v", actual.execution.Canary, actual.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Canary did not finish after response EOF")
	}
}
