package probe

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

func TestTrafficHTTP_ProtocolsPersistOnlyCompleteSemanticSuccess(t *testing.T) {
	for _, tc := range []struct {
		name              string
		protocol          model.Protocol
		contentType, wire string
		success, partial  bool
	}{
		{"chat tool", model.ProtoOpenAIChat, "text/event-stream", "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":\"{\"}}]}}]}\n\ndata: [DONE]\n\n", true, false},
		{"chat refusal", model.ProtoOpenAIChat, "application/json", `{"choices":[{"message":{"refusal":"no"}}]}`, true, false},
		{"chat partial", model.ProtoOpenAIChat, "text/event-stream", "data: {\"choices\":[{\"delta\":{\"content\":\"答复\"}}]}\n\n", false, true},
		{"responses usage", model.ProtoOpenAIResponses, "text/event-stream", "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"output_tokens\":2}}}\n\n", true, false},
		{"responses NDJSON", model.ProtoOpenAIResponses, "application/x-ndjson", "{\"type\":\"response.output_text.delta\",\"delta\":\"答复\"}\n{\"type\":\"response.completed\"}\n", true, false},
		{"responses partial", model.ProtoOpenAIResponses, "text/event-stream", "event: response.refusal.delta\ndata: {\"type\":\"response.refusal.delta\",\"delta\":\"no\"}\n\n", false, true},
		{"chat metadata only", model.ProtoOpenAIChat, "text/event-stream", "data: {\"choices\":[{\"delta\":{\"content\":\"\"}}]}\n\ndata: [DONE]\n\n", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTrafficHTTPHarnessFor(t, tc.protocol, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				// Split protocol frames and UTF-8 without exceeding the bounded
				// observer queue merely because the fixture flushes each byte.
				for start := 0; start < len(tc.wire); start += 7 {
					_, _ = io.WriteString(w, tc.wire[start:min(start+7, len(tc.wire))])
					w.(http.Flusher).Flush()
				}
			})
			status, body := h.requestProtocol(t, tc.protocol)
			if status != 200 || !bytes.Equal(body, []byte(tc.wire)) {
				t.Fatal("observation changed the wire response")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			release, err := h.handler.Quiesce(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			if err := h.manager.Flush(ctx); err != nil {
				t.Fatal(err)
			}
			execution := h.execution(t)
			if execution.Success != tc.success || execution.Partial != tc.partial || execution.CapabilityDisposition != model.ApplyCurrent {
				t.Fatalf("protocol conclusion success=%v partial=%v class=%s disposition=%s incomplete=%s", execution.Success, execution.Partial, execution.ErrorClass, execution.CapabilityDisposition, execution.ObserverIncompleteReason)
			}
			profiles, err := h.store.ListClientProfilesPage(ctx, model.ClientProfileFilter{UpstreamID: h.up.ID})
			if err != nil {
				t.Fatal(err)
			}
			if got := len(profiles.Items); (got == 1) != tc.success {
				t.Fatalf("profiles=%d for success=%v", got, tc.success)
			}
		})
	}
}

func TestTrafficHTTP_CapacityKeepsPureStatusEvidenceAndCountsWire(t *testing.T) {
	for _, status := range []int{200, 401, 403, 404, 405, 429, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			body := `{"type":"message","content":[{"type":"text","text":"ok"}]}`
			h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, body)
			})
			for i := 0; i < fullObserverLeases; i++ {
				<-h.manager.leases
			}
			defer func() {
				for i := 0; i < fullObserverLeases; i++ {
					h.manager.leases <- struct{}{}
				}
			}()
			got, wire := h.requestProtocol(t, model.ProtoAnthropic)
			if got != status || string(wire) != body {
				t.Fatalf("status fallback changed response: %d %s", got, wire)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			release, err := h.handler.Quiesce(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			if err := h.manager.Flush(ctx); err != nil {
				t.Fatal(err)
			}
			execution := h.execution(t)
			if !execution.ObserverIncomplete || execution.ObserverIncompleteReason != model.ObserverCapacity || execution.ReachabilityDisposition != model.ApplyCurrent || execution.ResponseBytes != int64(len(body)) {
				t.Fatalf("status evidence/byte count lost: incomplete=%v reach=%s bytes=%d", execution.ObserverIncomplete, execution.ReachabilityDisposition, execution.ResponseBytes)
			}
			if status == 200 && (execution.CapabilityDisposition != model.ApplyNotApplicable || execution.Success || h.tracker.Status(h.route.ID).ConsecutiveFail != 0) {
				t.Fatal("capacity manufactured a 2xx failure/success")
			}
			if status != 200 && execution.CapabilityDisposition != model.ApplyCurrent {
				t.Fatalf("pure status evidence discarded: %s", execution.CapabilityDisposition)
			}
			if status == 429 && h.tracker.Status(h.route.ID).CooldownUntil == 0 {
				t.Fatal("429 did not establish cooldown")
			}
		})
	}
}
