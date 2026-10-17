package proxy

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

func TestWireProtocolErrorFactsAcrossChunks(t *testing.T) {
	text := "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"error\"}}\n\n"
	remote := "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\"}}\n\n"
	for _, tc := range []struct {
		name             string
		proto            model.Protocol
		body             string
		semantic, remote bool
	}{
		{"midstream", model.ProtoAnthropic, text + remote, true, true},
		{"openai", model.ProtoOpenAIChat, "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: {\"error\":{\"type\":\"insufficient_quota\"}}\n\n", true, true},
		{"text-spells-error", model.ProtoAnthropic, text + "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n", true, false},
		{"heartbeat", model.ProtoAnthropic, ": keepalive\n\nevent: ping\ndata: {}\n\nevent: message_start\ndata: {\"type\":\"message_start\"}\n\n", false, false},
		{"error-first", model.ProtoAnthropic, remote + text, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, width := range []int{1, 5, 32, len(tc.body)} {
				w := newWireEvidence(tc.proto, http.Header{"Content-Type": {"text/event-stream"}}, nil)
				input := []byte(tc.body)
				original := append([]byte(nil), input...)
				for p := 0; p < len(input); p += width {
					end := p + width
					if end > len(input) {
						end = len(input)
					}
					w.feed(input[p:end], time.Now())
				}
				w.finish()
				state := w.snapshot()
				if !bytes.Equal(input, original) || rawProtocolError(input, "text/event-stream") != tc.remote || (!state.FirstSemanticAt.IsZero()) != tc.semantic {
					t.Fatalf("width=%d state=%+v input mutated=%v", width, state, !bytes.Equal(input, original))
				}
			}
		})
	}
}

func TestWireOversizeFailsClosedWithoutRetainingErrorText(t *testing.T) {
	for _, terminated := range []bool{false, true} {
		w := newWireEvidence(model.ProtoAnthropic, http.Header{}, nil)
		input := []byte("data: {\"error\":{\"message\":\"" + strings.Repeat("x", controlEventLimit) + "\"}}")
		if terminated {
			input = append(input, '\n', '\n')
		}
		original := append([]byte(nil), input...)
		w.feed(input, time.Now())
		w.feed([]byte("\nevent: error\ndata: {\"type\":\"error\"}\n\n"), time.Now())
		if !bytes.Equal(input, original) || w.snapshot().Incomplete == "" || rawProtocolError(input, "text/event-stream") {
			t.Fatalf("oversize must stay incomplete without guessed recovery: %+v", w.snapshot())
		}
	}
}
