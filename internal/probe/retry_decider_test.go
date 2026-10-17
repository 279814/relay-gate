package probe

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

func TestRetryDecider_OnlyCompleteStructuredErrorsCanReplay(t *testing.T) {
	for _, tc := range []struct {
		name, body      string
		complete, retry bool
	}{
		{"error null", `{"type":"message","error":null,"content":[{"type":"text","text":"ok"}]}`, true, false},
		{"business text", `{"type":"message","content":[{"type":"text","text":"example error: explanation"}]}`, true, false},
		{"incomplete error", `{"error":{"type":"server_error"`, false, false},
		{"structured error", `{"error":{"type":"server_error"}}`, true, true},
		{"usage followed by error", "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"part\"}}\n\ndata: {\"type\":\"error\",\"error\":{\"type\":\"server_error\"}}\n\n", true, false},
		{"over budget", strings.Repeat(" ", 64<<10) + `{"error":{"type":"server_error"}}`, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			advice := NewRetryDecider(model.ProtoAnthropic).DecidePeek(context.Background(), 200, http.Header{}, []byte(tc.body), tc.complete)
			if got := advice.Disposition == health.RetryTryNextRoute; got != tc.retry {
				t.Fatalf("retry=%v want %v advice=%+v", got, tc.retry, advice)
			}
		})
	}
}
