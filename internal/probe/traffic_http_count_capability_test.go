package probe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
)

func TestCountTokensHTTPCommitsEndpointCapabilityAndSkipsUnsupported(t *testing.T) {
	for _, testCase := range []struct {
		status int
		body   string
		want   model.CapabilityState
	}{
		{404, `{"error":{"message":"no count_tokens"}}`, model.CapabilityUnsupported},
		{405, `{"error":{"message":"no method"}}`, model.CapabilityUnsupported},
		{401, `{"error":{"type":"authentication_error"}}`, model.CapabilityConfigError},
		{403, `{"error":{"type":"permission_error"}}`, model.CapabilityConfigError},
		{500, `{"error":{"type":"server_error"}}`, model.CapabilityTransientError},
		{200, `{"input_tokens":13}`, model.CapabilitySupported},
		{200, `{"input_tokens":0}`, model.CapabilityTransientError},
	} {
		t.Run(fmt.Sprintf("%d-%s", testCase.status, testCase.want), func(t *testing.T) {
			var countHits, messageHits atomic.Int32
			h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == model.EndpointCountTokens.CanonicalPath() {
					countHits.Add(1)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(testCase.status)
					_, _ = io.WriteString(w, testCase.body)
					return
				}
				messageHits.Add(1)
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, anthropicSemanticBody())
			})
			ep, err := h.store.Endpoint(context.Background(), h.up.ID, model.EndpointCountTokens)
			if err != nil {
				t.Fatal(err)
			}
			ep.LegacyCompatRealOnly = false
			ep.AuthProfile = model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: "upstream_api_key"}
			if err := h.store.UpdateEndpoint(ep, ep.Revision); err != nil {
				t.Fatal(err)
			}
			cfg := h.manager.cfg.(*livecfg.Source)
			cfg.Invalidate()
			if err := cfg.Refresh(); err != nil {
				t.Fatal(err)
			}
			before := h.tracker.Snapshot()
			send := func(kind model.EndpointKind) {
				t.Helper()
				request, err := http.NewRequest(http.MethodPost, h.url+kind.CanonicalPath(), strings.NewReader(`{"model":"claude-cal","messages":[]}`))
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("X-Api-Key", "test-relay-key")
				response, err := http.DefaultClient.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				_, err = io.Copy(io.Discard, response.Body)
				response.Body.Close()
				if err != nil || response.StatusCode != http.StatusOK {
					t.Fatalf("status=%d err=%v", response.StatusCode, err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				release, err := h.handler.Quiesce(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer release()
				if err := h.manager.Flush(ctx); err != nil {
					t.Fatal(err)
				}
			}
			send(model.EndpointCountTokens)
			if countHits.Load() != 1 {
				t.Fatal("count_tokens never reached its native endpoint")
			}
			got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointCountTokens, "")
			if got != testCase.want {
				t.Fatalf("committed capability=%s want=%s", got, testCase.want)
			}
			if !reflect.DeepEqual(before, h.tracker.Snapshot()) {
				t.Fatal("count_tokens changed model health")
			}
			if testCase.want == model.CapabilityUnsupported || testCase.want == model.CapabilityConfigError {
				send(model.EndpointCountTokens)
				if countHits.Load() != 1 {
					t.Fatal("committed endpoint exclusion was ignored by selection")
				}
			} else {
				send(model.EndpointCountTokens)
				if countHits.Load() != 2 {
					t.Fatal("supported or transient evidence incorrectly excluded count_tokens")
				}
			}
			send(model.EndpointMessages)
			if messageHits.Load() != 1 {
				t.Fatal("count_tokens capability excluded the model endpoint")
			}
		})
	}
}
