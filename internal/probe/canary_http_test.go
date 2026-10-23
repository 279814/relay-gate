package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

func canaryRequestNonce(t *testing.T, body []byte, kind model.EndpointKind) string {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err != nil {
		t.Error(err)
		return ""
	}
	tools := canaryArray(object["tools"])
	if len(tools) != 1 {
		t.Error("Canary request must expose exactly one inert tool")
		return ""
	}
	tool := tools[0]
	if kind == model.EndpointChatCompletions {
		tool = canaryObject(tool["function"])
	}
	schema := canaryObject(tool["parameters"])
	if kind == model.EndpointMessages {
		schema = canaryObject(tool["input_schema"])
	}
	properties := canaryObject(schema["properties"])
	var values []string
	_ = json.Unmarshal(canaryObject(properties["nonce"])["enum"], &values)
	if len(values) != 1 || len(values[0]) != 32 {
		t.Error("Canary request omitted random nonce expectation")
		return ""
	}
	return values[0]
}

func TestCanaryManualLazyRealHTTPUsesOneExecutorAndSeparateCost(t *testing.T) {
	for _, proto := range []model.Protocol{model.ProtoAnthropic, model.ProtoOpenAIResponses, model.ProtoOpenAIChat} {
		t.Run(string(proto), func(t *testing.T) {
			kind, _ := proto.Endpoint()
			var calls atomic.Int64
			var previous string
			h := newTrafficHTTPHarnessFor(t, proto, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				if r.URL.Path != kind.CanonicalPath() || strings.Contains(string(body), "1+1") {
					t.Error("Canary reused ordinary Recipe or another endpoint")
				}
				if kind == model.EndpointMessages && r.Header.Get("Anthropic-Version") != "2023-06-01" {
					t.Error("Canary omitted the native messages protocol version")
				}
				nonce := canaryRequestNonce(t, body, kind)
				if nonce == previous {
					t.Error("Canary reused a nonce")
				}
				previous = nonce
				args := fmt.Sprintf(`{"nonce":%q}`, nonce)
				w.Header().Set("Content-Type", "application/json")
				switch kind {
				case model.EndpointMessages:
					_, _ = fmt.Fprintf(w, `{"content":[{"type":"tool_use","id":"one","name":"relay_canary_noop","input":%s}],"stop_reason":"tool_use","usage":{"input_tokens":12,"output_tokens":7}}`, args)
				case model.EndpointResponses:
					_, _ = fmt.Fprintf(w, `{"status":"completed","output":[{"id":"one","type":"function_call","name":"relay_canary_noop","arguments":%q}],"usage":{"input_tokens":12,"output_tokens":7}}`, args)
				case model.EndpointChatCompletions:
					_, _ = fmt.Fprintf(w, `{"choices":[{"index":0,"message":{"tool_calls":[{"id":"one","type":"function","function":{"name":"relay_canary_noop","arguments":%q}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":12,"completion_tokens":7}}`, args)
				}
			})
			h.up.ProbeMode = model.ProbeModeLazy
			if err := h.store.UpdateUpstreamWithRevision(context.Background(), h.up, h.up.Revision); err != nil {
				t.Fatal(err)
			}
			endpoint, err := h.store.Endpoint(context.Background(), h.up.ID, kind)
			if err != nil {
				t.Fatal(err)
			}
			endpoint.LegacyCompatRealOnly = false
			endpoint.AuthProfile = model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: "upstream_api_key"}
			if err := h.store.UpdateEndpoint(endpoint, endpoint.Revision); err != nil {
				t.Fatal(err)
			}
			service := manualAuthProbeService(t, h, h.store)
			service.executor.recorder = NewResultRecorder(h.store, health.NewObservationReducer(nil), h.reach, h.caps)
			if _, err := h.store.DB().Exec(`UPDATE route_health SET state='dead',consecutive_fail=3,last_error='synthetic existing failure'`); err != nil {
				t.Fatal(err)
			}
			healthBefore, err := h.store.ListRouteHealth()
			if err != nil {
				t.Fatal(err)
			}
			for round := range 2 {
				execution, err := service.RunCanary(context.Background(), h.route.ID)
				if err != nil {
					t.Fatal(err)
				}
				if execution.Canary == nil || execution.Canary.Verdict != "passed" || execution.Canary.Source != model.CanaryManual || execution.ExpectedCancel || !execution.NormalEndSeen || execution.CapabilityDisposition != model.ApplyNotApplicable || execution.ReachabilityDisposition != model.ApplyNotApplicable {
					t.Fatalf("manual Lazy Canary round=%d: %+v", round, execution)
				}
				if execution.ObservedOutputTokens != 7 {
					t.Fatalf("Canary lost native positive output usage: %d", execution.ObservedOutputTokens)
				}
				loaded, err := h.store.GetProbeExecution(context.Background(), execution.ID)
				if err != nil || loaded.Canary == nil || loaded.Canary.EvidenceHash != execution.Canary.EvidenceHash {
					t.Fatalf("missing durable exact result: %+v %v", loaded, err)
				}
			}
			if calls.Load() != 2 {
				t.Fatalf("Canary sent %d requests, want exactly one per click", calls.Load())
			}
			var requests, unknown, output, ordinary int
			if err := h.store.DB().QueryRow(`SELECT SUM(requests),SUM(unknown_output_rows),SUM(observed_output_tokens) FROM canary_cost_daily`).Scan(&requests, &unknown, &output); err != nil || requests != 2 || unknown != 0 || output != 14 {
				t.Fatalf("separate native Canary cost=%d/%d/%d %v", requests, unknown, output, err)
			}
			if err := h.store.DB().QueryRow(`SELECT COUNT(*) FROM probe_cost_daily`).Scan(&ordinary); err != nil || ordinary != 0 {
				t.Fatalf("Canary polluted Recipe daily: %d %v", ordinary, err)
			}
			for _, table := range []string{"endpoint_capability", "upstream_reachability"} {
				var count int
				if err := h.store.DB().QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 0 {
					t.Fatalf("Canary changed health %s=%d %v", table, count, err)
				}
			}
			healthAfter, err := h.store.ListRouteHealth()
			if err != nil || !reflect.DeepEqual(healthBefore, healthAfter) {
				t.Fatalf("Canary changed persistent Route health: before=%+v after=%+v err=%v", healthBefore, healthAfter, err)
			}
		})
	}
}
