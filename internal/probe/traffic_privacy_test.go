package probe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/proxy"
	"github.com/279814/relay-gate/internal/sample"
	"github.com/279814/relay-gate/internal/store"
	"github.com/279814/relay-gate/internal/transform"
)

type privacyLogBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *privacyLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}
func (b *privacyLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

type trafficPrivacyHarness struct {
	*trafficHTTPHarness
	samples *sample.Recorder
	logs    *sample.LogRecorder
	text    *privacyLogBuffer
}

// Reuse the real Store, Source, sequencer, bounded observer and recorder. The
// replacement HTTP entry additionally persists the actual proxy sample/log sinks.
func newTrafficPrivacyHarness(t *testing.T, remote http.HandlerFunc) *trafficPrivacyHarness {
	t.Helper()
	h := newTrafficHTTPHarness(t, remote)
	cfg := h.manager.cfg.(proxy.ConfigSource)
	settings, err := cfg.Settings()
	if err != nil {
		t.Fatal(err)
	}
	text := &privacyLogBuffer{}
	logger := slog.New(slog.NewTextHandler(text, nil))
	samples := sample.NewRecorder(h.store, settings, cfg, logger)
	logs := sample.NewLogRecorder(h.store, settings, cfg, logger)
	t.Cleanup(samples.Close)
	t.Cleanup(logs.Close)
	targets := outbound.NewProvider(h.manager.cfg.(outbound.EndpointConfigSource), nil, outbound.NewResolver(testHasher{}))
	h.handler = proxy.NewHandler(cfg, h.tracker, samples, []string{"test-relay-key"}, logger).
		WithRunState(fixtureController(t, h.store)).WithTargets(targets, h.store).WithObservers(h.manager).WithCountTokensCapability(h.caps).WithLogSink(logs)
	mux := http.NewServeMux()
	h.handler.Routes(mux)
	gate := httptest.NewServer(mux)
	t.Cleanup(gate.Close)
	h.url = gate.URL
	return &trafficPrivacyHarness{h, samples, logs, text}
}

func (h *trafficPrivacyHarness) flush(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	release, err := h.handler.Quiesce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	for _, flush := range []func(context.Context) error{h.manager.Flush, h.samples.Flush, h.logs.Flush} {
		if err := flush(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

func assertPrivateValuesAbsent(t *testing.T, where string, value any, private ...string) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if row, ok := value.(*model.Sample); ok {
		text += string(row.InBody) + string(row.OutBody) + string(row.RespBody)
		for _, attempt := range row.Attempts {
			text += string(attempt.OutBody) + string(attempt.RespBody)
		}
	}
	for _, secret := range private {
		if secret != "" && strings.Contains(text, secret) {
			t.Fatalf("%s contains a private fixture value", where)
		}
	}
}

func (h *trafficPrivacyHarness) assertDurablePrivacy(t *testing.T, attempts int, private ...string) []*model.ProbeExecution {
	t.Helper()
	h.flush(t)
	page, err := h.store.ListProbeExecutions(context.Background(), model.ProbeExecutionFilter{Trigger: model.TriggerRealTraffic})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != attempts {
		t.Fatalf("durable attempt count=%d want %d", len(page.Items), attempts)
	}
	for _, execution := range page.Items {
		wantCapability := model.ApplyCurrent
		if execution.StatusCode == 0 {
			wantCapability = model.ApplyNotApplicable
		}
		if execution.ReachabilityDisposition != model.ApplyCurrent || execution.CapabilityDisposition != wantCapability {
			t.Fatalf("evidence not committed with its correct scope: %+v", execution)
		}
		assertPrivateValuesAbsent(t, "probe execution", execution, private...)
	}
	assertPrivateValuesAbsent(t, "tracker status", h.tracker.Status(h.route.ID), private...)
	rows, err := h.store.ListSamples(store.SampleFilter{})
	if err != nil {
		t.Fatal(err)
	}
	wantSamples, wantLogs := 1, attempts
	if page.Items[0].Endpoint == model.EndpointCountTokens {
		wantSamples = 0 // count_tokens retains actual-send metadata logs, never body samples
	}
	if len(rows) != wantSamples {
		t.Fatalf("persisted sample groups=%d want %d", len(rows), wantSamples)
	}
	if wantSamples > 0 {
		full, err := h.store.GetSample(rows[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(full.Attempts) != attempts {
			t.Fatalf("sample attempts=%d want %d", len(full.Attempts), attempts)
		}
		assertPrivateValuesAbsent(t, "sample metadata and plaintext bodies", full, private...)
	}
	logs, err := h.store.ListRequestLogs(store.RequestLogFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != wantLogs {
		t.Fatalf("persisted request logs=%d want %d", len(logs), wantLogs)
	}
	if page.Items[0].Endpoint == model.EndpointCountTokens {
		executionIDs := make(map[string]bool, len(page.Items))
		for _, execution := range page.Items {
			executionIDs[execution.ID] = true
		}
		for _, row := range logs {
			if row.Endpoint != "/v1/messages/count_tokens" || row.ReqID == "" || !executionIDs[row.Metadata.ExecutionID] {
				t.Fatalf("count_tokens log lacks actual-send correlation: %+v", row.Metadata)
			}
		}
	}
	assertPrivateValuesAbsent(t, "request logs", logs, private...)
	assertPrivateValuesAbsent(t, "application logs", h.text.String(), private...)
	return page.Items
}

func TestTrafficPrivacy_ErrorBodyStaysOnClientWireButNeverInDurableEvidence(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprint("stream=", stream), func(t *testing.T) {
			const expectedKey = "sk-cal-upstream-key"
			payload := fmt.Sprintf(`{"type":"error","error":{"type":"authentication_error","code":"invalid_api_key","message":"private response sentence: %s"}}`, expectedKey)
			wire := payload
			if stream {
				wire = "event: error\ndata: " + payload + "\n\n"
			}
			h := newTrafficPrivacyHarness(t, func(w http.ResponseWriter, r *http.Request) {
				drainBody(r)
				key := r.Header.Get("X-Api-Key")
				if key == "" {
					key = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
				}
				if key != expectedKey {
					t.Error("fixture upstream received an unexpected credential")
				}
				if stream {
					w.Header().Set("Content-Type", "text/event-stream")
				} else {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(401)
				}
				_, _ = io.WriteString(w, wire)
			})
			status, output := h.requestProtocol(t, model.ProtoAnthropic)
			want := 401
			if stream {
				want = 200
			}
			if status != want || string(output) != wire || !strings.Contains(wire, h.up.APIKey) {
				t.Fatal("upstream private response was altered or fixture did not echo its own key")
			}
			executions := h.assertDurablePrivacy(t, 1, h.up.APIKey)
			if executions[0].ErrorClass != model.ErrorAuthRejected || executions[0].Success || executions[0].StatusCode != want {
				t.Fatalf("safe structured diagnostics lost: %+v", executions[0])
			}
			assertPrivateValuesAbsent(t, "diagnostic text", executions[0], "private response sentence")
		})
	}
}

func TestTrafficPrivacy_RetryUsesEachAttemptsOwnKey(t *testing.T) {
	echo := func(w http.ResponseWriter, r *http.Request) {
		drainBody(r)
		key := r.Header.Get("X-Api-Key")
		if key == "" {
			key = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(502)
		_, _ = fmt.Fprintf(w, `{"error":{"type":"server_error","message":"Invalid API key: %s"}}`, key)
	}
	h := newTrafficPrivacyHarness(t, echo)
	second := httptest.NewServer(http.HandlerFunc(echo))
	t.Cleanup(second.Close)
	up := &model.Upstream{Name: "privacy second", BaseURL: second.URL, APIKey: "sk-second-attempt-independent-key", AuthStyle: model.AuthAuto, Enabled: true, ProbeMode: model.ProbeModeActive}
	if err := h.store.CreateUpstream(up); err != nil {
		t.Fatal(err)
	}
	route := &model.Route{ModelNameID: h.route.ModelNameID, UpstreamID: up.ID, Priority: 2, Weight: 1, Enabled: true}
	if err := h.store.CreateRoute(route); err != nil {
		t.Fatal(err)
	}
	settings, settingsRevision, err := h.store.GetSettingsWithRevision()
	if err != nil {
		t.Fatal(err)
	}
	settings.RetryPolicy = model.RetryPolicyBalanced
	settings.RetryMaxAttempts = 2
	if _, err := h.store.SaveSettingsWithRevision(settings, settingsRevision); err != nil {
		t.Fatal(err)
	}
	if err := h.manager.cfg.(interface{ Refresh() error }).Refresh(); err != nil {
		t.Fatal(err)
	}
	status, output := h.requestProtocol(t, model.ProtoAnthropic)
	if status != 502 || !bytes.Contains(output, []byte(up.APIKey)) || bytes.Contains(output, []byte(h.up.APIKey)) {
		t.Fatalf("final attempt wire/identity changed: status=%d", status)
	}
	executions := h.assertDurablePrivacy(t, 2, h.up.APIKey, up.APIKey)
	seen := map[int64]bool{}
	for _, execution := range executions {
		seen[execution.RouteID] = true
		if execution.ErrorClass != model.ErrorTransient || execution.Success {
			t.Fatalf("HTTP 502 not transient: %+v", execution)
		}
	}
	if !seen[h.route.ID] || !seen[route.ID] {
		t.Fatal("discarded/final attempt identities conflated")
	}
}

func TestTrafficPrivacy_MalformedStatusCannotPersistEchoedRequestSecret(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				line, err := bufio.NewReader(conn).ReadString('\n')
				if err == nil {
					_, _ = io.WriteString(conn, line+"\r\n")
				}
			}()
		}
	}()
	h := newTrafficPrivacyHarness(t, http.NotFound)
	h.up.BaseURL = "http://" + listener.Addr().String()
	if err := h.store.UpdateUpstreamWithRevision(context.Background(), h.up, h.up.Revision); err != nil {
		t.Fatal(err)
	}
	ep, err := h.store.Endpoint(context.Background(), h.up.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	ep.FixedQueryTemplate = "key={{UPSTREAM_API_KEY}}"
	if err := h.store.UpdateEndpoint(ep, ep.Revision); err != nil {
		t.Fatal(err)
	}
	if err := h.manager.cfg.(interface{ Refresh() error }).Refresh(); err != nil {
		t.Fatal(err)
	}
	status, output := h.requestProtocol(t, model.ProtoAnthropic)
	if status == 200 || bytes.Contains(output, []byte(h.up.APIKey)) {
		t.Fatal("malformed response succeeded or exposed request secret to client")
	}
	execution := h.assertDurablePrivacy(t, 1, h.up.APIKey)[0]
	if execution.Success || execution.StatusCode != 0 || execution.ErrorClass == model.ErrorIgnored || execution.RedactedDetail == "" {
		t.Fatalf("malformed transport lost failure evidence: %+v", execution)
	}
}

func TestTrafficPrivacy_CountTokensNeverWritesModelHealth(t *testing.T) {
	for _, status := range []int{200, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			h := newTrafficPrivacyHarness(t, func(w http.ResponseWriter, r *http.Request) {
				drainBody(r)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				if status == 200 {
					_, _ = io.WriteString(w, `{"input_tokens":5}`)
				}
			})
			h.tracker.CompleteL2(h.route.ID, time.Now(), 0)
			before := h.tracker.Status(h.route.ID)
			if before.NextL2At == 0 {
				t.Fatal("fixture must arm a future L2 due time")
			}
			request, err := http.NewRequest(http.MethodPost, h.url+model.EndpointCountTokens.CanonicalPath(), strings.NewReader(`{"model":"claude-cal","messages":[{"role":"user","content":"hello"}]}`))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("X-Api-Key", "test-relay-key")
			request.Header.Set("Content-Type", "application/json")
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != 200 || !bytes.Contains(body, []byte("input_tokens")) {
				t.Fatalf("count_tokens response=%d %s", response.StatusCode, body)
			}
			execution := h.assertDurablePrivacy(t, 1, h.up.APIKey)[0]
			after := h.tracker.Status(h.route.ID)
			if after.State != before.State || after.ConsecutiveOK != before.ConsecutiveOK || after.ConsecutiveFail != before.ConsecutiveFail || after.LastOKAt != before.LastOKAt || after.LastErrAt != before.LastErrAt || after.NextL2At != before.NextL2At {
				t.Fatalf("count_tokens changed model health: before=%+v after=%+v", before, after)
			}
			if execution.Endpoint != model.EndpointCountTokens || execution.StatusCode != status {
				t.Fatalf("wrong endpoint execution: %+v", execution)
			}
			if row := h.caps.Snapshot(model.RecipeScopeRoute, h.route.ID, model.EndpointMessages); row != nil && (row.LastRealOKAt != 0 || row.LastRealOKToken != "") {
				t.Fatal("count_tokens forged model piggyback evidence")
			}
		})
	}
}

func TestTrafficPrivacy_ResponseTransformCannotEraseOriginalStructuredError(t *testing.T) {
	original := `{"type":"error","error":{"type":"authentication_error","message":"private upstream sentence"}}`
	h := newTrafficPrivacyHarness(t, func(w http.ResponseWriter, r *http.Request) {
		drainBody(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, original)
	})
	ep, err := h.store.Endpoint(context.Background(), h.up.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	registry := transform.NewRegistry(8)
	set, err := registry.CreateSet("erase original error")
	if err != nil {
		t.Fatal(err)
	}
	transformed := `{"type":"message","content":[{"type":"text","text":"injected success"}]}`
	if _, err := registry.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindReplaceBytes, From: original, To: transformed}}, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := registry.PublishSnapshot(set.ID, h.route.ID, ep.ID); err != nil {
		t.Fatal(err)
	}
	h.handler.WithTransforms(registry)
	if output := h.request(t); string(output) != transformed {
		t.Fatal("fixture transform did not produce the alternate client body")
	}
	execution := h.assertDurablePrivacy(t, 1, h.up.APIKey)[0]
	if execution.Success || execution.ErrorClass != model.ErrorAuthRejected || execution.SemanticSeen {
		t.Fatalf("gateway transform changed original health evidence: %+v", execution)
	}
	assertPrivateValuesAbsent(t, "structured diagnostic", execution, "private upstream sentence", "injected success")
}
