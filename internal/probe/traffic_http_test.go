package probe

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/observationseq"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/proxy"
	"github.com/279814/relay-gate/internal/store"
	"github.com/279814/relay-gate/internal/transform"
)

type trafficHTTPHarness struct {
	store   *store.Store
	manager *TrafficObserverManager
	caps    *CapabilityRegistry
	reach   *health.ReachabilityTracker
	tracker *health.Tracker
	route   *model.Route
	up      *model.Upstream
	url     string
	handler *proxy.Handler
}

func newTrafficHTTPHarness(t *testing.T, upstream http.HandlerFunc) *trafficHTTPHarness {
	return newTrafficHTTPHarnessFor(t, model.ProtoAnthropic, upstream)
}

func newTrafficHTTPHarnessFor(t *testing.T, protocol model.Protocol, upstream http.HandlerFunc) *trafficHTTPHarness {
	t.Helper()
	remote := httptest.NewServer(upstream)
	t.Cleanup(remote.Close)
	st := calibrationTestStore(t)
	up, name, route := seedCalibrationRoute(t, st)
	if protocol != name.Protocol {
		name.Protocol = protocol
		if err := st.UpdateModelNameWithRevision(context.Background(), name, name.Revision); err != nil {
			t.Fatal(err)
		}
	}
	up.BaseURL = remote.URL
	if err := st.UpdateUpstreamWithRevision(context.Background(), up, up.Revision); err != nil {
		t.Fatal(err)
	}
	cfg, _ := restoreTestDeps(st)
	if _, err := cfg.Bundle(); err != nil {
		t.Fatal(err)
	}
	tracker := health.NewTracker(cfg)
	caps := NewCapabilityRegistry(cfg).WithRouteGeneration(tracker)
	reach := health.NewReachabilityTracker(cfg)
	seq, err := observationseq.Open(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(seq.Close)
	recorder := NewResultRecorder(st, health.NewObservationReducer(nil), reach, caps)
	manager := NewTrafficObserverManager(cfg, seq, recorder, discardLogger()).WithHealthTracker(tracker).WithLearner(NewLearner(st))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { manager.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	targets := outbound.NewProvider(cfg, nil, outbound.NewResolver(testHasher{}))
	handler := proxy.NewHandler(cfg, tracker, nil, []string{"test-relay-key"}, discardLogger()).
		WithRunState(fixtureController(t, st)).WithTargets(targets, st).WithObservers(manager).WithCountTokensCapability(caps)
	mux := http.NewServeMux()
	handler.Routes(mux)
	gate := httptest.NewServer(mux)
	t.Cleanup(gate.Close)
	return &trafficHTTPHarness{st, manager, caps, reach, tracker, route, up, gate.URL, handler}
}

func TestTrafficHTTP_ResponseTransformCannotForgeRealSuccess(t *testing.T) {
	semantic := "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"upstream text\"}}\n\n"
	for _, tc := range []struct {
		name, body, contentType string
		rule                    transform.Rule
		partial                 bool
	}{
		{"injected semantic", `{"type":"message","content":[]}`, "application/json", transform.Rule{Kind: transform.KindReplaceBytes, From: `"content":[]`, To: `"content":[{"type":"text","text":"fabricated"}]`}, false},
		{"synthetic end", semantic, "text/event-stream", transform.Rule{Kind: transform.KindSSEAppendEnd, Match: "message_stop", Value: `{"type":"message_stop"}`}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				_, _ = io.WriteString(w, tc.body)
			})
			endpoint, err := h.store.Endpoint(context.Background(), h.up.ID, model.EndpointMessages)
			if err != nil {
				t.Fatal(err)
			}
			registry := transform.NewRegistry(8)
			set, err := registry.CreateSet(tc.name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := registry.UpdateDraft(set.ID, []transform.Rule{tc.rule}, transform.FailClosed, transform.FailOpen, ""); err != nil {
				t.Fatal(err)
			}
			if _, _, err := registry.PublishSnapshot(set.ID, h.route.ID, endpoint.ID); err != nil {
				t.Fatal(err)
			}
			h.handler.WithTransforms(registry)
			out := h.request(t)
			if tc.partial && !bytes.Contains(out, []byte("message_stop")) {
				t.Fatal("fixture did not append synthetic end")
			}
			if !tc.partial && !bytes.Contains(out, []byte("fabricated")) {
				t.Fatal("fixture did not inject semantic text")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := h.manager.Flush(ctx); err != nil {
				t.Fatal(err)
			}
			execution := h.execution(t)
			if execution.Success || execution.Partial != tc.partial {
				t.Fatalf("transform forged success: success=%v partial=%v", execution.Success, execution.Partial)
			}
			row := h.caps.Snapshot(model.RecipeScopeRoute, h.route.ID, model.EndpointMessages)
			if row.LastRealOKAt != 0 || row.LastRealOKToken != "" {
				t.Fatal("gateway transform created piggyback evidence")
			}
			profiles, err := h.store.ListClientProfilesPage(context.Background(), model.ClientProfileFilter{UpstreamID: h.up.ID})
			if err != nil {
				t.Fatal(err)
			}
			if len(profiles.Items) != 0 {
				t.Fatal("gateway transform created a learned profile")
			}
		})
	}
}

func (h *trafficHTTPHarness) request(t *testing.T) []byte {
	t.Helper()
	status, body := h.requestProtocol(t, model.ProtoAnthropic)
	if status != 200 {
		t.Fatalf("response status=%d body=%s", status, body)
	}
	return body
}

func (h *trafficHTTPHarness) requestProtocol(t *testing.T, protocol model.Protocol) (int, []byte) {
	t.Helper()
	endpoint, _ := protocol.Endpoint()
	body := `{"model":"claude-cal","messages":[{"role":"user","content":"private request text"}],"max_tokens":16,"stream":true}`
	if protocol == model.ProtoOpenAIResponses {
		body = `{"model":"claude-cal","input":"private request text","max_output_tokens":16,"stream":true}`
	}
	req, err := http.NewRequest(http.MethodPost, h.url+endpoint.CanonicalPath(), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Api-Key", "test-relay-key")
	req.Header.Set("Authorization", "Bearer test-relay-key")
	req.Header.Set("Content-Type", "application/json")
	// Go's client must expose the wire bytes for the strict passthrough assertion.
	req.Header.Set("Accept-Encoding", "identity")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	output, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, output
}

func (h *trafficHTTPHarness) execution(t *testing.T) *model.ProbeExecution {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		page, err := h.store.ListProbeExecutions(context.Background(), model.ProbeExecutionFilter{Trigger: model.TriggerRealTraffic})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) > 0 {
			return page.Items[0]
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("real Attempt did not persist a probe_execution")
	return nil
}

func TestTrafficHTTP_CompleteAndPartialResponsesUseUnifiedObservation(t *testing.T) {
	semantic := "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n"
	complete := semantic + "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	for _, tc := range []struct {
		name             string
		body             string
		gzip             bool
		success, partial bool
	}{
		{"complete SSE", complete, false, true, false},
		{"semantic without protocol end", semantic, false, false, true},
		{"complete JSON", `{"type":"message","content":[{"type":"text","text":"hello"}],"usage":{"output_tokens":4}}`, false, true, false},
		{"gzip SSE", complete, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := []byte(tc.body)
			if tc.gzip {
				var output bytes.Buffer
				writer := gzip.NewWriter(&output)
				_, _ = writer.Write(wire)
				_ = writer.Close()
				wire = output.Bytes()
			}
			h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				if strings.HasPrefix(tc.body, "{") {
					w.Header().Set("Content-Type", "application/json")
				}
				if tc.gzip {
					w.Header().Set("Content-Encoding", "gzip")
				}
				for start := 0; start < len(wire); start += 11 {
					end := min(start+11, len(wire))
					_, _ = w.Write(wire[start:end])
					w.(http.Flusher).Flush()
				}
			})
			if got := h.request(t); !bytes.Equal(got, wire) {
				t.Fatal("observation changed wire response bytes")
			}
			execution := h.execution(t)
			if execution.CapabilityPolicySelector.Kind != model.EvidenceRealTraffic {
				t.Fatalf("model traffic used synthetic policy: %s", execution.CapabilityPolicySelector.Kind)
			}
			if execution.Success != tc.success || execution.Partial != tc.partial {
				t.Fatalf("observation success=%v partial=%v class=%s", execution.Success, execution.Partial, execution.ErrorClass)
			}
			if execution.ReachabilityDisposition != model.ApplyCurrent || execution.CapabilityDisposition != model.ApplyCurrent {
				t.Fatalf("observation not committed: reach=%s capability=%s", execution.ReachabilityDisposition, execution.CapabilityDisposition)
			}
			if execution.Success && (!execution.SemanticSeen || !execution.NormalEndSeen) {
				t.Fatal("success lacks complete protocol evidence")
			}
			if !execution.RealRequestShapeLearnable || execution.RealRequestShapeHash == "" {
				t.Fatalf("final request was not safely shaped: reason=%s", execution.RealRequestShapeUnavailableReason)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := h.manager.Flush(ctx); err != nil {
				t.Fatal(err)
			}
			profiles, err := h.store.ListClientProfilesPage(context.Background(), model.ClientProfileFilter{UpstreamID: h.up.ID})
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if tc.success {
				want = 1
			}
			if len(profiles.Items) != want {
				t.Fatalf("normal successes alone may learn: profiles=%d want=%d", len(profiles.Items), want)
			}
			if want == 1 {
				profile := profiles.Items[0]
				if profile.Status != model.ProfileCandidate || profile.ClientFamily == "" || strings.Contains(string(profile.BodyTemplate), "private request text") || strings.Contains(string(profile.BodyShapeJSON), "private request text") {
					t.Fatalf("unsafe or published learner candidate: %+v", profile)
				}
			}
		})
	}
}

func TestTrafficHTTP_PartialDoesNotBecomeHealthy(t *testing.T) {
	body := "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"partial\"}}\n\n"
	h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, body)
	})
	h.request(t)
	h.execution(t)
	deadline := time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(deadline) {
		if h.tracker.Status(h.route.ID).ConsecutiveFail > 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("semantic bytes without normal protocol end were reported healthy")
}

func TestTrafficHTTP_GzipTracksSemanticArrivalBeforeStreamEnd(t *testing.T) {
	h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "gzip")
		encoder := gzip.NewWriter(w)
		_, _ = io.WriteString(encoder, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"early\"}}\n\n")
		_ = encoder.Flush()
		w.(http.Flusher).Flush()
		time.Sleep(120 * time.Millisecond)
		_, _ = io.WriteString(encoder, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
		_ = encoder.Close()
	})
	h.request(t)
	execution := h.execution(t)
	if !execution.Success || execution.DoneAtMS-execution.FirstSemanticAtMS < 60 {
		t.Fatalf("gzip semantic timing waited for stream end: first=%d done=%d success=%v", execution.FirstSemanticAtMS, execution.DoneAtMS, execution.Success)
	}
}

func TestTrafficHTTP_TruncatedTransportAfterSemanticIsPartial(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		t.Run(fmt.Sprintf("gzip=%v", compressed), func(t *testing.T) {
			wire := []byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"partial\"}}\n\n")
			encoding := ""
			if compressed {
				var output bytes.Buffer
				encoder := gzip.NewWriter(&output)
				_, _ = encoder.Write(wire)
				_ = encoder.Flush() // no gzip footer: upstream disconnects
				wire, encoding = output.Bytes(), "Content-Encoding: gzip\r\n"
			}
			h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, _ *http.Request) {
				connection, buffered, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer connection.Close()
				_, _ = fmt.Fprintf(buffered, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n%s\r\n%x\r\n%s\r\n", encoding, len(wire), wire)
				_ = buffered.Flush() // omit terminal HTTP chunk as well
			})
			h.request(t)
			execution := h.execution(t)
			if !execution.Partial || execution.Success || execution.CapabilityDisposition != model.ApplyCurrent {
				t.Fatalf("truncated upstream lost reliable partial evidence: partial=%v success=%v class=%s disposition=%s", execution.Partial, execution.Success, execution.ErrorClass, execution.CapabilityDisposition)
			}
		})
	}
}

func TestTrafficHTTP_SamplesDisabledStillObserveAndLearn(t *testing.T) {
	h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"type":"message","content":[{"type":"text","text":"ok"}]}`)
	})
	settings, settingsRevision, err := h.store.GetSettingsWithRevision()
	if err != nil {
		t.Fatal(err)
	}
	settings.SampleEnabled = false
	if _, err := h.store.SaveSettingsWithRevision(settings, settingsRevision); err != nil {
		t.Fatal(err)
	}
	if err := h.manager.cfg.(interface{ Refresh() error }).Refresh(); err != nil {
		t.Fatal(err)
	}
	h.request(t)
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
	profiles, err := h.store.ListClientProfilesPage(ctx, model.ClientProfileFilter{UpstreamID: h.up.ID})
	if err != nil {
		t.Fatal(err)
	}
	if !execution.Success || !execution.RealRequestShapeLearnable || len(profiles.Items) != 1 {
		t.Fatal("sample_enabled=false disabled independent health or learning")
	}
}

func TestTrafficHTTP_DiscardedAndFinalAttemptsEachCommitExecution(t *testing.T) {
	h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(503)
		_, _ = io.WriteString(w, `{"error":{"type":"server_error"}}`)
	})
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"type":"message","content":[{"type":"text","text":"final"}]}`)
	}))
	t.Cleanup(remote.Close)
	up := &model.Upstream{Name: "second", BaseURL: remote.URL, APIKey: "sk-second-upstream-key", AuthStyle: model.AuthAuto, Enabled: true, ProbeMode: model.ProbeModeActive}
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
	if _, err := h.store.SaveSettingsWithRevision(settings, settingsRevision); err != nil {
		t.Fatal(err)
	}
	if err := h.manager.cfg.(interface{ Refresh() error }).Refresh(); err != nil {
		t.Fatal(err)
	}
	if body := h.request(t); !bytes.Contains(body, []byte("final")) {
		t.Fatalf("retry did not reach final route: %s", body)
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
	page, err := h.store.ListProbeExecutions(ctx, model.ProbeExecutionFilter{Trigger: model.TriggerRealTraffic})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("attempt executions=%d", len(page.Items))
	}
	seen := make(map[int64]*model.ProbeExecution)
	for _, execution := range page.Items {
		if execution.ObservationOrder <= 0 || execution.CapabilityDisposition != model.ApplyCurrent || execution.ReachabilityDisposition != model.ApplyCurrent || execution.RecipeBindingUse != model.BindingRealTrafficContext || execution.SentAtMS == 0 || execution.GotConnAtMS == 0 {
			t.Fatalf("attempt lacks current dual evidence/trace: %+v", execution)
		}
		seen[execution.RouteID] = execution
	}
	if seen[h.route.ID] == nil || seen[route.ID] == nil || seen[h.route.ID].Success || !seen[route.ID].Success || seen[h.route.ID].ObservationOrder >= seen[route.ID].ObservationOrder {
		t.Fatal("discarded and final attempt identities/order were conflated")
	}
}
