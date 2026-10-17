package probe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

// All former Reporter assertions now enter through real HTTP, the bounded
// observer, the production classifier/reducer and SQLite transaction CAS.
func settleRealTraffic(t *testing.T, h *trafficHTTPHarness) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
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

func TestRealTraffic_ProtocolEvidenceOwnsHealthAndPiggyback(t *testing.T) {
	semantic := "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n"
	for _, tc := range []struct {
		name, body, contentType string
		status                  int
		success, partial        bool
		class                   model.ErrorClass
	}{
		{"type error object", `{"type":"error","error":{"type":"server_error","message":"boom"}}`, "application/json", 200, false, false, model.ErrorTransient},
		{"top-level error key", `{"error":{"type":"api_error","message":"fail"}}`, "application/json", 200, false, false, model.ErrorTransient},
		{"SSE error event", "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\"}}\n\n", "text/event-stream", 200, false, false, model.ErrorRateLimited},
		{"JSON rate limit", `{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}`, "application/json", 200, false, false, model.ErrorRateLimited},
		{"complete semantic JSON", `{"type":"message","content":[{"type":"text","text":"hello"}]}`, "application/json", 200, true, false, ""},
		{"complete semantic SSE", semantic + "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n", "text/event-stream", 200, true, false, ""},
		{"HTML has bytes but no protocol evidence", "<html>not a model response</html>", "text/html", 200, false, false, ""},
		{"valid empty protocol content", `{"type":"message","content":[]}`, "application/json", 200, false, false, model.ErrorFakeAlive},
		{"empty 200", "", "application/json", 200, false, false, ""},
		{"302 cannot become success", `{"redirect":true}`, "application/json", 302, false, false, model.ErrorTransient},
		{"semantic followed by error", semantic + "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"server_error\"}}\n\n", "text/event-stream", 200, false, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, r *http.Request) {
				drainBody(r)
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			})
			gen := h.tracker.EnsureGeneration(h.route.ID)
			h.tracker.Report(health.Report{RouteID: h.route.ID, Generation: gen, Verdict: health.VerdictOK, Source: health.SourceReal})
			seeded := h.tracker.Status(h.route.ID).LastRealOKAt
			time.Sleep(2 * time.Millisecond)
			status, body := h.requestProtocol(t, model.ProtoAnthropic)
			if status != tc.status || string(body) != tc.body {
				t.Fatalf("observation changed response: status=%d body=%q", status, body)
			}
			settleRealTraffic(t, h)
			execution := h.execution(t)
			if execution.Success != tc.success || execution.Partial != tc.partial || (tc.class != "" && execution.ErrorClass != tc.class) {
				t.Fatalf("protocol evidence changed: %+v", execution)
			}
			after := h.tracker.Status(h.route.ID)
			row := h.caps.Snapshot(model.RecipeScopeRoute, h.route.ID, model.EndpointMessages)
			if tc.success {
				if !execution.SemanticSeen || !execution.NormalEndSeen || after.LastRealOKAt <= seeded || after.ConsecutiveFail != 0 || row == nil || row.LastRealOKAt == 0 || row.LastRealOKToken == "" {
					t.Fatalf("complete semantic success lost piggyback evidence: status=%+v capability=%+v", after, row)
				}
			} else {
				if after.LastRealOKAt != seeded || (row != nil && (row.LastRealOKAt != 0 || row.LastRealOKToken != "")) {
					t.Fatal("incomplete/error response forged real success")
				}
				// A decoder failure supplies no reliable negative body evidence;
				// valid structured errors and partial streams do count as failures.
				if execution.ErrorClass != model.ErrorIgnored && execution.ErrorClass != model.ErrorRateLimited && after.ConsecutiveFail < 1 {
					t.Fatalf("valid failure was not reported: execution=%+v health=%+v", execution, after)
				}
			}
		})
	}
}

func TestRealTraffic_Live401403DoesNotMarkModelDeadOrCooldown(t *testing.T) {
	for _, status := range []int{401, 403} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, r *http.Request) {
				drainBody(r)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, `{"error":{"type":"authentication_error","message":"bad key"}}`)
			})
			generation := h.tracker.EnsureGeneration(h.route.ID)
			h.tracker.Report(health.Report{RouteID: h.route.ID, Generation: generation, Verdict: health.VerdictOK, Source: health.SourceReal})
			code, _ := h.requestProtocol(t, model.ProtoAnthropic)
			if code != status {
				t.Fatalf("status=%d want %d", code, status)
			}
			settleRealTraffic(t, h)
			execution := h.execution(t)
			state := h.tracker.Status(h.route.ID)
			if execution.ErrorClass != model.ErrorAuthRejected || state.State != model.StateAlive || state.CooldownUntil != 0 || state.ConsecutiveFail != 0 {
				t.Fatalf("single request auth outcome became model failure: execution=%+v health=%+v", execution, state)
			}
			if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointMessages, ""); got == model.CapabilityConfigError {
				t.Fatal("single model 401/403 became config_error")
			}
		})
	}
}

func TestRealTraffic_ModelNotFoundIsRouteLocalAndKeepsStationReachable(t *testing.T) {
	h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, r *http.Request) {
		drainBody(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		_, _ = io.WriteString(w, liveMissingModel)
	})
	mn := &model.ModelName{Name: "privacy sibling", Protocol: model.ProtoAnthropic, MatchMode: model.MatchExact, Enabled: true}
	mn.Defaults()
	if err := h.store.CreateModelName(mn); err != nil {
		t.Fatal(err)
	}
	sibling := &model.Route{ModelNameID: mn.ID, UpstreamID: h.up.ID, Priority: 1, Weight: 1, Enabled: true}
	if err := h.store.CreateRoute(sibling); err != nil {
		t.Fatal(err)
	}
	settings, settingsRevision, err := h.store.GetSettingsWithRevision()
	if err != nil {
		t.Fatal(err)
	}
	settings.OKThreshold = 1
	if _, err := h.store.SaveSettingsWithRevision(settings, settingsRevision); err != nil {
		t.Fatal(err)
	}
	if err := h.manager.cfg.(interface{ Refresh() error }).Refresh(); err != nil {
		t.Fatal(err)
	}
	code, _ := h.requestProtocol(t, model.ProtoAnthropic)
	if code != 404 {
		t.Fatalf("response=%d", code)
	}
	settleRealTraffic(t, h)
	execution := h.execution(t)
	row := h.caps.Snapshot(model.RecipeScopeRoute, h.route.ID, model.EndpointMessages)
	if row.State != model.CapabilityConfigError || row.ErrorClass != model.ErrorModelNotFound || row.ExpiresAt != 0 || execution.CapabilityDisposition != model.ApplyCurrent {
		t.Fatalf("route config evidence missing: %+v", row)
	}
	if h.tracker.State(h.route.ID) == model.StateDead || h.reach.Effective(h.up.ID, h.up.NetworkRevision) != model.ReachabilityReachable {
		t.Fatalf("model_not_found health=%s reach=%s snapshot=%+v suppliedNetRev=%d disposition=%s", h.tracker.State(h.route.ID), h.reach.Effective(h.up.ID, h.up.NetworkRevision), h.reach.Snapshot(h.up.ID), h.up.NetworkRevision, execution.ReachabilityDisposition)
	}
	if got := h.caps.Effective(model.RecipeScopeRoute, sibling.ID, model.EndpointMessages, ""); got != model.CapabilityUnknown {
		t.Fatalf("sibling inherited config_error: %s", got)
	}
}

func TestRealTraffic_ModelNotFoundCodeVariantsAcrossNativeProtocol(t *testing.T) {
	for _, code := range []string{"model_not_found", "model_not_available", "invalid_model", "unknown_model"} {
		t.Run(code, func(t *testing.T) {
			h := newTrafficHTTPHarnessFor(t, model.ProtoOpenAIChat, func(w http.ResponseWriter, r *http.Request) {
				drainBody(r)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(400)
				_, _ = fmt.Fprintf(w, `{"error":{"type":"invalid_request_error","code":%q}}`, code)
			})
			status, _ := h.requestProtocol(t, model.ProtoOpenAIChat)
			if status != 400 {
				t.Fatalf("response=%d", status)
			}
			settleRealTraffic(t, h)
			if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointChatCompletions, ""); got != model.CapabilityConfigError {
				t.Fatalf("code %s capability=%s", code, got)
			}
		})
	}
}

func TestRealTraffic_ModelNotFoundWordsCannotCreateConfigurationEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		success    bool
	}{
		{"assistant prose", `{"type":"message","content":[{"type":"text","text":"model_not_found model not found"}]}`, true},
		{"error message prose", `{"error":{"type":"server_error","message":"model_not_found in prose"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, r *http.Request) {
				drainBody(r)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, tc.body)
			})
			h.request(t)
			settleRealTraffic(t, h)
			execution := h.execution(t)
			if execution.Success != tc.success || execution.ErrorClass == model.ErrorModelNotFound || h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointMessages, "") == model.CapabilityConfigError {
				t.Fatalf("arbitrary words became model code: %+v", execution)
			}
		})
	}
}

func TestRealTraffic_LateModelErrorCannotPoisonReusedRouteID(t *testing.T) {
	h := newCountTrafficHarness(t)
	late := h.beginEndpoint(model.EndpointMessages)
	oldID, oldCreatedAt := h.route.ID, h.route.CreatedAt
	if err := h.store.DeleteRouteWithRevision(context.Background(), oldID, h.route.Revision); err != nil {
		t.Fatal(err)
	}
	semantic := health.NewSemanticInvalidator(nil, nil, h.caps, nil, nil)
	semantic.InvalidateRoute(oldID)
	time.Sleep(2 * time.Millisecond)
	replacement := &model.Route{ModelNameID: h.route.ModelNameID, UpstreamID: h.up.ID, Priority: 1, Weight: 1, Enabled: true}
	if err := h.store.CreateRoute(replacement); err != nil {
		t.Fatal(err)
	}
	// AUTOINCREMENT protects ordinary creation. Simulate an imported/restored
	// reused ID explicitly in this temporary database, retaining real CAS reads.
	if _, err := h.store.DB().Exec(`DELETE FROM route_health WHERE route_id=?`, replacement.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.DB().Exec(`UPDATE route SET id=? WHERE id=?`, oldID, replacement.ID); err != nil {
		t.Fatal(err)
	}
	replacement.ID = oldID
	if replacement.ID != oldID || replacement.CreatedAt == oldCreatedAt {
		t.Fatalf("fixture must reuse the ID with a new incarnation: old=%d/%d new=%d/%d", oldID, oldCreatedAt, replacement.ID, replacement.CreatedAt)
	}
	h.route = replacement
	if err := h.manager.cfg.(interface{ Refresh() error }).Refresh(); err != nil {
		t.Fatal(err)
	}
	h.finish(t, late, 404, liveMissingModel)
	if got := h.caps.Effective(model.RecipeScopeRoute, oldID, model.EndpointMessages, ""); got != model.CapabilityUnknown {
		t.Fatalf("old incarnation poisoned reuse: %s", got)
	}
	if got := restartedRegistry(t, h.store).Effective(model.RecipeScopeRoute, oldID, model.EndpointMessages, ""); got != model.CapabilityUnknown {
		t.Fatalf("restart revived stale result: %s", got)
	}
	h.finish(t, h.beginEndpoint(model.EndpointMessages), 404, liveMissingModel)
	if got := h.caps.Effective(model.RecipeScopeRoute, oldID, model.EndpointMessages, ""); got != model.CapabilityConfigError {
		t.Fatalf("matching new incarnation could not record config_error: %s", got)
	}
}

type recordingSched struct{ n int }

func (s *recordingSched) ObserveRealSuccess(ScheduleKey, time.Time) { s.n++ }

func TestTrafficFinish_StatusAloneAndMissingOrderCannotSaveOrPiggyback(t *testing.T) {
	h := newCountTrafficHarness(t)
	recorder := &captureRecorder{}
	scheduler := &recordingSched{}
	manager := NewTrafficObserverManager(h.manager.cfg, nil, recorder, discardLogger()).WithScheduler(scheduler)
	instrument := manager.PrepareAttempt(context.Background(), health.AttemptTarget{RouteID: h.route.ID, UpstreamID: h.up.ID, Endpoint: model.EndpointMessages, Protocol: model.ProtoAnthropic}, health.AttemptRequestView{})
	instrument.Observer.TryHeaders(200, http.Header{"Content-Type": {"application/json"}}, time.Now())
	instrument.Observer.TryChunk([]byte(`{"type":"message","content":[{"type":"text","text":"not order-bound"}]}`), time.Now())
	instrument.Observer.Finish(health.AttemptFinish{})
	if instrument.Trace != nil || scheduler.n != 0 || recorder.calls != 0 || len(manager.queue) != 0 {
		t.Fatal("status/body without an allocated observation order created evidence")
	}
	// A genuine ordered status-only response also cannot yield semantic success.
	h.finish(t, h.beginEndpoint(model.EndpointMessages), 200, "")
	page, err := h.store.ListProbeExecutions(context.Background(), model.ProbeExecutionFilter{Trigger: model.TriggerRealTraffic})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].Success || strings.Contains(page.Items[0].RedactedDetail, "not order-bound") {
		t.Fatalf("status alone became success: %+v", page.Items)
	}
	if row := h.caps.Snapshot(model.RecipeScopeRoute, h.route.ID, model.EndpointMessages); row != nil && (row.LastRealOKAt != 0 || row.LastRealOKToken != "") {
		t.Fatal("status alone fabricated piggyback evidence")
	}
}
