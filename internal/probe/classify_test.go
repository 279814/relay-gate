package probe

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/279814/relay-gate/internal/model"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Thin test driver: all wire interpretation and decisions belong to the
// production Decoder/Classifier. No keyword heuristic or synthetic HTTP status.
func classifyNativeFixture(t *testing.T, status int, header http.Header, body string) Decision {
	t.Helper()
	classifier := NewResponseClassifier(ObserveProbe, model.EndpointMessages, status, header, time.Unix(1700000000, 0))
	decoder, err := NewDecoder(DecoderSpec{Endpoint: model.EndpointMessages, Protocol: model.ProtoAnthropic}, WireJSON, 1<<20, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	events, readErr := decoder.Feed([]byte(body))
	for _, event := range events {
		if decision, done := classifier.Observe(event); done {
			return decision
		}
	}
	if readErr == nil {
		events, readErr = decoder.Finish()
		for _, event := range events {
			if decision, done := classifier.Observe(event); done {
				return decision
			}
		}
	}
	return classifier.Finish(readErr, nil)
}

func TestNativeHTTPClassificationUsesStructuredEvidence(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		want    model.ErrorClass
		success bool
	}{
		{"200 semantic body", 200, `{"content":[{"type":"text","text":"2"}]}`, model.ErrorNone, true},
		{"200 arbitrary object", 200, `{"ok":true}`, model.ErrorFakeAlive, false},
		{"401 auth", 401, `{"error":"invalid api key"}`, model.ErrorAuthRejected, false},
		{"403 auth", 403, `forbidden`, model.ErrorAuthRejected, false},
		{"400 model word only", 400, `{"error":{"message":"model_not_found"}}`, model.ErrorTransient, false},
		{"404 model words", 404, `{"error":"no such model: opus-9"}`, model.ErrorUnsupported, false},
		{"400 invalid model words", 400, `{"error":"invalid model specified"}`, model.ErrorTransient, false},
		{"400 explicit model code", 400, `{"error":{"code":"model_not_found"}}`, model.ErrorModelNotFound, false},
		{"429", 429, `{"error":"slow down"}`, model.ErrorRateLimited, false},
		{"529 explicit HTTP wins", 529, `{"type":"overloaded_error"}`, model.ErrorTransient, false},
		{"503 rate words", 503, `{"error":"rate limit exceeded"}`, model.ErrorTransient, false},
		{"400 quota words", 400, `{"error":"quota exhausted"}`, model.ErrorTransient, false},
		{"500", 500, `internal error`, model.ErrorTransient, false},
		{"502", 502, `bad gateway`, model.ErrorTransient, false},
		{"503", 503, `unavailable`, model.ErrorTransient, false},
		{"unexpected400", 400, `{"error":"missing field foo"}`, model.ErrorTransient, false},
		{"302", 302, `{"redirect":true}`, model.ErrorTransient, false},
		{"301", 301, ``, model.ErrorTransient, false},
		{"307", 307, ``, model.ErrorTransient, false},
		{"308", 308, ``, model.ErrorTransient, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decision := classifyNativeFixture(t, tc.status, nil, tc.body)
			if decision.ErrorClass != tc.want || decision.Success != tc.success || decision.StatusCode != tc.status || !decision.Reachable {
				t.Fatalf("wrong HTTP evidence: %+v", decision)
			}
		})
	}
}

func TestNativeHTTPAndStreamErrorPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   model.ErrorClass
	}{
		{"500 overload remains HTTP transient", 500, `{"error":{"type":"overloaded_error"}}`, model.ErrorTransient},
		{"200 overload is protocol rate-limit", 200, `{"error":{"type":"overloaded_error"}}`, model.ErrorRateLimited},
		{"200 numeric401 is not HTTP status", 200, `{"error":{"code":401}}`, model.ErrorTransient},
		{"200 authentication type", 200, `{"error":{"type":"authentication_error"}}`, model.ErrorAuthRejected},
		{"400 shape with model words", 400, `{"error":{"type":"invalid_request_error","message":"model not found"}}`, model.ErrorShapeRejected},
		{"400 explicit model code", 400, `{"error":{"type":"invalid_request_error","code":"model_not_found"}}`, model.ErrorModelNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if decision := classifyNativeFixture(t, tc.status, nil, tc.body); decision.ErrorClass != tc.want {
				t.Fatalf("wrong structured precedence: %+v", decision)
			}
		})
	}
}

func TestNativeClassifierRetryAfterUsesInjectedHeaderTime(t *testing.T) {
	now := time.Date(2026, 10, 18, 1, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, value string
		want        int64
	}{
		{"seconds", "120", now.Add(120 * time.Second).UnixMilli()},
		{"missing", "", 0}, {"zero", "0", now.UnixMilli()}, {"negative", "-5", 0},
		{"future HTTP date", now.Add(5 * time.Minute).Format(http.TimeFormat), now.Add(5 * time.Minute).UnixMilli()},
		{"past date", now.Add(-time.Hour).Format(http.TimeFormat), now.UnixMilli()},
		{"oversized ignored", "999999", 0}, {"overflow ignored", "999999999999", 0}, {"int64 max ignored", "9223372036854775807", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := http.Header{"Retry-After": []string{tc.value}}
			decision := NewResponseClassifier(ObserveProbe, model.EndpointMessages, 429, header, now).Finish(nil, nil)
			if decision.RetryAfterUntilMS != tc.want {
				t.Fatalf("Retry-After=%q got %d want %d", tc.value, decision.RetryAfterUntilMS, tc.want)
			}
		})
	}
}

func TestNativeClassifierCarriesRetryAfterThrough(t *testing.T) {
	header := http.Header{"Retry-After": []string{"300"}}
	now := time.Unix(1700000000, 0)
	decision := NewResponseClassifier(ObserveProbe, model.EndpointMessages, 429, header, now).Finish(nil, nil)
	if decision.ErrorClass != model.ErrorRateLimited || decision.RetryAfterUntilMS != now.Add(300*time.Second).UnixMilli() {
		t.Fatalf("rate-limit retry time lost: %+v", decision)
	}
}

func TestNativeClassifierTransportAndCancellationStayDistinct(t *testing.T) {
	for _, tc := range []struct {
		name           string
		status         int
		readErr, cause error
		want           model.ErrorClass
	}{
		{"no response is not proof of life", 0, nil, nil, model.ErrorUnreachable},
		{"client canceled", 0, context.Canceled, ErrClientCanceled, model.ErrorIgnored},
		{"service paused", 200, context.Canceled, ErrServicePaused, model.ErrorIgnored},
		{"shutdown", 200, context.Canceled, ErrServiceShutdown, model.ErrorIgnored},
		{"connect failed", 0, ErrProbeTransportFailed, nil, model.ErrorUnreachable},
		{"semantic timeout", 200, ErrProbeSemanticTimeout, nil, model.ErrorTransient},
		{"idle/total read timeout", 200, context.DeadlineExceeded, nil, model.ErrorTransient},
		{"unexpected EOF", 200, io.ErrUnexpectedEOF, nil, model.ErrorTransient},
		{"canceled words are not cause", 200, errors.New("client canceled the request"), nil, model.ErrorTransient},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decision := NewResponseClassifier(ObserveProbe, model.EndpointMessages, tc.status, nil, time.Now()).Finish(tc.readErr, tc.cause)
			if decision.ErrorClass != tc.want || decision.Reachable != (tc.status > 0) {
				t.Fatalf("wrong cancellation/transport scope: %+v", decision)
			}
		})
	}
}

func TestNativeProbeTimeoutsCannotBecomeIgnoredOrFakeAlive(t *testing.T) {
	for _, failure := range []error{ErrProbeSemanticTimeout, context.DeadlineExceeded, io.ErrUnexpectedEOF} {
		decision := NewResponseClassifier(ObserveProbe, model.EndpointMessages, 200, nil, time.Now()).Finish(failure, nil)
		if decision.Success || decision.ErrorClass != model.ErrorTransient {
			t.Fatalf("upstream timeout/break was ignored or labeled fake-alive: %+v", decision)
		}
	}
}

func TestNativeStructuredDiagnosticsAreBoundedAndNeverEchoMessage(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{"error": map[string]any{"type": "api_error", "code": strings.Repeat("x", maxRedactedDetail*2), "message": "line one\n\n   private body line two"}})
	decision := classifyNativeFixture(t, 200, nil, string(payload))
	if len(decision.RedactedDetail) > maxRedactedDetail || strings.Contains(decision.RedactedDetail, "private body") || strings.ContainsAny(decision.RedactedDetail, "\r\n") {
		t.Fatalf("unbounded/raw private diagnostic: %q", decision.RedactedDetail)
	}
	if empty := classifyNativeFixture(t, 503, nil, ""); empty.StatusCode != 503 || empty.ErrorClass != model.ErrorTransient || strings.Contains(empty.RedactedDetail, "line one") {
		t.Fatalf("empty error body lost status: %+v", empty)
	}
}
