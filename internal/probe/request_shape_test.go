package probe

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

func TestSanitizeRequestShapeOmitsPrivateValuesAndCanonicalizes(t *testing.T) {
	request := func(private string, reordered bool) health.AttemptRequestView {
		body := `{"model":"private-model-` + private + `","stream":true,"messages":[{"role":"user","content":"` + private + `"}],"system":"` + private + `","metadata":{"user_id":"` + private + `"}}`
		if reordered {
			body = `{"metadata":{"user_id":"` + private + `"},"system":"` + private + `","messages":[],"stream":true,"model":"another-private-model"}`
		}
		return health.AttemptRequestView{
			Header: http.Header{
				"User-Agent":        {"claude-cli/2.1.0 (external, cli)"},
				"Content-Type":      {"application/json"},
				"Anthropic-Version": {"2023-06-01"},
				"Authorization":     {"Bearer " + private}, "Cookie": {"relay_session=" + private},
				"X-Private-Context": {private},
			}, RawQuery: "session_id=" + private + "&beta=true&api_key=" + private, Body: []byte(body),
		}
	}
	first, reason := SanitizeRequestShape(model.EndpointMessages, request("OPAQUE_PRIVATE_CONTEXT_A", false))
	if reason != "" {
		t.Fatalf("safe shape rejected: %s", reason)
	}
	second, reason := SanitizeRequestShape(model.EndpointMessages, request("OPAQUE_PRIVATE_CONTEXT_B", true))
	if reason != "" || ShapeHash(first) == "" || ShapeHash(first) != ShapeHash(second) {
		t.Fatalf("business values or JSON key order changed safe identity: %s", reason)
	}
	if first.ClientFamily != "claude-cli/2" || first.FixedRawQuery != "beta=true&session_id=%7B%7BSESSION_ID%7D%7D" {
		t.Fatalf("unexpected safe family/query: %s %s", first.ClientFamily, first.FixedRawQuery)
	}
	raw, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"OPAQUE_PRIVATE_CONTEXT", "private-model", "another-private-model", "relay_session", "X-Private-Context"} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatalf("private value survived sanitizer: %s", private)
		}
	}
	if !bytes.Contains(first.BodyShapeJSON, []byte(`"stream":true`)) || !bytes.Contains(first.BodyTemplate, []byte("{{PROBE_PROMPT}}")) {
		t.Fatal("safe flags or compact probe template lost")
	}
	view := request("OPAQUE_PRIVATE_CONTEXT_A", false)
	safe, _ := SanitizeRequestShape(model.EndpointMessages, view)
	view.Header.Set("Anthropic-Version", "mutated")
	for i := range view.Body {
		view.Body[i] = 'x'
	}
	if ShapeHash(safe) != ShapeHash(first) {
		t.Fatal("sanitizer retained mutable input")
	}
}

func TestSanitizeRequestShapeRejectsUnknownOrUnboundedInput(t *testing.T) {
	cases := []struct {
		name string
		view health.AttemptRequestView
	}{
		{"unknown business string", health.AttemptRequestView{Body: []byte(`{"model":"m","messages":[],"private_extension":"secret"}`)}},
		{"unknown query", health.AttemptRequestView{RawQuery: "tenant_context=secret", Body: []byte(`{"model":"m","messages":[]}`)}},
		{"duplicate JSON fields", health.AttemptRequestView{Body: []byte(`{"model":"m","stream":true,"stream":false,"messages":[]}`)}},
		{"invalid JSON", health.AttemptRequestView{Body: []byte(`{"model":`)}},
		{"truncated", health.AttemptRequestView{BodyTruncated: true, Body: []byte(`{"model":"m"}`)}},
		{"oversize body", health.AttemptRequestView{Body: []byte(strings.Repeat(" ", 65537))}},
		{"oversize headers", health.AttemptRequestView{Header: http.Header{"X-Private": {strings.Repeat("x", 16385)}}, Body: []byte(`{}`)}},
		{"many empty header values", health.AttemptRequestView{Header: http.Header{"X-Private": make([]string, 5000)}, Body: []byte(`{"model":"m","messages":[]}`)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shape, reason := SanitizeRequestShape(model.EndpointMessages, tc.view)
			if reason == "" || len(shape.BodyTemplate) != 0 || len(shape.SafeHeaders) != 0 || shape.ClientFamily != "" {
				t.Fatalf("unsafe input remained learnable: reason=%s", reason)
			}
		})
	}
}

func TestShapeHashCanonicalizesSafeHeaderAndJSONOrder(t *testing.T) {
	a := model.ClientRequestShape{ClientFamily: "generic", SafeHeaders: []model.HeaderTemplate{
		{Name: "Anthropic-Version", Values: []string{"2023-06-01"}}, {Name: "Content-Type", Values: []string{"application/json"}},
	}, BodyShapeJSON: []byte(`{"stream":true,"model":"string"}`), BodyTemplate: []byte(`{"a":true,"b":false}`)}
	b := model.ClientRequestShape{ClientFamily: "generic", SafeHeaders: []model.HeaderTemplate{
		{Name: "content-type", Values: []string{"application/json"}}, {Name: "anthropic-version", Values: []string{"2023-06-01"}},
	}, BodyShapeJSON: []byte(`{"model":"string","stream":true}`), BodyTemplate: []byte(`{"b":false,"a":true}`)}
	if ShapeHash(a) == "" || ShapeHash(a) != ShapeHash(b) {
		t.Fatal("safe shape hash depends on representation order")
	}
	a.FixedRawQuery = "beta=true&session_id={{SESSION_ID}}"
	b.FixedRawQuery = "session_id=%7B%7BSESSION_ID%7D%7D&beta=true"
	a.SafeHeaders = append(a.SafeHeaders, model.HeaderTemplate{Name: "Accept", Values: []string{"text/event-stream", "application/json"}})
	b.SafeHeaders = append(b.SafeHeaders, model.HeaderTemplate{Name: "accept", Values: []string{"application/json"}}, model.HeaderTemplate{Name: "Accept", Values: []string{"text/event-stream"}})
	if ShapeHash(a) != ShapeHash(b) {
		t.Fatal("safe query/header representation changed shape identity")
	}
	b.ClientFamily = "claude-cli/2"
	if ShapeHash(a) == ShapeHash(b) {
		t.Fatal("client family omitted from safe shape identity")
	}
}

func TestSanitizeRequestShapeAcceptsCurrentCapturedClientAndPreservesSafeFlags(t *testing.T) {
	shape, reason := SanitizeRequestShape(model.EndpointMessages, health.AttemptRequestView{
		Header: http.Header{
			"User-Agent":     {"claude-cli/2.1.220 (external, sdk-cli)"},
			"Anthropic-Beta": {"claude-code-20250219,thinking-token-count-2026-05-13,context-management-2025-06-27"},
			"X-App":          {"cli"}, "X-Stainless-Package-Version": {"0.70.1"},
		},
		Body: []byte(`{"model":"private-model","stream":false,"thinking":{"type":"enabled","budget_tokens":8000},"messages":[{"role":"user","content":"PRIVATE_TASK_TEXT"}]}`),
	})
	if reason != "" || shape.ClientFamily != "claude-cli/2" {
		t.Fatalf("captured client lost its learnable identity: %s %s", reason, shape.ClientFamily)
	}
	store := &captureLearnerStore{}
	if err := NewLearner(store).ObserveSuccessful(t.Context(), 7, model.EndpointMessages, shape); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(store.profile.BodyTemplate, &body); err != nil {
		t.Fatal(err)
	}
	thinking, ok := body["thinking"].(map[string]any)
	if !ok || thinking["type"] != "enabled" || thinking["budget_tokens"] != float64(1024) || body["max_tokens"] != float64(1025) || body["stream"] != false {
		t.Fatalf("safe shape was replaced by an incompatible generic probe: %s", store.profile.BodyTemplate)
	}
	if bytes.Contains(store.profile.BodyTemplate, []byte("PRIVATE_TASK_TEXT")) || bytes.Contains(store.profile.BodyTemplate, []byte("private-model")) {
		t.Fatal("safe flag replay copied private text")
	}
}

func FuzzSanitizeRequestShapeNeverRetainsPrivateText(f *testing.F) {
	f.Add([]byte("a private task"))
	f.Add([]byte("\x00\xff\"\r\n"))
	f.Add([]byte(`{"model":"private-model","stream":true,"messages":[]}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		digest := sha256.Sum256(input)
		private := "PRIVATE_TASK_" + hex.EncodeToString(digest[:])
		body, err := json.Marshal(map[string]any{"model": private, "messages": []any{map[string]any{"role": "user", "content": private}}, "metadata": map[string]any{"user_id": private}, "stream": true})
		if err != nil {
			t.Fatal(err)
		}
		shape, reason := SanitizeRequestShape(model.EndpointMessages, health.AttemptRequestView{Header: http.Header{"Authorization": {"Bearer " + private}, "X-Context": {private}}, RawQuery: "session_id=" + url.QueryEscape(private), Body: body})
		if reason != "" {
			return
		}
		encoded, err := json.Marshal(shape)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(encoded, []byte(private)) {
			t.Fatal("raw private context escaped into learned shape")
		}
		// Also let the fuzzer mutate the actual JSON grammar and nesting, rather
		// than exercising only well-formed string values in the constructed case.
		arbitrary, reason := SanitizeRequestShape(model.EndpointMessages, health.AttemptRequestView{Header: http.Header{"X-Context": {private}}, RawQuery: "session_id=" + url.QueryEscape(private), Body: input})
		if reason == "" {
			encoded, err := json.Marshal(arbitrary)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(encoded, []byte(private)) || !json.Valid(arbitrary.BodyTemplate) {
				t.Fatal("arbitrary wire input escaped the safe shape boundary")
			}
		}
	})
}
