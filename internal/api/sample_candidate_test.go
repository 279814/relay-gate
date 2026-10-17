package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probe"
)

type candidateSampleSource struct{ sample *model.Sample }

func (s candidateSampleSource) GetSample(int64) (*model.Sample, error) { return s.sample, nil }

func candidateHeadersForTest(t *testing.T, headers http.Header) (map[string]string, []string) {
	t.Helper()
	builder := probe.NewSampleCandidateBuilder(candidateSampleSource{&model.Sample{Endpoint: "/v1/messages", InMethod: "POST", InHeaders: headers, InBody: []byte(`{"model":"x","messages":[],"stream":true}`)}})
	candidate, err := builder.BuildSampleCandidate(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]string{}
	for _, header := range candidate.Version.Headers {
		result[header.Name] = strings.Join(header.Values, ",")
	}
	return result, candidate.Skipped
}

func TestSampleRecipeCandidateUsesOnlySanitizedProtocolShape(t *testing.T) {
	s, h := newTestServer(t)
	smp := &model.Sample{Endpoint: "/v1/messages", InMethod: "POST", InPath: "/v1/messages", InQuery: "beta=true&api_key=sample-query-private",
		InHeaders: http.Header{"Content-Type": {"application/json"}, "User-Agent": {"claude-cli/2.1.220"}, "Authorization": {"Bearer sample-header-private"}, "Cookie": {"sample-cookie-private"}, "X-Custom": {"sample-opaque-private"}},
		InBody:    []byte(`{"model":"sample-model-private","messages":[{"role":"user","content":"sample-business-private"}],"stream":false,"max_tokens":500}`)}
	if err := s.st.InsertSample(smp); err != nil {
		t.Fatal(err)
	}
	response := do(t, h, "GET", fmt.Sprintf("/admin/api/samples/%d/probe-headers", smp.ID), "", true)
	if response.Code != http.StatusOK {
		t.Fatalf("candidate=%d %s", response.Code, response.Body.String())
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body["candidate"]) == 0 || body["defaults"] != nil {
		t.Fatalf("not a unified safe candidate: %s", response.Body.String())
	}
	for _, private := range []string{"sample-query-private", "sample-header-private", "sample-cookie-private", "sample-opaque-private", "sample-model-private", "sample-business-private"} {
		if strings.Contains(response.Body.String(), private) {
			t.Errorf("candidate retained %q", private)
		}
	}
	if !strings.Contains(response.Body.String(), "UPSTREAM_MODEL") || !strings.Contains(response.Body.String(), "PROBE_PROMPT") {
		t.Fatalf("candidate lost safe template: %s", response.Body.String())
	}
	var candidates int
	if err := s.st.DB().QueryRow(`SELECT COUNT(*) FROM probe_recipe`).Scan(&candidates); err != nil || candidates != 0 {
		t.Fatalf("export must not persist/publish: rows=%d err=%v", candidates, err)
	}
}

func TestSampleRecipeCandidateRejectsTruncatedOrUnsafeShapes(t *testing.T) {
	for _, name := range []string{"truncated", "query", "protocol_value", "method", "encoding"} {
		t.Run(name, func(t *testing.T) {
			s, h := newTestServer(t)
			smp := &model.Sample{Endpoint: "/v1/messages", InMethod: "POST", InPath: "/v1/messages", InHeaders: http.Header{"Content-Type": {"application/json"}}, InBody: []byte(`{"model":"x","messages":[],"stream":true}`)}
			switch name {
			case "truncated":
				smp.Truncated = model.TruncInBody
			case "query":
				smp.InQuery = "opaque=sample-query-private"
			case "protocol_value":
				smp.InHeaders.Set("X-App", "sample-app-private")
			case "method":
				smp.InMethod = "PATCH"
			case "encoding":
				smp.InHeaders.Set("Content-Encoding", "gzip")
			}
			if err := s.st.InsertSample(smp); err != nil {
				t.Fatal(err)
			}
			response := do(t, h, "GET", fmt.Sprintf("/admin/api/samples/%d/probe-headers", smp.ID), "", true)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("unsafe sample=%d %s", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "sample-") {
				t.Fatalf("validation reflected private value: %s", response.Body.String())
			}
		})
	}
}
