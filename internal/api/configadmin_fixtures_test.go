package api

import (
	"encoding/json"
	"testing"
)

// Fixture clients choose their version explicitly. This helper never reads the
// Store or GETs a newer version, so stale-page requests remain stale.
func withExpectedRevision(t *testing.T, body string, revision int64) string {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal([]byte(body), &value); err != nil {
		t.Fatal(err)
	}
	value["expected_revision"] = revision
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// Existing valid-create fixtures act as clients that explicitly send all five
// endpoint configurations. The HTTP handler performs no inference or repair.
func upstreamFixture(t *testing.T, body string) string {
	t.Helper()
	var value map[string]any
	if json.Unmarshal([]byte(body), &value) != nil {
		return body
	}
	if _, exists := value["initial_endpoints"]; exists {
		return body
	}
	endpoints := make([]map[string]any, 0, 5)
	for _, kind := range []string{"models", "messages", "responses", "chat_completions", "count_tokens"} {
		endpoints = append(endpoints, map[string]any{"endpoint": kind, "auth_profile": map[string]any{"mode": "header_bearer", "secret_ref": "upstream_api_key"}})
	}
	value["initial_endpoints"] = endpoints
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
