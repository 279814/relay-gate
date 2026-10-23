package transform

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestShadowHashesOmitEncodedKnownCredentials(t *testing.T) {
	const secret = "fixture-shadow-Secret/+Value?=9"
	body := []byte(`{"token":"` + url.QueryEscape(secret) + `"}`)
	c, err := Compile(Version{Rules: []Rule{{Kind: KindReplaceBytes, From: "public", To: "other"}}})
	if err != nil {
		t.Fatal(err)
	}
	summary := c.ShadowDiffSecrets("request", RequestInput{Header: http.Header{}, Body: body}, ResponseInput{}, SecretMap{"upstream_api_key": []byte(secret)})
	if strings.Contains(summary, HashBytes(body)) || !strings.Contains(summary, "secret_taint") {
		t.Fatalf("shadow hashed encoded known credential: %s", summary)
	}
	s := c.NewSSEShadow().WithSensitiveValues([]string{secret})
	s.Event(SSEEvent{Event: "message", Data: string(body), Raw: append([]byte("data: "), body...)})
	if s.InputHash() != "" || !strings.Contains(s.Summary(), "secret_taint") {
		t.Fatalf("SSE shadow hashed encoded known credential: %s", s.Summary())
	}
}
