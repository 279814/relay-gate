package proxy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/transform"
)

// docs/01 §5.4 / §16.3: credentials are unconditionally redacted in samples.
// When request transform secret_ref writes the upstream key into the outbound
// body or a non-auth header, redaction must run on those post-transform bytes
// with the key in the redact set — envelope encrypt alone is not enough,
// because admin sample view decrypts back to the stored plaintext.
func TestSample_RedactsTransformSecretRefInBodyAndCustomHeader(t *testing.T) {
	const upKey = "sk-distinctive-xform-secret-ref-9f3a2b"

	hs := newHarness(t, nil)
	hs.cfg.snap.Upstreams[10].APIKey = upKey

	reg := transform.NewRegistry(8)
	set, err := reg.CreateSet("secret-ref-sample")
	if err != nil {
		t.Fatal(err)
	}
	rules := []transform.Rule{
		{Kind: transform.KindSetHeader, Name: "X-Site-Token", SecretRef: "upstream_api_key"},
		{Kind: transform.KindSetJSONPointer, Name: "/token", SecretRef: "upstream_api_key"},
	}
	if _, err := reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","token":"old","max_tokens":1}`))
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	// Upstream must still receive the raw key (redaction is sample-only).
	if got := hs.gotReq.headers.Get("X-Site-Token"); got != upKey {
		t.Fatalf("upstream header X-Site-Token=%q, want raw key", got)
	}
	if !bytes.Contains(hs.gotReq.body, []byte(upKey)) {
		t.Fatalf("upstream body missing injected key: %s", hs.gotReq.body)
	}

	smp := hs.sink.one(t)
	blob, err := json.Marshal(smp)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte(upKey)) {
		t.Fatalf("stored sample (admin-decrypt plaintext) still contains injected key")
	}
	if strings.Contains(smp.OutHeaders.Get("X-Site-Token"), upKey) {
		t.Fatalf("OutHeaders still has raw key: %q", smp.OutHeaders.Get("X-Site-Token"))
	}
	if bytes.Contains(smp.OutBody, []byte(upKey)) {
		t.Fatalf("OutBody still has raw key: %s", smp.OutBody)
	}
	// Structure must remain useful for diagnosis.
	if smp.OutHeaders.Get("X-Site-Token") == "" {
		t.Fatal("X-Site-Token header name should remain after redaction")
	}
	if !bytes.Contains(smp.OutBody, []byte(`"model"`)) {
		t.Fatalf("OutBody lost non-secret content: %s", smp.OutBody)
	}
}
