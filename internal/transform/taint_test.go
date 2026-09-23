package transform

import (
	"net/http"
	"strings"
	"testing"
)

func TestSecretRef_InjectsAndTaintsDiagnostics(t *testing.T) {
	const secret = "sk-live-super-secret-value"
	c, err := Compile(Version{
		Rules: []Rule{
			{Kind: KindSetHeader, Name: "X-Custom-Key", SecretRef: "upstream_api_key"},
			{Kind: KindSetJSONPointer, Name: "/token", SecretRef: "upstream_api_key"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	secrets := SecretMap{"upstream_api_key": []byte(secret)}
	out := c.ApplyRequestSecrets(RequestInput{
		Header: http.Header{},
		Body:   []byte(`{"model":"m","token":"old"}`),
	}, secrets)
	if out.Err != nil {
		t.Fatal(out.Err)
	}
	if got := out.Header.Get("X-Custom-Key"); got != secret {
		t.Fatalf("header=%q", got)
	}
	if !strings.Contains(string(out.Body), secret) {
		t.Fatalf("body missing secret: %s", out.Body)
	}
	// Force an error path that would otherwise embed the secret if we sprintf'd values.
	bad := c.ApplyRequestSecrets(RequestInput{
		Header: http.Header{},
		Body:   []byte(`{"model":"m"}`),
	}, nil)
	if bad.Err == nil {
		t.Fatal("expected unresolved secret error")
	}
	if strings.Contains(bad.Err.Error(), secret) {
		t.Fatalf("error leaked secret: %v", bad.Err)
	}
	sum := c.ShadowDiffSecrets("request", RequestInput{
		Header: http.Header{},
		Body:   []byte(`{"model":"m","token":"old"}`),
	}, ResponseInput{}, secrets)
	if strings.Contains(sum, secret) {
		t.Fatalf("shadow summary leaked secret: %s", sum)
	}
}

func TestSecretPlaceholder_InBodyTemplate(t *testing.T) {
	c, err := Compile(Version{
		Rules: []Rule{{
			Kind:  KindBodyTemplate,
			Value: `{"model":"m","auth":"{{SECRET:probe_token}}"}`,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const secret = "tok-abcdef-should-redact"
	out := c.ApplyRequestSecrets(RequestInput{
		Header: http.Header{},
		Body:   []byte(`{"model":"m"}`),
	}, SecretMap{"probe_token": []byte(secret)})
	if out.Err != nil {
		t.Fatal(out.Err)
	}
	if !strings.Contains(string(out.Body), secret) {
		t.Fatalf("body=%s", out.Body)
	}
	fakeErr := out.Taint.RedactErr(nil)
	if fakeErr != nil {
		t.Fatal(fakeErr)
	}
	leaked := out.Taint.Redact("seen " + secret + " in log")
	if strings.Contains(leaked, secret) || !strings.Contains(leaked, "[REDACTED]") {
		t.Fatalf("redact failed: %q", leaked)
	}
}

func TestSecretRef_RejectedOnReplaceBytes(t *testing.T) {
	_, err := Compile(Version{Rules: []Rule{
		{Kind: KindReplaceBytes, From: "a", To: "b", SecretRef: "x"},
	}})
	if err == nil || !strings.Contains(err.Error(), "secret_ref not allowed") {
		t.Fatalf("err=%v", err)
	}
}

func TestApplyResponse_SecretRefDoesNotEchoUpstreamKey(t *testing.T) {
	// Response set_header must not place the distinctive upstream key on the
	// client response, even when ApplyResponseSecrets is given a SecretMap
	// (shadow / future wiring). Protected Authorization is already compile-rejected;
	// this covers copying the key into a custom header.
	const secret = "sk-distinctive-upstream-key-9f3a2b"
	c, err := Compile(Version{
		ResFailPolicy: FailOpen,
		Rules: []Rule{
			{Kind: KindSetHeader, Name: "X-Echo-Key", SecretRef: "upstream_api_key"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	in := ResponseInput{
		Status: 200,
		Header: http.Header{"Content-Type": []string{"application/json"}, "X-Keep": []string{"1"}},
		Body:   []byte(`{"ok":true}`),
	}
	out := c.ApplyResponseSecrets(in, SecretMap{"upstream_api_key": []byte(secret)})
	if out.Err == nil {
		t.Fatal("expected response secret_ref to be rejected")
	}
	if !strings.Contains(out.Err.Error(), "secret_ref not allowed on response") {
		t.Fatalf("err=%v", out.Err)
	}
	if strings.Contains(out.Err.Error(), secret) {
		t.Fatalf("error leaked secret: %v", out.Err)
	}
	for name, vs := range out.Header {
		for _, v := range vs {
			if strings.Contains(v, secret) {
				t.Fatalf("response header %s contains upstream key: %q", name, v)
			}
		}
	}
	if out.Header.Get("X-Echo-Key") != "" {
		t.Fatalf("X-Echo-Key should be absent, got %q", out.Header.Get("X-Echo-Key"))
	}
	if out.Header.Get("X-Keep") != "1" {
		t.Fatalf("fail_open should restore original headers: %v", out.Header)
	}
}

func TestRecordExecution_StripsSecretPlaceholders(t *testing.T) {
	reg := NewRegistry(10)
	rec := reg.RecordExecution(ExecutionRecord{
		DiffSummary: `tried {{SECRET:upstream_api_key}}`,
		Error:       `fail {{SECRET:upstream_api_key}}`,
		OK:          false,
	})
	if strings.Contains(rec.DiffSummary, "upstream_api_key") || strings.Contains(rec.Error, "upstream_api_key") {
		t.Fatalf("placeholder name left in record: %+v", rec)
	}
	if !strings.Contains(rec.DiffSummary, "[REDACTED]") {
		t.Fatalf("expected redaction marker: %q", rec.DiffSummary)
	}
}
