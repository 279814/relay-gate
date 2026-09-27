package proxy

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/279814/relay-gate/internal/transform"
)

func shadowRecords(reg *transform.Registry) []transform.ExecutionRecord {
	var out []transform.ExecutionRecord
	for _, rec := range reg.ListExecutions(0) {
		if rec.Mode == "shadow" {
			out = append(out, rec)
		}
	}
	return out
}

// §15.2: a bound shadow version computes its diff on a side copy of the live
// request. The upstream still receives the published bytes, exactly one
// upstream call is made, and the recorded diff carries hashes/hit rules only.
func TestShadowBinding_LiveSideCopyDiffWithoutChangingRequest(t *testing.T) {
	var upstreamCalls atomic.Int32
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"msg_1","type":"message"}`))
	})

	reg := transform.NewRegistry(16)
	set, err := reg.CreateSet("shadow-live")
	if err != nil {
		t.Fatal(err)
	}
	pubRules := []transform.Rule{
		{Kind: transform.KindReplaceBytes, From: `"max_tokens":1`, To: `"max_tokens":2`},
	}
	if _, err := reg.UpdateDraft(set.ID, pubRules, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	// harness Route.ID=100, Endpoint.ID=1
	if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	shadowRules := []transform.Rule{
		{Kind: transform.KindReplaceBytes, From: `"max_tokens":1`, To: `"max_tokens":99`},
		{Kind: transform.KindSetHeader, Name: "X-Shadow-Key", SecretRef: "upstream_api_key"},
	}
	if _, err := reg.UpdateDraft(set.ID, shadowRules, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	_, shadowVer, err := reg.ShadowSnapshot(set.ID, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)

	body := `{"model":"claude-opus-5","max_tokens":1}`
	rec := hs.serve(hs.anthropicRequest(body))
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if n := upstreamCalls.Load(); n != 1 {
		t.Fatalf("shadow must not send extra upstream requests: calls=%d", n)
	}
	if want := `{"model":"claude-opus-5","max_tokens":2}`; string(hs.gotReq.body) != want {
		t.Fatalf("upstream must get published bytes: got %s want %s", hs.gotReq.body, want)
	}
	if hs.gotReq.headers.Get("X-Shadow-Key") != "" {
		t.Fatal("shadow header leaked into live request")
	}

	recs := shadowRecords(reg)
	if len(recs) != 1 {
		t.Fatalf("want 1 shadow record, got %d: %+v", len(recs), reg.ListExecutions(0))
	}
	sr := recs[0]
	if sr.VersionID != shadowVer.ID || sr.RouteID != 100 || sr.EndpointID != 1 || sr.Phase != "request" {
		t.Fatalf("shadow record identity: %+v", sr)
	}
	if !sr.OK {
		t.Fatalf("shadow record should be OK: %+v", sr)
	}
	if sr.InputHash != transform.HashBytes([]byte(body)) {
		t.Fatalf("shadow input must be the pre-published request: %s", sr.InputHash)
	}
	shadowOut := transform.HashBytes([]byte(`{"model":"claude-opus-5","max_tokens":99}`))
	if !strings.Contains(sr.DiffSummary, "changed=true") || !strings.Contains(sr.DiffSummary, shadowOut) {
		t.Fatalf("shadow diff missing change/output hash: %s", sr.DiffSummary)
	}
	if !strings.Contains(sr.DiffSummary, "r0:replace_bytes") {
		t.Fatalf("shadow diff missing hit rules: %s", sr.DiffSummary)
	}
	if strings.Contains(sr.DiffSummary, "sk-upstream-secret") || strings.Contains(sr.DiffSummary, "max_tokens") {
		t.Fatalf("shadow diff must not carry secrets or raw body: %s", sr.DiffSummary)
	}
}

// Shadow alone (no published pointer) leaves the passthrough bytes intact.
func TestShadowBinding_ShadowOnlyKeepsPassthrough(t *testing.T) {
	hs := newHarness(t, nil)
	reg := transform.NewRegistry(16)
	set, err := reg.CreateSet("shadow-only")
	if err != nil {
		t.Fatal(err)
	}
	rules := []transform.Rule{
		{Kind: transform.KindReplaceBytes, From: `"max_tokens":1`, To: `"max_tokens":99`},
	}
	if _, err := reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.ShadowSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)

	body := `{"model":"claude-opus-5","max_tokens":1}`
	rec := hs.serve(hs.anthropicRequest(body))
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if string(hs.gotReq.body) != body {
		t.Fatalf("passthrough changed by shadow: %s", hs.gotReq.body)
	}
	if len(shadowRecords(reg)) != 1 {
		t.Fatalf("want 1 shadow record, got %+v", reg.ListExecutions(0))
	}
}

// No shadow pointer: no shadow work and no shadow record.
func TestShadowBinding_UnboundRecordsNothing(t *testing.T) {
	hs := newHarness(t, nil)
	reg := transform.NewRegistry(16)
	hs.h.WithTransforms(reg)
	body := `{"model":"claude-opus-5","max_tokens":1}`
	if rec := hs.serve(hs.anthropicRequest(body)); rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}
	if n := len(reg.ListExecutions(0)); n != 0 {
		t.Fatalf("unbound must record nothing, got %d", n)
	}
}
