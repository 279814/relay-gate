package proxy

import (
	"net/http"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/transform"
)

func TestPublishedBindingApplyAndUnboundSkip(t *testing.T) {
	reg := transform.NewRegistry(10)
	set, err := reg.CreateSet("t")
	if err != nil {
		t.Fatal(err)
	}
	rules := []transform.Rule{
		{Kind: transform.KindSetHeader, Name: "X-Demo", Value: "yes"},
		{Kind: transform.KindReplaceBytes, From: `"model":"client"`, To: `"model":"upstream"`},
	}
	if _, err := reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, 1, 7); err != nil {
		t.Fatal(err)
	}

	compiled, _, err := reg.PublishedCompiled(1, 7)
	if err != nil || compiled == nil {
		t.Fatalf("compiled=%v err=%v", compiled, err)
	}
	inHdr := http.Header{"Authorization": []string{"Bearer secret"}}
	inBody := []byte(`{"model":"client"}`)
	out := compiled.ApplyRequest(transform.RequestInput{Header: inHdr, Body: inBody})
	if out.Err != nil {
		t.Fatal(out.Err)
	}
	if out.Header.Get("X-Demo") != "yes" {
		t.Fatalf("header=%q", out.Header.Get("X-Demo"))
	}
	if out.Header.Get("Authorization") != "Bearer secret" {
		t.Fatalf("auth mutated: %q", out.Header.Get("Authorization"))
	}
	if !strings.Contains(string(out.Body), `"model":"upstream"`) {
		t.Fatalf("body=%s", out.Body)
	}

	cNil, _, err := reg.PublishedCompiled(1, 8)
	if err != nil || cNil != nil {
		t.Fatalf("unbound must skip: %v %v", cNil, err)
	}
}

// Delete + recreate can reuse a SQLite route rowid. After the delete path
// removes the binding, a request against the same numeric route+endpoint id
// must forward the body unchanged (passthrough).
func TestRequestTransform_ReusedRouteIDPassthroughAfterDetach(t *testing.T) {
	hs := newHarness(t, nil)
	reg := transform.NewRegistry(8)
	set, err := reg.CreateSet("reuse-traffic")
	if err != nil {
		t.Fatal(err)
	}
	rules := []transform.Rule{
		{Kind: transform.KindReplaceBytes, From: `"model":"claude-opus-5"`, To: `"model":"rewritten"`},
	}
	if _, err := reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	// harness Route.ID=100, Endpoint.ID=1
	if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)

	body := `{"model":"claude-opus-5","max_tokens":1}`
	rec := hs.serve(hs.anthropicRequest(body))
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(string(hs.gotReq.body), `"model":"rewritten"`) {
		t.Fatalf("setup: transform did not apply, upstream body=%s", hs.gotReq.body)
	}

	// Simulate Route delete detach, then the same numeric id reincarnated in cfg.
	if err := reg.RemoveBindingsForRoute(100); err != nil {
		t.Fatal(err)
	}
	hs.gotReq = &capturedRequest{}
	rec = hs.serve(hs.anthropicRequest(body))
	if rec.Code != 200 {
		t.Fatalf("after detach status=%d body=%s", rec.Code, rec.Body.String())
	}
	if string(hs.gotReq.body) != body {
		t.Fatalf("reused id must passthrough unchanged: got %s want %s", hs.gotReq.body, body)
	}
}
