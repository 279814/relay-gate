package proxy

import (
	"net/http"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/transform"
)

// §6.5 / §15.7: request transform fail_closed is route-local — skip the Route
// without burning retry_max_attempts, then try the next candidate.
func TestRequestTransform_FailClosedSkipsToNextRoute(t *testing.T) {
	hs := newMultiHarness(t,
		respondOK(`{"id":"should-not","type":"message"}`),
		respondOK(`{"id":"msg_ok","type":"message"}`),
	)
	// One network attempt budget: if fail_closed incorrectly burned it,
	// the second Route would never be tried.
	hs.cfg.settings.RetryMaxAttempts = 1

	reg := transform.NewRegistry(8)
	set, err := reg.CreateSet("bad-req")
	if err != nil {
		t.Fatal(err)
	}
	rules := []transform.Rule{
		{Kind: transform.KindSetJSONPointer, Name: "/missing", Value: `"x"`},
	}
	if _, err := reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	// Bind only the first Route (id 100); endpoint id matches testEndpoints.
	if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)

	rec := hs.serve(hs.req())
	if rec.Code != 200 {
		t.Fatalf("want 200 via second Route, got %d body=%s", rec.Code, rec.Body.String())
	}
	hs.assertHits(t, 0, 1)
	if !strings.Contains(rec.Body.String(), "msg_ok") {
		t.Fatalf("body=%s", rec.Body.String())
	}
}

func TestRequestTransform_FailClosedAloneStill502(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream must not be contacted on fail_closed")
	})
	reg := transform.NewRegistry(4)
	set, err := reg.CreateSet("solo-bad")
	if err != nil {
		t.Fatal(err)
	}
	rules := []transform.Rule{
		{Kind: transform.KindSetJSONPointer, Name: "/missing", Value: `"x"`},
	}
	if _, err := reg.UpdateDraft(set.ID, rules, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","max_tokens":1}`))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("want 502, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "请求转换失败") {
		t.Fatalf("body=%s", rec.Body.String())
	}
}
