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
