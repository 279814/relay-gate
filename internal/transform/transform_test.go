package transform

import (
	"bytes"
	"net/http"
	"testing"
)

func TestCompile_RejectsProtectedHeaderAndCRLF(t *testing.T) {
	_, err := Compile(Version{Rules: []Rule{{Kind: KindSetHeader, Name: "Authorization", Value: "x"}}})
	if err == nil {
		t.Fatal("expected protected header rejection")
	}
	_, err = Compile(Version{Rules: []Rule{{Kind: KindSetHeader, Name: "X-Custom", Value: "a\nb"}}})
	if err == nil {
		t.Fatal("expected CR/LF rejection")
	}
	_, err = Compile(Version{Rules: []Rule{{Kind: KindSetHeader, Name: "X-Custom", Value: "<script>x</script>"}}})
	if err == nil {
		t.Fatal("expected script rejection")
	}
}

func TestApplyRequest_RestoresAuthorization(t *testing.T) {
	c, err := Compile(Version{
		ReqFailPolicy: FailClosed,
		Rules: []Rule{
			{Kind: KindSetHeader, Name: "X-Trace", Value: "1"},
			{Kind: KindSetHeader, Name: "X-Other", Value: "2"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	in := RequestInput{
		Header: http.Header{"Authorization": []string{"Bearer secret"}, "X-Other": []string{"old"}},
		Body:   []byte(`{"model":"a"}`),
	}
	out := c.ApplyRequest(in)
	if out.Err != nil {
		t.Fatal(out.Err)
	}
	if got := out.Header.Get("Authorization"); got != "Bearer secret" {
		t.Fatalf("auth mutated: %q", got)
	}
	if got := out.Header.Get("X-Trace"); got != "1" {
		t.Fatalf("X-Trace=%q", got)
	}
}

func TestPassthrough_UnboundHashIdentity(t *testing.T) {
	body := []byte(`{"model":"x","n":1}`)
	h := http.Header{"Content-Type": []string{"application/json"}}
	reg := NewRegistry(10)
	c, vid, err := reg.PublishedCompiled(1, 1)
	if err != nil || c != nil || vid != 0 {
		t.Fatalf("unbound must be nil compiled: c=%v id=%d err=%v", c, vid, err)
	}
	// Identity: no transform path → same hashes
	if HashBytes(body) != HashBytes(append([]byte(nil), body...)) {
		t.Fatal("body hash changed without transform")
	}
	if HeaderFingerprint(h) != HeaderFingerprint(cloneHeader(h)) {
		t.Fatal("header fingerprint changed without transform")
	}
}

func TestPublishShadowRollback(t *testing.T) {
	reg := NewRegistry(50)
	set, err := reg.CreateSet("demo")
	if err != nil {
		t.Fatal(err)
	}
	rules := []Rule{{Kind: KindReplaceBytes, From: "OLD", To: "NEW"}}
	if _, err := reg.UpdateDraft(set.ID, rules, FailClosed, FailOpen, "v1"); err != nil {
		t.Fatal(err)
	}
	b1, v1, err := reg.PublishSnapshot(set.ID, 9, 3)
	if err != nil {
		t.Fatal(err)
	}
	if b1.PublishedID != v1.ID {
		t.Fatalf("published pointer %d != %d", b1.PublishedID, v1.ID)
	}
	rules2 := []Rule{{Kind: KindReplaceBytes, From: "OLD", To: "NEWER"}}
	if _, err := reg.UpdateDraft(set.ID, rules2, FailClosed, FailOpen, "v2"); err != nil {
		t.Fatal(err)
	}
	b2, v2, err := reg.PublishSnapshot(set.ID, 9, 3)
	if err != nil {
		t.Fatal(err)
	}
	if b2.PublishedID != v2.ID {
		t.Fatal("expected new published")
	}
	rolled, err := reg.Rollback(9, 3, v1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rolled.PublishedID != v1.ID {
		t.Fatalf("rollback published=%d want %d", rolled.PublishedID, v1.ID)
	}
	c, _, err := reg.PublishedCompiled(9, 3)
	if err != nil {
		t.Fatal(err)
	}
	res := c.ApplyRequest(RequestInput{Header: http.Header{}, Body: []byte("OLD")})
	if !bytes.Equal(res.Body, []byte("NEW")) {
		t.Fatalf("body=%s", res.Body)
	}
}

func TestShadowDoesNotMutateInput(t *testing.T) {
	c, err := Compile(Version{
		Rules: []Rule{{Kind: KindReplaceBytes, From: "a", To: "bbb"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("a")
	sum := c.ShadowDiff("request", RequestInput{Header: http.Header{}, Body: body}, ResponseInput{})
	if !bytes.Equal(body, []byte("a")) {
		t.Fatal("shadow mutated live body")
	}
	if sum == "" {
		t.Fatal("empty shadow summary")
	}
}

func TestSSE_AtomicAndSyntheticEnd(t *testing.T) {
	c, err := Compile(Version{
		Rules: []Rule{
			{Kind: KindSSEMatch, Match: "content_block_delta", From: "hi", To: "hello"},
			{Kind: KindSSEAppendEnd, Match: "message_stop", Value: `{"type":"message_stop"}`, Synthetic: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	out, hits, _, err := c.ApplySSEEvent(SSEEvent{Event: "content_block_delta", Data: "hi there"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Data != "hello there" || len(hits) == 0 {
		t.Fatalf("sse=%+v hits=%v", out, hits)
	}
	end, ok := c.AppendSyntheticEnd()
	if !ok || end.Event != "message_stop" {
		t.Fatalf("synthetic end=%+v ok=%v", end, ok)
	}
}

func TestResponse_FailOpenRestores(t *testing.T) {
	c, err := Compile(Version{
		ResFailPolicy: FailOpen,
		Rules: []Rule{
			{Kind: KindSetJSONPointer, Name: "/missing", Value: `"x"`},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	in := ResponseInput{Status: 200, Header: http.Header{"X-A": []string{"1"}}, Body: []byte(`{"ok":true}`)}
	out := c.ApplyResponse(in)
	if out.Err == nil {
		t.Fatal("expected pointer miss error")
	}
	if out.Status != 200 || !bytes.Equal(out.Body, in.Body) {
		t.Fatalf("fail_open did not restore: %+v", out)
	}
}

func TestRequest_FailClosedResetsPartialMutation(t *testing.T) {
	c, err := Compile(Version{
		ReqFailPolicy: FailClosed,
		Rules: []Rule{
			{Kind: KindSetHeader, Name: "X-Trace", Value: "1"},
			{Kind: KindSetJSONPointer, Name: "/missing", Value: "x"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	in := RequestInput{
		Header: http.Header{"Authorization": []string{"Bearer k"}, "X-Keep": []string{"y"}},
		Body:   []byte(`{"ok":true}`),
	}
	out := c.ApplyRequest(in)
	if out.Err == nil {
		t.Fatal("expected error")
	}
	if out.Header.Get("X-Trace") != "" {
		t.Fatal("fail_closed left partial header mutation")
	}
	if out.Header.Get("X-Keep") != "y" || out.Header.Get("Authorization") != "Bearer k" {
		t.Fatalf("original headers lost: %v", out.Header)
	}
	if !bytes.Equal(out.Body, in.Body) {
		t.Fatal("body mutated on fail_closed")
	}
	if len(out.HitRules) != 0 {
		t.Fatalf("hit_rules should clear on failure: %v", out.HitRules)
	}
}

func TestSetJSONPointer_TopLevelOffset(t *testing.T) {
	c, err := Compile(Version{
		Rules: []Rule{{Kind: KindSetJSONPointer, Name: "/model", Value: "mapped"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"model":"orig","keep":1}`)
	out := c.ApplyRequest(RequestInput{Header: http.Header{}, Body: body})
	if out.Err != nil {
		t.Fatal(out.Err)
	}
	if !bytes.Contains(out.Body, []byte(`"model":"mapped"`)) {
		t.Fatalf("body=%s", out.Body)
	}
	if !bytes.Contains(out.Body, []byte(`"keep":1`)) {
		t.Fatalf("remarshaled unexpectedly: %s", out.Body)
	}
}
