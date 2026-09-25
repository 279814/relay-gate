package transform

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
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
	_, err = Compile(Version{Rules: []Rule{{Kind: KindSetHeader, Name: "X-Custom\r\nX-Injected", Value: "y"}}})
	if err == nil {
		t.Fatal("expected header name CR/LF rejection")
	}
	_, err = Compile(Version{Rules: []Rule{{Kind: KindSetHeader, Name: "X-Custom", Value: "a\x00b"}}})
	if err == nil {
		t.Fatal("expected NUL rejection")
	}
	_, err = Compile(Version{Rules: []Rule{{Kind: KindSetHeader, Name: "X-Custom", Value: "<script>x</script>"}}})
	if err == nil {
		t.Fatal("expected script rejection")
	}
}

func TestApplyRequest_RejectsStoredHeaderNameWithCRLF(t *testing.T) {
	// 编译期通常已拒绝；这里模拟脏 Compiled（例如旧库行）在应用点仍不得写出。
	c := &Compiled{
		Version: Version{
			ReqFailPolicy: FailClosed,
			Rules:         []Rule{{Kind: KindSetHeader, Name: "X-Ok\r\nX-Injected", Value: "y"}},
		},
	}
	in := RequestInput{Header: http.Header{}, Body: []byte(`{}`)}
	out := c.ApplyRequest(in)
	if out.Err == nil {
		t.Fatal("apply must reject CR/LF in stored header name")
	}
	if got := out.Header.Get("X-Injected"); got != "" {
		t.Fatalf("injected header must not appear, got %q", got)
	}
	for name := range out.Header {
		if strings.ContainsAny(name, "\r\n\x00") {
			t.Fatalf("outbound header map must not keep dirty name %q", name)
		}
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

// Delete + recreate can reuse a SQLite route rowid. RemoveBindingsForRoute must
// drop the published pointer so the reincarnated id stays passthrough unless
// the new route publishes its own binding.
func TestRemoveBindingsForRoute_ReusedIDIsPassthrough(t *testing.T) {
	reg := NewRegistry(20)
	set, err := reg.CreateSet("reuse")
	if err != nil {
		t.Fatal(err)
	}
	rules := []Rule{{Kind: KindReplaceBytes, From: "OLD", To: "NEW"}}
	if _, err := reg.UpdateDraft(set.ID, rules, FailClosed, FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	const routeID, endpointID, otherRoute int64 = 5, 11, 6
	if _, _, err := reg.PublishSnapshot(set.ID, routeID, endpointID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, otherRoute, endpointID); err != nil {
		t.Fatal(err)
	}
	c, _, err := reg.PublishedCompiled(routeID, endpointID)
	if err != nil || c == nil {
		t.Fatalf("setup compiled=%v err=%v", c != nil, err)
	}
	if err := reg.RemoveBindingsForRoute(routeID); err != nil {
		t.Fatal(err)
	}
	// Same numeric id after delete+recreate: must not see the old published binding.
	c, vid, err := reg.PublishedCompiled(routeID, endpointID)
	if err != nil || c != nil || vid != 0 {
		t.Fatalf("reused id must be unbound: c=%v id=%d err=%v", c != nil, vid, err)
	}
	if _, ok := reg.GetBinding(routeID, endpointID); ok {
		t.Fatal("binding row must be removed, not merely cleared")
	}
	// Live sibling route must keep its binding.
	cOther, _, err := reg.PublishedCompiled(otherRoute, endpointID)
	if err != nil || cOther == nil {
		t.Fatalf("sibling binding must remain: c=%v err=%v", cOther != nil, err)
	}
	body := []byte("OLD")
	out := cOther.ApplyRequest(RequestInput{Header: http.Header{}, Body: body})
	if out.Err != nil || !bytes.Equal(out.Body, []byte("NEW")) {
		t.Fatalf("sibling apply body=%s err=%v", out.Body, out.Err)
	}
}

func TestRemoveBindingsForEndpoint_DropsOnlyThatEndpoint(t *testing.T) {
	reg := NewRegistry(10)
	set, err := reg.CreateSet("ep")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.UpdateDraft(set.ID, []Rule{{Kind: KindReplaceBytes, From: "a", To: "b"}}, FailClosed, FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, 1, 10); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, 1, 20); err != nil {
		t.Fatal(err)
	}
	if err := reg.RemoveBindingsForEndpoint(10); err != nil {
		t.Fatal(err)
	}
	c, _, err := reg.PublishedCompiled(1, 10)
	if err != nil || c != nil {
		t.Fatalf("deleted endpoint binding must be gone: c=%v err=%v", c != nil, err)
	}
	cKeep, _, err := reg.PublishedCompiled(1, 20)
	if err != nil || cKeep == nil {
		t.Fatalf("other endpoint binding must remain: c=%v err=%v", cKeep != nil, err)
	}
}

func TestDetachEndpointBindingsAround_RestoresOnFailureKeepsPostCommitAttach(t *testing.T) {
	reg := NewRegistry(10)
	set, err := reg.CreateSet("around")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.UpdateDraft(set.ID, []Rule{{Kind: KindReplaceBytes, From: "a", To: "b"}}, FailClosed, FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, 3, 7); err != nil {
		t.Fatal(err)
	}

	boom := errors.New("delete failed")
	if err := reg.DetachEndpointBindingsAround(7, func() error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("error=%v want boom", err)
	}
	c, _, err := reg.PublishedCompiled(3, 7)
	if err != nil || c == nil {
		t.Fatalf("failed delete must restore binding: c=%v err=%v", c != nil, err)
	}

	if err := reg.DetachEndpointBindingsAround(7, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	c, _, err = reg.PublishedCompiled(3, 7)
	if err != nil || c != nil {
		t.Fatalf("successful delete must drop in-memory binding: c=%v err=%v", c != nil, err)
	}

	// Bindings attached after the delete commits must not be stripped by any
	// finishing bare-id detach (DetachEndpointBindingsAround already returned).
	if _, _, err := reg.PublishSnapshot(set.ID, 3, 7); err != nil {
		t.Fatal(err)
	}
	c, _, err = reg.PublishedCompiled(3, 7)
	if err != nil || c == nil {
		t.Fatalf("post-commit attach must remain: c=%v err=%v", c != nil, err)
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

func TestResponse_ReplaceBytesHonorsAddedBudget(t *testing.T) {
	// From is one byte; To is large enough that many matches exceed MaxAddedBytes.
	to := strings.Repeat("Z", 64*1024)
	from := "a"
	body := []byte(strings.Repeat(from, 64)) // 64 matches → ~4 MiB expansion > 1 MiB budget
	c, err := Compile(Version{
		ResFailPolicy: FailClosed,
		Rules:         []Rule{{Kind: KindReplaceBytes, From: from, To: to}},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := c.ApplyResponse(ResponseInput{Status: 200, Body: body})
	if out.Err == nil {
		t.Fatal("expected replace_bytes added-byte budget error")
	}
	if !strings.Contains(out.Err.Error(), "would add") {
		t.Fatalf("err=%v", out.Err)
	}
	if !bytes.Equal(out.Body, body) {
		t.Fatal("fail_closed must restore original body")
	}
}
