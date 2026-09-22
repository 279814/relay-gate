package transform

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

func TestCompile_JSONPatchKinds(t *testing.T) {
	_, err := Compile(Version{Rules: []Rule{{Kind: KindJSONPatchAdd, Name: "foo", Value: `"x"`}}})
	if err == nil {
		t.Fatal("expected pointer must start with /")
	}
	_, err = Compile(Version{Rules: []Rule{{Kind: KindJSONPatchAdd, Name: "/foo"}}})
	if err == nil {
		t.Fatal("expected value required")
	}
	_, err = Compile(Version{Rules: []Rule{{Kind: KindJSONPatchCopy, From: "/a", To: "b"}}})
	if err == nil {
		t.Fatal("expected to pointer validation")
	}
	_, err = Compile(Version{Rules: []Rule{
		{Kind: KindJSONPatchAdd, Name: "/x", Value: `1`},
		{Kind: KindJSONPatchRemove, Name: "/x"},
		{Kind: KindJSONPatchCopy, From: "/a", To: "/b"},
	}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestJSONPatch_AddRemoveCopy(t *testing.T) {
	c, err := Compile(Version{
		Rules: []Rule{
			{Kind: KindJSONPatchAdd, Name: "/extra", Value: `{"n":2}`},
			{Kind: KindJSONPatchCopy, From: "/model", To: "/alias"},
			{Kind: KindJSONPatchRemove, Name: "/drop"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	in := RequestInput{
		Header: http.Header{},
		Body:   []byte(`{"model":"m1","drop":true,"keep":1}`),
	}
	out := c.ApplyRequest(in)
	if out.Err != nil {
		t.Fatal(out.Err)
	}
	var got map[string]any
	if err := json.Unmarshal(out.Body, &got); err != nil {
		t.Fatal(err)
	}
	if got["model"] != "m1" || got["alias"] != "m1" {
		t.Fatalf("copy failed: %v", got)
	}
	if _, ok := got["drop"]; ok {
		t.Fatalf("remove failed: %v", got)
	}
	extra, ok := got["extra"].(map[string]any)
	if !ok || extra["n"].(float64) != 2 {
		t.Fatalf("add failed: %v", got)
	}
	if !bytes.Contains(out.Body, []byte(`"keep"`)) {
		t.Fatalf("lost keep: %s", out.Body)
	}
}

func TestJSONPatch_RejectsScriptValue(t *testing.T) {
	_, err := Compile(Version{Rules: []Rule{
		{Kind: KindJSONPatchAdd, Name: "/x", Value: `<script>alert(1)</script>`},
	}})
	if err == nil {
		t.Fatal("expected script rejection")
	}
}

func TestJSONPatch_MissingFromFailsClosed(t *testing.T) {
	c, err := Compile(Version{
		ReqFailPolicy: FailClosed,
		Rules: []Rule{
			{Kind: KindJSONPatchAdd, Name: "/ok", Value: `1`},
			{Kind: KindJSONPatchCopy, From: "/missing", To: "/dst"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"a":1}`)
	out := c.ApplyRequest(RequestInput{Header: http.Header{}, Body: body})
	if out.Err == nil {
		t.Fatal("expected copy miss error")
	}
	if !bytes.Equal(out.Body, body) {
		t.Fatalf("fail_closed left mutation: %s", out.Body)
	}
}
