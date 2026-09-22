package transform

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
)

func TestBodyTemplate_ReplacesLiteral(t *testing.T) {
	c, err := Compile(Version{
		Rules: []Rule{{Kind: KindBodyTemplate, Value: `{"model":"m2","n":1}`}},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := c.ApplyRequest(RequestInput{
		Header: http.Header{},
		Body:   []byte(`{"model":"m1","drop":true}`),
	})
	if out.Err != nil {
		t.Fatal(out.Err)
	}
	if !bytes.Equal(out.Body, []byte(`{"model":"m2","n":1}`)) {
		t.Fatalf("body=%s", out.Body)
	}
}

func TestBodyTemplate_RejectsDuplicateModelAtCompile(t *testing.T) {
	_, err := Compile(Version{Rules: []Rule{
		{Kind: KindBodyTemplate, Value: `{"model":"a","model":"b"}`},
	}})
	if err == nil || !strings.Contains(err.Error(), "duplicate model") {
		t.Fatalf("err=%v", err)
	}
}

func TestBodyTemplate_MustNotDeleteModel(t *testing.T) {
	c, err := Compile(Version{
		ReqFailPolicy: FailClosed,
		Rules:         []Rule{{Kind: KindBodyTemplate, Value: `{"ok":true}`}},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"model":"keep-me"}`)
	out := c.ApplyRequest(RequestInput{Header: http.Header{}, Body: body})
	if out.Err == nil || !strings.Contains(out.Err.Error(), "delete model") {
		t.Fatalf("err=%v", out.Err)
	}
	if !bytes.Equal(out.Body, body) {
		t.Fatal("fail_closed left mutation")
	}
}

func TestBodyTemplate_MustNotChangeModelType(t *testing.T) {
	c, err := Compile(Version{
		ReqFailPolicy: FailClosed,
		Rules:         []Rule{{Kind: KindBodyTemplate, Value: `{"model":{"nested":1}}`}},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := c.ApplyRequest(RequestInput{
		Header: http.Header{},
		Body:   []byte(`{"model":"m1"}`),
	})
	if out.Err == nil || !strings.Contains(out.Err.Error(), "change model type") {
		t.Fatalf("err=%v", out.Err)
	}
}

func TestBodyTemplate_RejectsScript(t *testing.T) {
	_, err := Compile(Version{Rules: []Rule{
		{Kind: KindBodyTemplate, Value: `function(){return 1}`},
	}})
	if err == nil {
		t.Fatal("expected script rejection")
	}
}
