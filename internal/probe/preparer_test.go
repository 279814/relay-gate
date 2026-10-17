package probe

import (
	"context"
	"github.com/279814/relay-gate/internal/model"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"testing"
)

func TestExecutorPreparationDoesNotDependOnLegacyProber(t *testing.T) {
	source, err := parser.ParseFile(token.NewFileSet(), "executor.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(source, func(node ast.Node) bool {
		if name, ok := node.(*ast.Ident); ok && name.Name == "Prober" {
			t.Error("Executor still depends on the legacy network/parser implementation")
		}
		return true
	})
}

func TestExecutorMissingRecipeSourceDoesNotSendBuiltinRequest(t *testing.T) {
	rt := &countingRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		return respFrom(200, "text/event-stream", anthropicSemanticBody()), nil
	}}
	up := upstreamFor("https://example.test")
	recorder := &captureRecorder{}
	executor := newTestExecutorFor(up, rt, recorder, AlwaysOpenAdmission(), WallClock())
	executor.recipes = nil
	result, err := executor.Execute(context.Background(), l2RequestFor(up))
	if err != nil {
		t.Fatal(err)
	}
	if rt.count() != 0 || result.Sent || result.Decision.ErrorClass != model.ErrorConfig {
		t.Fatalf("missing source silently selected a builtin: sent=%v calls=%d class=%s", result.Sent, rt.count(), result.Decision.ErrorClass)
	}
}

func TestExecutorDoesNotMergeRetiredUpstreamProbeHeaders(t *testing.T) {
	var sent http.Header
	rt := &countingRoundTripper{fn: func(r *http.Request) (*http.Response, error) {
		sent = r.Header.Clone()
		return respFrom(200, "text/event-stream", anthropicSemanticBody()), nil
	}}
	up := upstreamFor("https://example.test")
	up.ProbeHeaders = map[string]string{"user-agent": "legacy-fingerprint-private", "x-legacy": "legacy-private", "accept": "legacy-media"}
	executor := newTestExecutorFor(up, rt, &captureRecorder{}, AlwaysOpenAdmission(), WallClock())
	if _, err := executor.Execute(context.Background(), l2RequestFor(up)); err != nil {
		t.Fatal(err)
	}
	if sent == nil || sent.Get("X-Legacy") != "" || sent.Get("User-Agent") == "legacy-fingerprint-private" || sent.Get("Accept") == "legacy-media" {
		t.Fatalf("retired overrides affected outbound request: %v", sent)
	}
}
