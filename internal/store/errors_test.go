package store

import (
	"errors"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

// 未识别的约束冲突经 writeErr 的 400 分支会把 err.Error() 原样回给客户端，
// 所以不得包 ErrValidation；已知约束保留固定文案且不含驱动原文。
func TestWrapConstraint_UnknownConstraintIsNotClientVisibleValidation(t *testing.T) {
	raw := errors.New("constraint failed: CHECK constraint failed: upstream_endpoint (275)")
	got := wrapConstraint(raw, "upstream_endpoint")
	if errors.Is(got, model.ErrValidation) {
		t.Fatalf("unknown constraint wrapped as ErrValidation, 400 body would be %q", got.Error())
	}
	if !errors.Is(got, raw) {
		t.Fatalf("driver error must stay in chain for redacted logging, got %v", got)
	}
}

func TestWrapConstraint_KnownConstraintsKeepFixedMessage(t *testing.T) {
	cases := []string{
		"constraint failed: UNIQUE constraint failed: upstream.name (2067)",
		"constraint failed: UNIQUE constraint failed: model_name.name (2067)",
		"constraint failed: FOREIGN KEY constraint failed (787)",
		"constraint failed: UNIQUE constraint failed: route.model_name_id, route.upstream_id (2067)",
	}
	for _, msg := range cases {
		got := wrapConstraint(errors.New(msg), "route")
		if !errors.Is(got, model.ErrValidation) {
			t.Fatalf("%q: want ErrValidation, got %v", msg, got)
		}
		for _, leak := range []string{"constraint failed", "FOREIGN KEY", "UNIQUE", "(787)", "(2067)"} {
			if strings.Contains(got.Error(), leak) {
				t.Fatalf("%q: client message leaks %q: %q", msg, leak, got.Error())
			}
		}
	}
}
