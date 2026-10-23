package store

import (
	"context"
	"errors"
	"fmt"
	"github.com/279814/relay-gate/internal/model"
	"testing"
)

func TestSecurityDiagnosticsUsesOnlyTypedCanaryFactsAndStableBoundedPages(t *testing.T) {
	st := testStore(t)
	route := mkRoute(t, st)
	for i := 0; i < 5; i++ {
		canaryCostFixture(t, st, route, fmt.Sprintf("canary-%d", i), true, true)
	}
	// This is an ordinary manual execution with no Canary source facts.
	if _, err := st.db.Exec(`DELETE FROM canary_execution WHERE execution_id='canary-0'`); err != nil {
		t.Fatal(err)
	}
	first, err := st.ListSecurityDiagnostics(context.Background(), SecurityDiagnosticFilter{PageRequest: model.PageRequest{Limit: 2}, Source: model.CanaryManual, Verdict: "passed"})
	if err != nil || first.Total != 4 || len(first.Items) != 2 || first.Items[0].ID != "canary-4" || first.Items[0].Canary == nil || first.NextCursor == "" {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	second, err := st.ListSecurityDiagnostics(context.Background(), SecurityDiagnosticFilter{PageRequest: model.PageRequest{Limit: 2, Cursor: first.NextCursor}, Source: model.CanaryManual, Verdict: "passed"})
	if err != nil || second.Total != 4 || len(second.Items) != 2 || second.Items[0].ID != "canary-2" || second.Items[1].ID != "canary-1" || second.NextCursor != "" {
		t.Fatalf("second=%+v err=%v", second, err)
	}
	if _, err := st.ListSecurityDiagnostics(context.Background(), SecurityDiagnosticFilter{PageRequest: model.PageRequest{Limit: 2, Cursor: first.NextCursor}, Source: model.CanaryPeriodic, Verdict: "passed"}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("cross-filter cursor accepted %v", err)
	}
	if _, err := st.GetSecurityDiagnostic(context.Background(), "canary-0"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ordinary manual guessed to Canary: %v", err)
	}
	if exact, err := st.GetSecurityDiagnostic(context.Background(), "canary-3"); err != nil || exact.Canary == nil || exact.Canary.ExecutionID != exact.ID {
		t.Fatalf("exact diag=%+v %v", exact, err)
	}
	if _, err := st.db.Exec(`DROP TABLE canary_execution`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ListSecurityDiagnostics(context.Background(), SecurityDiagnosticFilter{}); err == nil {
		t.Fatal("durable failure fabricated an empty list")
	}
}
