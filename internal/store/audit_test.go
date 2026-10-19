package store

import (
	"context"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestDurableAuditRecordsCompletionAndInterruptedAttemptsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	writer, ok := any(st).(interface {
		BeginAuditEvent(context.Context, string, string, string) (int64, error)
		CompleteAuditEvent(context.Context, int64, string, string) error
	})
	if !ok {
		t.Fatal("durable audit operations are unavailable")
	}
	first, err := writer.BeginAuditEvent(ctx, "route_disable", "42", strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.CompleteAuditEvent(ctx, first, "failed", "conflict"); err != nil {
		t.Fatal(err)
	}
	if err := writer.CompleteAuditEvent(ctx, first, "succeeded", ""); err == nil {
		t.Fatal("completed audit history was rewritten")
	}
	second, err := writer.BeginAuditEvent(ctx, "master_rotate", "current", strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.BeginAuditEvent(ctx, "untrusted_secret_value", "current", strings.Repeat("b", 64)); err == nil {
		t.Fatal("audit accepted an action outside the finite vocabulary")
	}
	if err := writer.CompleteAuditEvent(ctx, second, "failed", "raw-password-or-private-error"); err == nil {
		t.Fatal("audit accepted unbounded error detail")
	}
	path, cipher := st.path, st.cipher
	st.Close()
	reopened, err := Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var outcome, reason string
	if err := reopened.db.QueryRow(`SELECT outcome,reason_code FROM audit_event WHERE id=?`, first).Scan(&outcome, &reason); err != nil || outcome != "failed" || reason != "conflict" {
		t.Fatalf("completed audit lost across restart: outcome=%s reason=%s err=%v", outcome, reason, err)
	}
	if err := reopened.db.QueryRow(`SELECT outcome,reason_code FROM audit_event WHERE id=?`, second).Scan(&outcome, &reason); err != nil || outcome != "unknown" || reason != "restart_before_completion" {
		t.Fatalf("interrupted mutation was claimed complete: outcome=%s reason=%s err=%v", outcome, reason, err)
	}
}

func TestAuditPagesFreezeInsertionBoundaryAndBindAllFilters(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	for n := 0; n < 5; n++ {
		action := "route_disable"
		if n%2 == 1 {
			action = "relay_rotate"
		}
		id, err := st.BeginAuditEvent(ctx, action, "42", strings.Repeat("a", 64))
		if err != nil {
			t.Fatal(err)
		}
		if err := st.CompleteAuditEvent(ctx, id, "succeeded", ""); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.Exec(`UPDATE audit_event SET at_ms=10 WHERE id=?`, id); err != nil {
			t.Fatal(err)
		}
	}
	filter := model.AuditEventFilter{PageRequest: model.PageRequest{Limit: 2}, AfterMS: 10, BeforeMS: 10}
	page, err := st.ListAuditEventsPage(ctx, filter)
	if err != nil || len(page.Items) != 2 || page.Items[0].ID != 5 || page.Items[1].ID != 4 || page.NextCursor == "" {
		t.Fatalf("audit first page=%+v err=%v", page, err)
	}
	if _, err := st.BeginAuditEvent(ctx, "route_disable", "42", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	filter.Cursor = page.NextCursor
	page, err = st.ListAuditEventsPage(ctx, filter)
	if err != nil || len(page.Items) != 2 || page.Items[0].ID != 3 || page.Items[1].ID != 2 {
		t.Fatalf("new audit row changed continuation: page=%+v err=%v", page, err)
	}
	filter.Cursor = page.NextCursor
	page, err = st.ListAuditEventsPage(ctx, filter)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != 1 || page.NextCursor != "" {
		t.Fatalf("audit final page=%+v err=%v", page, err)
	}
	filter = model.AuditEventFilter{PageRequest: model.PageRequest{Limit: 1}, Category: "route", Action: "route_disable", Outcome: "succeeded", ResourceType: "route", ResourceID: "42", AfterMS: 10, BeforeMS: 10}
	page, err = st.ListAuditEventsPage(ctx, filter)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != 5 || page.NextCursor == "" {
		t.Fatalf("audit exact filters=%+v err=%v", page, err)
	}
	filter.Cursor, filter.ResourceID = page.NextCursor, "43"
	if _, err := st.ListAuditEventsPage(ctx, filter); err == nil {
		t.Fatal("audit continuation accepted changed filters")
	}
	for _, invalid := range []model.AuditEventFilter{{PageRequest: model.PageRequest{Limit: 201}}, {Category: "private-secret"}, {Action: "untrusted_error_text"}, {Outcome: "invented"}, {AfterMS: -1}, {AfterMS: 10, BeforeMS: 9}} {
		if _, err := st.ListAuditEventsPage(ctx, invalid); err == nil {
			t.Fatalf("audit accepted invalid filter: %+v", invalid)
		}
	}
}
