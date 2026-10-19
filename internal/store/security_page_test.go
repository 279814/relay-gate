package store

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/security"
)

func TestSecurityFindingPageUsesBothSortKeysAndBoundedPages(t *testing.T) {
	st := testStore(t)
	for i := 0; i < 7; i++ {
		if err := st.InsertSecurityFinding(security.Finding{ID: fmt.Sprintf("tie-%d", i), AtMS: int64(100 + i/2), Severity: security.SeverityHigh, RouteID: 7, Category: "prompt_injection", Detail: "finite redacted evidence"}); err != nil {
			t.Fatal(err)
		}
	}
	f := SecurityFindingFilter{PageRequest: model.PageRequest{Limit: 2}, RouteID: 7}
	first, err := st.ListSecurityFindingsPage(context.Background(), f)
	if err != nil || len(first.Findings) != 2 || first.Total != 7 || first.NextCursor == "" || first.Findings[0].ID != "tie-6" || first.Findings[1].ID != "tie-5" {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	for _, change := range []func(*SecurityFindingFilter){
		func(f *SecurityFindingFilter) { f.RouteID = 8 },
		func(f *SecurityFindingFilter) { f.Severity = security.SeverityLow },
		func(f *SecurityFindingFilter) { f.Category = "protocol_html" },
		func(f *SecurityFindingFilter) { f.FromMS = 1 },
		func(f *SecurityFindingFilter) { f.ToMS = 200 },
	} {
		changed := f
		changed.Cursor = first.NextCursor
		change(&changed)
		if _, err := st.ListSecurityFindingsPage(context.Background(), changed); !errors.Is(err, ErrInvalidCursor) {
			t.Fatalf("changed filter accepted cursor: %v", err)
		}
	}
	seen := map[string]bool{"tie-6": true, "tie-5": true}
	f.Cursor, f.Limit = first.NextCursor, 3
	for f.Cursor != "" {
		page, err := st.ListSecurityFindingsPage(context.Background(), f)
		if err != nil || len(page.Findings) > 3 || page.Total != 7 {
			t.Fatalf("page=%+v err=%v", page, err)
		}
		for _, finding := range page.Findings {
			if seen[finding.ID] || finding.Detail != "finite redacted evidence" {
				t.Fatalf("duplicate or wrong decoded evidence: %+v", finding)
			}
			seen[finding.ID] = true
		}
		f.Cursor = page.NextCursor
	}
	if len(seen) != 7 {
		t.Fatalf("page omitted tied records: %v", seen)
	}
}

func TestSecurityFindingPageValidatesContextAndFilters(t *testing.T) {
	st := testStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := st.ListSecurityFindingsPage(ctx, SecurityFindingFilter{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled read was not canceled: %v", err)
	}
	for _, f := range []SecurityFindingFilter{
		{Severity: "urgent"}, {RouteID: -1}, {Category: "body with spaces"}, {FromMS: 11, ToMS: 10},
	} {
		if _, err := st.ListSecurityFindingsPage(context.Background(), f); !errors.Is(err, model.ErrValidation) {
			t.Fatalf("invalid filter=%+v err=%v", f, err)
		}
	}
	for _, f := range []SecurityFindingFilter{
		{PageRequest: model.PageRequest{Limit: MaximumPageLimit + 1}},
		{PageRequest: model.PageRequest{Cursor: "not-a-cursor"}},
	} {
		if _, err := st.ListSecurityFindingsPage(context.Background(), f); !errors.Is(err, ErrInvalidCursor) {
			t.Fatalf("invalid page=%+v err=%v", f, err)
		}
	}
}
