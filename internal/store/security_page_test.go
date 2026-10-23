package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/security"
)

func TestSecurityFindingPersistsCapturedIdentityInsteadOfCurrentLabels(t *testing.T) {
	st := testStore(t)
	var captured security.Finding
	if err := json.Unmarshal([]byte(`{"id":"stable-source","at_ms":1,"upstream_id":42,"upstream":"historical-name","route_id":7,"rule_id":"custom:site-check","category":"custom-category"}`), &captured); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertSecurityFinding(captured); err != nil {
		t.Fatal(err)
	}
	var upstreamID int64
	var ruleID string
	if err := st.db.QueryRow(`SELECT upstream_id,rule_id FROM security_finding WHERE id=?`, captured.ID).Scan(&upstreamID, &ruleID); err != nil || upstreamID != 42 || ruleID != "custom:site-check" {
		t.Fatalf("captured source identity was lost: upstream=%d rule=%q err=%v", upstreamID, ruleID, err)
	}
	page, err := st.ListSecurityFindingsPage(context.Background(), SecurityFindingFilter{})
	if err != nil || len(page.Findings) != 1 || page.Findings[0].RuleID != "custom:site-check" {
		t.Fatalf("read discarded captured rule identity: %+v %v", page, err)
	}
}

func TestRepeatedFindingIDCannotRewriteEvidenceOrEraseReview(t *testing.T) {
	st := testStore(t)
	first := security.Finding{ID: "immutable-evidence", AtMS: 1, Detail: "first finite redacted evidence", RuleID: "builtin:prompt_injection"}
	if err := st.InsertSecurityFinding(first); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ReviewSecurityFinding(context.Background(), first.ID, "false_positive", 1); err != nil {
		t.Fatal(err)
	}
	repeated := first
	repeated.Detail = "late different evidence"
	if err := st.InsertSecurityFinding(repeated); err != nil {
		t.Fatal(err)
	}
	page, err := st.ListSecurityFindingsPage(context.Background(), SecurityFindingFilter{})
	if err != nil || len(page.Findings) != 1 || page.Findings[0].Detail != first.Detail {
		t.Fatalf("repeated finding identity rewrote evidence: %+v %v", page, err)
	}
	var count int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM security_finding_review WHERE finding_id=? AND status='false_positive' AND revision=2`, first.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("duplicate observer write erased review: count=%d err=%v", count, err)
	}
}

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
