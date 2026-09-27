package transform

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSetBudgets_RaiseRequiresConfirmAndAudits(t *testing.T) {
	reg := NewRegistry(10)
	cur := reg.Budgets()
	if cur.RequestMs != DefaultRequestBudgetMs || cur.SSEEventMs != DefaultSSEBudgetMs {
		t.Fatalf("defaults=%+v", cur)
	}
	_, err := reg.SetBudgets(DefaultRequestBudgetMs+10, DefaultSSEBudgetMs, false)
	if err == nil || !strings.Contains(err.Error(), "confirm_raise") {
		t.Fatalf("err=%v", err)
	}
	if len(reg.BudgetAudits(10)) != 0 {
		t.Fatal("failed raise must not audit")
	}
	out, err := reg.SetBudgets(DefaultRequestBudgetMs+10, DefaultSSEBudgetMs, true)
	if err != nil {
		t.Fatal(err)
	}
	if out.RequestMs != DefaultRequestBudgetMs+10 {
		t.Fatalf("out=%+v", out)
	}
	aud := reg.BudgetAudits(10)
	if len(aud) != 1 || aud[0].Action != "raise_budget" || !aud[0].Confirmed {
		t.Fatalf("audit=%+v", aud)
	}
	// Lowering does not need confirm.
	out, err = reg.SetBudgets(20, 5, false)
	if err != nil {
		t.Fatal(err)
	}
	if out.RequestMs != 20 || out.SSEEventMs != 5 {
		t.Fatalf("lower=%+v", out)
	}
	aud = reg.BudgetAudits(10)
	if len(aud) < 2 || aud[0].Action != "set_budget" {
		t.Fatalf("lower audit=%+v", aud)
	}
}

func TestApply_HonorsTinyBudget(t *testing.T) {
	c, err := Compile(Version{
		Rules: []Rule{
			{Kind: KindSetHeader, Name: "X-A", Value: "1"},
			{Kind: KindSetHeader, Name: "X-B", Value: "2"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	c.reqBudget = -time.Millisecond
	out := c.ApplyRequest(RequestInput{})
	if out.Err == nil || !strings.Contains(out.Err.Error(), "budget exceeded") {
		t.Fatalf("err=%v", out.Err)
	}
}

// overrunAfterFirstRule makes the clock read t0 while the deadline is set and
// the single rule is admitted, then jumps past any budget once that rule ran.
func overrunAfterFirstRule(t *testing.T) {
	t.Helper()
	t0 := time.Unix(1_700_000_000, 0)
	calls := 0
	prev := budgetNow
	budgetNow = func() time.Time {
		calls++
		if calls <= 2 {
			return t0
		}
		return t0.Add(time.Hour)
	}
	t.Cleanup(func() { budgetNow = prev })
}

func TestApplyRequest_InFlightRuleOverrunRestoresOriginal(t *testing.T) {
	c, err := Compile(Version{Rules: []Rule{{Kind: KindSetHeader, Name: "X-A", Value: "1"}}})
	if err != nil {
		t.Fatal(err)
	}
	overrunAfterFirstRule(t)
	in := RequestInput{Header: http.Header{"X-Keep": {"k"}}, Body: []byte(`{"a":1}`)}
	out := c.ApplyRequest(in)
	if !errors.Is(out.Err, ErrBudgetExceeded) {
		t.Fatalf("err=%v", out.Err)
	}
	if out.Changed || out.HitRules != nil || out.Header.Get("X-A") != "" ||
		out.Header.Get("X-Keep") != "k" || string(out.Body) != `{"a":1}` {
		t.Fatalf("in-flight rule result kept: %+v", out)
	}
}

func TestApplyResponse_InFlightRuleOverrunRestoresOriginal(t *testing.T) {
	c, err := Compile(Version{Rules: []Rule{{Kind: KindSetStatus, Value: "201"}}})
	if err != nil {
		t.Fatal(err)
	}
	overrunAfterFirstRule(t)
	out := c.ApplyResponse(ResponseInput{Status: 200, Header: http.Header{}, Body: []byte(`{}`)})
	if !errors.Is(out.Err, ErrBudgetExceeded) {
		t.Fatalf("err=%v", out.Err)
	}
	if out.Status != 200 || out.Changed || out.HitRules != nil {
		t.Fatalf("in-flight rule result kept: %+v", out)
	}
}

func TestApplySSEEvent_InFlightRuleOverrunRestoresOriginal(t *testing.T) {
	c, err := Compile(Version{Rules: []Rule{
		{Kind: KindSSEMatch, Match: "content_block_delta", From: "hi", To: "hello"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	overrunAfterFirstRule(t)
	ev := SSEEvent{Event: "content_block_delta", Data: "hi"}
	got, _, _, err := c.ApplySSEEvent(ev)
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("err=%v", err)
	}
	if got.Data != "hi" {
		t.Fatalf("in-flight rule result kept: %+v", got)
	}
}
