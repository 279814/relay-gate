package transform

import (
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
