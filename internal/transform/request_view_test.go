package transform

import (
	"testing"
	"time"
)

func TestRequestViewFreezesVersionsAbsenceAndBudgetsForOnlyItsRoutes(t *testing.T) {
	r := NewRegistry(8)
	set, err := r.CreateSet("request-view")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.UpdateDraft(set.ID, []Rule{{Kind: KindSetHeader, Name: "X-Version", Value: "old"}}, FailClosed, FailClosed, ""); err != nil {
		t.Fatal(err)
	}
	_, published, err := r.PublishSnapshot(set.ID, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	_, shadow, err := r.ShadowSnapshot(set.ID, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	view := r.CaptureRoutes([]int64{1, 2})
	if _, err := r.SetBudgets(500, 100, true); err != nil {
		t.Fatal(err)
	}
	if _, err := r.UpdateDraft(set.ID, []Rule{{Kind: KindSetHeader, Name: "X-Version", Value: "new"}}, FailClosed, FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	for _, routeID := range []int64{1, 2, 3} {
		if _, _, err := r.PublishSnapshot(set.ID, routeID, 10); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name      string
		get       func(int64, int64) (*Compiled, int64, error)
		versionID int64
	}{{"published", view.PublishedCompiled, published.ID}, {"shadow", view.ShadowCompiled, shadow.ID}} {
		t.Run(tc.name, func(t *testing.T) {
			c, id, err := tc.get(1, 10)
			if err != nil || c == nil || id != tc.versionID || c.Version.Rules[0].Value != "old" || c.reqBudget != 50*time.Millisecond || c.sseBudget != 10*time.Millisecond {
				t.Fatalf("mixed request view: compiled=%+v id=%d err=%v", c, id, err)
			}
			// The exported Compiled value cannot modify the captured version.
			c.Version.Rules[0].Value = "caller mutation"
			c, _, _ = tc.get(1, 10)
			if c.Version.Rules[0].Value != "old" {
				t.Fatal("compiled caller mutated the request snapshot")
			}
			for _, routeID := range []int64{2, 3} {
				if c, id, err := tc.get(routeID, 10); c != nil || id != 0 || err != nil {
					t.Fatalf("new/unrelated binding entered the view: route=%d compiled=%+v id=%d err=%v", routeID, c, id, err)
				}
			}
		})
	}
	newView := r.CaptureRoutes([]int64{1})
	c, _, err := newView.PublishedCompiled(1, 10)
	if err != nil || c == nil || c.Version.Rules[0].Value != "new" || c.reqBudget != 500*time.Millisecond || c.sseBudget != 100*time.Millisecond {
		t.Fatalf("new request missed latest version/budget: %+v %v", c, err)
	}
}

func TestRequestViewRetainsBrokenBindingAsRouteLocalError(t *testing.T) {
	r := NewRegistry(8)
	r.bindings[bindKey(1, 10)] = &Binding{RouteID: 1, EndpointID: 10, SetID: 999, PublishedID: 7}
	view := r.CaptureRoutes([]int64{1, 2})
	if _, _, err := view.PublishedCompiled(1, 10); err == nil {
		t.Fatal("missing bound version became passthrough")
	}
	if c, id, err := view.PublishedCompiled(2, 10); c != nil || id != 0 || err != nil {
		t.Fatalf("unrelated route inherited binding failure: %v", err)
	}
}
