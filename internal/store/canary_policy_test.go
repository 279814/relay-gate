package store

import (
	"context"
	"errors"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestCanaryPolicyDefaultsOffValidatesOwnershipAndCAS(t *testing.T) {
	st := testStore(t)
	route := mkRoute(t, st)
	policy, err := st.GetCanaryPolicy(context.Background(), route.UpstreamID)
	if err != nil || policy.Enabled || policy.Revision != 0 || policy.IntervalSec != 3600 {
		t.Fatalf("default Canary policy=%+v %v", policy, err)
	}
	input := model.CanaryPolicy{UpstreamID: route.UpstreamID, RouteID: route.ID, IntervalSec: 3600}
	saved, err := st.SaveCanaryPolicy(context.Background(), input)
	if err != nil || saved.Revision != 1 || saved.Enabled {
		t.Fatalf("disabled policy=%+v %v", saved, err)
	}
	input.Revision = 1
	input.Enabled = true
	upstream, err := st.GetUpstream(route.UpstreamID)
	if err != nil {
		t.Fatal(err)
	}
	upstream.ProbeMode = model.ProbeModeLazy
	if err := st.UpdateUpstreamWithRevision(context.Background(), upstream, upstream.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveCanaryPolicy(context.Background(), input); !errors.Is(err, model.ErrValidation) {
		t.Fatalf("Lazy periodic Canary accepted: %v", err)
	}
	upstream.ProbeMode = model.ProbeModeActive
	if err := st.UpdateUpstreamWithRevision(context.Background(), upstream, upstream.Revision); err != nil {
		t.Fatal(err)
	}
	saved, err = st.SaveCanaryPolicy(context.Background(), input)
	if err != nil || !saved.Enabled || saved.Revision != 2 {
		t.Fatalf("active periodic policy=%+v %v", saved, err)
	}
	if _, err := st.SaveCanaryPolicy(context.Background(), input); err != ErrRevisionConflict {
		t.Fatalf("stale Canary edit overwrote current policy: %v", err)
	}
	input = saved
	input.RouteID = 9999
	if _, err := st.SaveCanaryPolicy(context.Background(), input); !errors.Is(err, model.ErrValidation) {
		t.Fatalf("unrelated/missing Route accepted: %v", err)
	}
	input = saved
	input.IntervalSec = 299
	if _, err := st.SaveCanaryPolicy(context.Background(), input); !errors.Is(err, model.ErrValidation) {
		t.Fatalf("unbounded short interval accepted: %v", err)
	}
	page, err := st.ListEnabledCanaryPolicies(context.Background(), 0, 1)
	if err != nil || len(page) != 1 || page[0].Revision != 2 {
		t.Fatalf("typed scheduler policy page=%+v %v", page, err)
	}
	page, err = st.ListEnabledCanaryPolicies(context.Background(), route.UpstreamID, 1)
	if err != nil || len(page) != 0 {
		t.Fatalf("policy keyset did not advance: %+v %v", page, err)
	}
}

func TestCanaryPolicyConcurrentCASCommitsOneRevision(t *testing.T) {
	st := testStore(t)
	route := mkRoute(t, st)
	initial, err := st.SaveCanaryPolicy(context.Background(), model.CanaryPolicy{UpstreamID: route.UpstreamID, RouteID: route.ID, IntervalSec: 900})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, interval := range []int{1200, 1800} {
		input := initial
		input.IntervalSec = interval
		go func() { <-start; _, err := st.SaveCanaryPolicy(context.Background(), input); results <- err }()
	}
	close(start)
	successes, conflicts := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			successes++
		} else if errors.Is(err, ErrRevisionConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("CAS successes=%d conflicts=%d", successes, conflicts)
	}
	current, err := st.GetCanaryPolicy(context.Background(), route.UpstreamID)
	if err != nil || current.Revision != 2 {
		t.Fatalf("CAS revision=%+v %v", current, err)
	}
}
