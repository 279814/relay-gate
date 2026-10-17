package api

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probe"
	"github.com/279814/relay-gate/internal/runstate"
)

type countingStateAdmin struct {
	RunStateAdmin
	calls int
}

func (*countingStateAdmin) Current() runstate.Snapshot {
	return runstate.Snapshot{State: model.RunStateRunning, Revision: 1}
}
func (c *countingStateAdmin) Set(_ context.Context, state model.RunState, _ int64) (runstate.Snapshot, error) {
	c.calls++
	return runstate.Snapshot{State: state, Revision: 2}, nil
}

func TestStateHTTPRequiresClientRevisionBeforeSet(t *testing.T) {
	s, _, _, _ := newLivecfgServer(t)
	controller, err := runstate.NewController(s.st)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(controller.Close)
	state := &countingStateAdmin{RunStateAdmin: controller}
	h := s.WithRunState(state).Routes(testAdminPW)
	for _, body := range []string{`{"state":"paused"}`, `{"state":"paused","expected_revision":null}`, `{"state":"paused","expected_revision":0}`, `{"state":"paused","expected_revision":-1}`} {
		r := do(t, h, http.MethodPost, "/admin/api/state", body, true)
		if r.Code != 400 || state.calls != 0 {
			t.Fatalf("body=%s status=%d calls=%d", body, r.Code, state.calls)
		}
	}
}

func TestStateHTTPSameCapturedRevisionHasOneWinner(t *testing.T) {
	s, _, _, _ := newLivecfgServer(t)
	controller, err := runstate.NewController(s.st)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(controller.Close)
	if err := controller.BindSyntheticController(probe.NewSyntheticCoordinator(model.RunStateRunning)); err != nil {
		t.Fatal(err)
	}
	h := s.WithRunState(controller).Routes(testAdminPW)
	revision := controller.Current().Revision
	if revision < 1 {
		t.Fatalf("initial state revision=%d", revision)
	}
	body := `{"state":"paused","expected_revision":` + itoa(revision) + `}`
	start := make(chan struct{})
	results := make(chan int, 2)
	var workers sync.WaitGroup
	for i := 0; i < 2; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			results <- do(t, h, http.MethodPost, "/admin/api/state", body, true).Code
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	counts := map[int]int{}
	for status := range results {
		counts[status]++
	}
	if counts[200] != 1 || counts[409] != 1 {
		t.Fatalf("concurrent statuses=%v", counts)
	}
	if snap := controller.Current(); snap.State != model.RunStatePaused || snap.Revision != revision+1 {
		t.Fatalf("state=%+v", snap)
	}
}
