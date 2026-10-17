package probe

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/runstate"
	"github.com/279814/relay-gate/internal/store"
)

type fixedSchedulerRunState struct{ snapshot runstate.Snapshot }

func (state fixedSchedulerRunState) Current() runstate.Snapshot { return state.snapshot }

type countedSettingsSource struct {
	ConfigSource
	reads atomic.Int32
}

func (source *countedSettingsSource) Settings() (model.Settings, error) {
	source.reads.Add(1)
	return source.ConfigSource.Settings()
}

func fixtureController(t *testing.T, st *store.Store) *runstate.Controller {
	t.Helper()
	controller, err := runstate.NewController(st)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(controller.Close)
	return controller
}

func TestSchedulerWithoutAdmittingControllerNeverClaimsOrSends(t *testing.T) {
	for _, test := range []struct {
		name  string
		state runstate.Reader
	}{
		{"missing", nil},
		{"maintenance", fixedSchedulerRunState{runstate.Snapshot{State: model.RunStateRunning, Revision: 1, Maintenance: true}}},
		{"invalid", fixedSchedulerRunState{runstate.Snapshot{State: "invalid", Revision: 1}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var hits atomic.Int32
			h := newSchedHarness(t, 1, func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(200) })
			config := &countedSettingsSource{ConfigSource: h.cfg}
			h.sched.cfg = config
			h.sched.WithRunState(test.state)
			h.sched.tick(context.Background())
			h.sched.wg.Wait()
			l1, l2, reports, _, _ := h.track.snapshot()
			if config.reads.Load() != 0 {
				t.Fatalf("nonadmitting Controller reached config/database reader %d times", config.reads.Load())
			}
			if hits.Load() != 0 || len(l1) != 0 || len(l2) != 0 || len(reports) != 0 {
				t.Fatalf("nonadmitting Controller dispatched: hits=%d l1=%v l2=%v reports=%v", hits.Load(), l1, l2, reports)
			}
		})
	}
}
