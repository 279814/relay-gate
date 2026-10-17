package probe

import (
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

// Only the three reads used by RunManual are supplied. All execution,
// preparation and observation work stays in the production service.
type manualFixtureStore struct {
	AdminStore
	cfg *fakeCfg
}

func (s manualFixtureStore) GetRoute(id int64) (*model.Route, error) {
	snap, err := s.cfg.Snapshot()
	if err != nil {
		return nil, err
	}
	if row := findRoute(snap, id); row != nil {
		return row, nil
	}
	return nil, store.ErrNotFound
}

func (s manualFixtureStore) GetUpstream(id int64) (*model.Upstream, error) {
	snap, err := s.cfg.Snapshot()
	if err != nil {
		return nil, err
	}
	if row := snap.Upstreams[id]; row != nil {
		return row, nil
	}
	return nil, store.ErrNotFound
}

func (s manualFixtureStore) GetModelName(id int64) (*model.ModelName, error) {
	snap, err := s.cfg.Snapshot()
	if err != nil {
		return nil, err
	}
	if row := findModelName(snap, id); row != nil {
		return row, nil
	}
	return nil, store.ErrNotFound
}

func manualFixtureService(cfg *fakeCfg, scheduler *Scheduler) *Service {
	return NewService(manualFixtureStore{cfg: cfg}, scheduler.executor, nil, cfg, nil, nil).
		WithManualPreparer(scheduler)
}
