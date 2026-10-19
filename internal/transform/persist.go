package transform

import (
	"errors"
)

// ErrPersist marks a PersistSink failure. The wrapped text is raw driver
// output (table names, SQLite messages) and must not reach an API client.
var ErrPersist = errors.New("persist transform snapshot")

// PersistSink stores the full transform snapshot (SQLite).
type PersistSink interface {
	SaveTransformSnapshot(sets []Set, bindings []Binding) error
	LoadTransformSnapshot() ([]Set, []Binding, error)
}

// TargetPersistSink checks the administrative publication target in the same
// transaction as its snapshot. Trusted legacy setup remains available above.
type TargetPersistSink interface {
	SaveTransformSnapshotForTarget(sets []Set, bindings []Binding, routeID, endpointID int64) error
}

// WithPersist attaches durable storage; mutations rewrite the snapshot.
func (r *Registry) WithPersist(p PersistSink) *Registry {
	r.persist = p
	return r
}

// LoadFromPersist replaces in-memory state from the sink.
func (r *Registry) LoadFromPersist() error {
	if r == nil || r.persist == nil {
		return nil
	}
	r.writerMu.Lock()
	defer r.writerMu.Unlock()
	sets, bindings, err := r.persist.LoadTransformSnapshot()
	if err != nil {
		return err
	}
	limits := BudgetLimits{RequestMs: DefaultRequestBudgetMs, SSEEventMs: DefaultSSEBudgetMs}
	revision := int64(1)
	if sink, ok := r.persist.(BudgetPersistSink); ok {
		limits, revision, err = sink.LoadTransformBudgets()
		if err != nil {
			return err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requestMs, r.sseMs, r.budgetRevision = limits.RequestMs, limits.SSEEventMs, revision
	r.sets = make(map[int64]*Set)
	r.bindings = make(map[string]*Binding)
	var maxSet, maxVer int64
	for i := range sets {
		s := sets[i]
		cp := cloneSet(&s)
		if cp.State == "" {
			cp.State = LifecycleActive
		}
		if cp.Revision < 1 {
			cp.Revision = 1
		}
		r.sets[cp.ID] = cp
		if cp.ID > maxSet {
			maxSet = cp.ID
		}
		if cp.Draft != nil && cp.Draft.ID > maxVer {
			maxVer = cp.Draft.ID
		}
		for _, h := range cp.History {
			if h.ID > maxVer {
				maxVer = h.ID
			}
		}
	}
	for i := range bindings {
		b := bindings[i]
		r.bindings[bindKey(b.RouteID, b.EndpointID)] = cloneBinding(&b)
	}
	if maxSet < 1 {
		maxSet = 0
	}
	if maxVer < 1 {
		maxVer = 0
	}
	r.nextSet.Store(maxSet + 1)
	r.nextVer.Store(maxVer + 1)
	return nil
}
