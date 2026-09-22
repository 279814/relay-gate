package transform

import "fmt"

// PersistSink stores the full transform snapshot (SQLite).
type PersistSink interface {
	SaveTransformSnapshot(sets []Set, bindings []Binding) error
	LoadTransformSnapshot() ([]Set, []Binding, error)
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
	sets, bindings, err := r.persist.LoadTransformSnapshot()
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sets = make(map[int64]*Set)
	r.bindings = make(map[string]*Binding)
	var maxSet, maxVer int64
	for i := range sets {
		s := sets[i]
		cp := cloneSet(&s)
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

func (r *Registry) flushLocked() error {
	if r.persist == nil {
		return nil
	}
	sets := make([]Set, 0, len(r.sets))
	for _, s := range r.sets {
		sets = append(sets, *cloneSet(s))
	}
	bindings := make([]Binding, 0, len(r.bindings))
	for _, b := range r.bindings {
		bindings = append(bindings, *cloneBinding(b))
	}
	if err := r.persist.SaveTransformSnapshot(sets, bindings); err != nil {
		return fmt.Errorf("persist transform snapshot: %w", err)
	}
	return nil
}
