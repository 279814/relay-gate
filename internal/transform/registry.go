package transform

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ListSets returns all sets (newest id last).
func (r *Registry) ListSets() []Set {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Set, 0, len(r.sets))
	for _, s := range r.sets {
		out = append(out, *cloneSet(s))
	}
	return out
}

// GetSet returns a set by id.
func (r *Registry) GetSet(id int64) (*Set, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sets[id]
	if !ok {
		return nil, fmt.Errorf("transform set %d not found", id)
	}
	return cloneSet(s), nil
}

// Preview compiles the draft and applies it in-memory (no binding change).
func (r *Registry) Preview(setID int64, phase string, req RequestInput, res ResponseInput) (map[string]any, error) {
	return r.PreviewSensitive(setID, phase, req, res, nil, nil)
}
func (r *Registry) PreviewSensitive(setID int64, phase string, req RequestInput, res ResponseInput, values []string, expected *int64) (map[string]any, error) {
	r.mu.RLock()
	s, ok := r.sets[setID]
	if !ok || s.Draft == nil {
		r.mu.RUnlock()
		return nil, fmt.Errorf("transform set %d draft not found", setID)
	}
	if expected != nil && s.Revision != *expected {
		r.mu.RUnlock()
		return nil, ErrRevisionConflict
	}
	draft := *s.Draft
	draft.Rules = append([]Rule(nil), s.Draft.Rules...)
	r.mu.RUnlock()
	if len(draft.Rules) == 0 {
		return nil, fmt.Errorf("draft has no rules")
	}
	c, err := Compile(draft)
	if err != nil {
		return nil, err
	}
	summary := c.ShadowDiffSensitive(phase, req, res, values)
	inputHash := ""
	if !strings.Contains(summary, "diff=omitted(") {
		body := req.Body
		if phase != "request" {
			body = res.Body
		}
		inputHash = HashBytes(body)
	}
	rec := r.record(ExecutionRecord{
		RouteID:     0,
		EndpointID:  0,
		VersionID:   draft.ID,
		Mode:        "preview",
		Phase:       phase,
		OK:          strings.HasSuffix(summary, "err="),
		DiffSummary: summary,
		InputHash:   inputHash,
	})
	return map[string]any{"summary": summary, "execution": rec}, nil
}

// DetachEndpointBindingsAround removes in-memory bindings for endpointID, runs
// fn, and restores them if fn fails. Durable transform_binding rows must be
// deleted inside Store.DeleteEndpoint's SQL transaction; callers must not
// bare-id detach again after fn succeeds (SQLite id reuse race).
func (r *Registry) DetachEndpointBindingsAround(endpointID int64, fn func() error) error {
	if r == nil {
		return fn()
	}
	if fn == nil {
		return nil
	}
	r.writerMu.Lock()
	defer r.writerMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	saved := make(map[string]*Binding)
	for key, b := range r.bindings {
		if b != nil && b.EndpointID == endpointID {
			saved[key] = b
			delete(r.bindings, key)
		}
	}
	if err := fn(); err != nil {
		for key, b := range saved {
			r.bindings[key] = b
		}
		return err
	}
	// Success: SQL detach already committed with the endpoint row. Do not
	// flush or re-detach by bare id — a concurrent create may have reused it.
	return nil
}

// DetachRouteBindingsAround removes in-memory bindings for the given route IDs,
// runs fn, and restores them if fn fails. Durable transform_binding rows must be
// deleted inside the store delete transaction; callers must not bare-id detach
// again after fn succeeds (SQLite id reuse race).
func (r *Registry) DetachRouteBindingsAround(routeIDs []int64, fn func() error) error {
	if r == nil {
		return fn()
	}
	if fn == nil {
		return nil
	}
	if len(routeIDs) == 0 {
		return fn()
	}
	want := make(map[int64]struct{}, len(routeIDs))
	for _, id := range routeIDs {
		if id > 0 {
			want[id] = struct{}{}
		}
	}
	if len(want) == 0 {
		return fn()
	}
	r.writerMu.Lock()
	defer r.writerMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	saved := make(map[string]*Binding)
	for key, b := range r.bindings {
		if b != nil {
			if _, ok := want[b.RouteID]; ok {
				saved[key] = b
				delete(r.bindings, key)
			}
		}
	}
	if err := fn(); err != nil {
		for key, b := range saved {
			r.bindings[key] = b
		}
		return err
	}
	// Success: SQL detach already committed with the route row(s). Do not
	// flush or re-detach by bare id — a concurrent create may have reused it.
	return nil
}

// GetBinding returns the binding for route+endpoint.
func (r *Registry) GetBinding(routeID, endpointID int64) (*Binding, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := r.bindings[bindKey(routeID, endpointID)]
	if !ok {
		return nil, false
	}
	return cloneBinding(b), true
}

// ListBindings returns all bindings.
func (r *Registry) ListBindings() []Binding {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Binding, 0, len(r.bindings))
	for _, b := range r.bindings {
		out = append(out, *cloneBinding(b))
	}
	return out
}

// PublishedCompiled returns the live published compiled version, or nil if unbound.
func (r *Registry) PublishedCompiled(routeID, endpointID int64) (*Compiled, int64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := r.bindings[bindKey(routeID, endpointID)]
	if !ok || b.PublishedID == 0 {
		return nil, 0, nil
	}
	s := r.sets[b.SetID]
	if s == nil {
		return nil, 0, fmt.Errorf("set missing")
	}
	if s.State != LifecycleActive {
		return nil, 0, nil
	}
	for i := range s.History {
		if s.History[i].ID == b.PublishedID {
			version := s.History[i]
			version.Rules = append([]Rule(nil), version.Rules...)
			c, err := Compile(version)
			if c != nil {
				c.reqBudget = time.Duration(r.requestMs) * time.Millisecond
				c.sseBudget = time.Duration(r.sseMs) * time.Millisecond
			}
			return c, b.PublishedID, err
		}
	}
	return nil, 0, fmt.Errorf("published version missing")
}

// ShadowCompiled returns shadow version for side-channel diff only.
func (r *Registry) ShadowCompiled(routeID, endpointID int64) (*Compiled, int64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := r.bindings[bindKey(routeID, endpointID)]
	if !ok || b.ShadowID == 0 {
		return nil, 0, nil
	}
	s := r.sets[b.SetID]
	if s == nil {
		return nil, 0, fmt.Errorf("set missing")
	}
	if s.State != LifecycleActive {
		return nil, 0, nil
	}
	for i := range s.History {
		if s.History[i].ID == b.ShadowID {
			version := s.History[i]
			version.Rules = append([]Rule(nil), version.Rules...)
			c, err := Compile(version)
			if c != nil {
				c.reqBudget = time.Duration(r.requestMs) * time.Millisecond
				c.sseBudget = time.Duration(r.sseMs) * time.Millisecond
			}
			return c, b.ShadowID, err
		}
	}
	return nil, 0, fmt.Errorf("shadow version missing")
}

// RecordExecution stores a redacted execution diagnostic.
func (r *Registry) RecordExecution(rec ExecutionRecord) ExecutionRecord {
	return r.record(rec)
}

func (r *Registry) record(rec ExecutionRecord) ExecutionRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	seq := r.execSeq.Add(1)
	rec.sequence = seq
	if rec.ID == "" {
		rec.ID = time.Now().UTC().Format("20060102T150405") + "-" + strconv.FormatUint(seq, 10)
	}
	if rec.At.IsZero() {
		rec.At = time.Now().UTC()
	}
	// Defense in depth: never persist obvious secret-shaped payloads in diagnostics.
	rec.DiffSummary = stripSecretPlaceholders(rec.DiffSummary)
	rec.Error = stripSecretPlaceholders(rec.Error)
	r.execs = append([]ExecutionRecord{rec}, r.execs...)
	if len(r.execs) > r.execCap {
		r.execs = r.execs[:r.execCap]
	}
	return rec
}

func stripSecretPlaceholders(s string) string {
	if s == "" {
		return s
	}
	return secretPlaceholderRE.ReplaceAllString(s, "{{SECRET:[REDACTED]}}")
}

// ListExecutions returns newest-first records.
func (r *Registry) ListExecutions(limit int) []ExecutionRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if limit <= 0 || limit > len(r.execs) {
		limit = len(r.execs)
	}
	out := make([]ExecutionRecord, limit)
	copy(out, r.execs[:limit])
	return out
}

func cloneSet(s *Set) *Set {
	cp := *s
	if s.Draft != nil {
		d := *s.Draft
		d.Rules = append([]Rule(nil), s.Draft.Rules...)
		cp.Draft = &d
	}
	cp.History = append([]Version(nil), s.History...)
	for i := range cp.History {
		cp.History[i].Rules = append([]Rule(nil), s.History[i].Rules...)
	}
	return &cp
}

func cloneBinding(b *Binding) *Binding {
	cp := *b
	return &cp
}
