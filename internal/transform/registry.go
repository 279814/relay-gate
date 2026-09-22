package transform

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// CreateSet adds a named empty transform set with an empty draft shell.
func (r *Registry) CreateSet(name string) (*Set, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("name required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextSet.Add(1) - 1
	s := &Set{
		ID:        id,
		Name:      name,
		CreatedAt: time.Now().UTC(),
		Draft: &Version{
			ID:            r.nextVer.Add(1) - 1,
			SetID:         id,
			Revision:      1,
			CreatedAt:     time.Now().UTC(),
			Rules:         nil,
			ReqFailPolicy: FailClosed,
			ResFailPolicy: FailOpen,
		},
	}
	r.sets[id] = s
	if err := r.flushLocked(); err != nil {
		delete(r.sets, id)
		return nil, err
	}
	return cloneSet(s), nil
}

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

// UpdateDraft replaces draft rules after compile validation.
func (r *Registry) UpdateDraft(setID int64, rules []Rule, reqPolicy, resPolicy, note string) (*Set, error) {
	v := Version{
		Rules:         append([]Rule(nil), rules...),
		ReqFailPolicy: reqPolicy,
		ResFailPolicy: resPolicy,
		Note:          note,
	}
	if _, err := Compile(v); err != nil && len(rules) > 0 {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sets[setID]
	if !ok {
		return nil, fmt.Errorf("transform set %d not found", setID)
	}
	if s.Draft == nil {
		s.Draft = &Version{SetID: setID}
	}
	s.Draft.ID = r.nextVer.Add(1) - 1
	s.Draft.Revision++
	s.Draft.CreatedAt = time.Now().UTC()
	s.Draft.Rules = append([]Rule(nil), rules...)
	if reqPolicy != "" {
		s.Draft.ReqFailPolicy = reqPolicy
	}
	if resPolicy != "" {
		s.Draft.ResFailPolicy = resPolicy
	}
	s.Draft.Note = note
	if err := r.flushLocked(); err != nil {
		return nil, err
	}
	return cloneSet(s), nil
}

// Preview compiles the draft and applies it in-memory (no binding change).
func (r *Registry) Preview(setID int64, phase string, req RequestInput, res ResponseInput) (map[string]any, error) {
	r.mu.RLock()
	s, ok := r.sets[setID]
	if !ok || s.Draft == nil {
		r.mu.RUnlock()
		return nil, fmt.Errorf("transform set %d draft not found", setID)
	}
	draft := *s.Draft
	r.mu.RUnlock()
	if len(draft.Rules) == 0 {
		return nil, fmt.Errorf("draft has no rules")
	}
	c, err := Compile(draft)
	if err != nil {
		return nil, err
	}
	summary := c.ShadowDiff(phase, req, res)
	rec := r.record(ExecutionRecord{
		RouteID:     0,
		EndpointID:  0,
		VersionID:   draft.ID,
		Mode:        "preview",
		Phase:       phase,
		OK:          true,
		DiffSummary: summary,
		InputHash:   HashBytes(req.Body),
	})
	return map[string]any{"summary": summary, "execution": rec}, nil
}

// PublishSnapshot freezes the current draft into an immutable history version
// and optionally points the binding's published pointer at it.
func (r *Registry) PublishSnapshot(setID, routeID, endpointID int64) (*Binding, *Version, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sets[setID]
	if !ok || s.Draft == nil || len(s.Draft.Rules) == 0 {
		return nil, nil, fmt.Errorf("draft empty or set missing")
	}
	if _, err := Compile(*s.Draft); err != nil {
		return nil, nil, err
	}
	snap := *s.Draft
	snap.ID = r.nextVer.Add(1) - 1
	snap.CreatedAt = time.Now().UTC()
	snap.Rules = append([]Rule(nil), s.Draft.Rules...)
	s.History = append(s.History, snap)

	key := bindKey(routeID, endpointID)
	b := r.bindings[key]
	if b == nil {
		b = &Binding{RouteID: routeID, EndpointID: endpointID, SetID: setID}
		r.bindings[key] = b
	}
	if b.SetID != 0 && b.SetID != setID {
		return nil, nil, fmt.Errorf("binding already uses set %d", b.SetID)
	}
	b.SetID = setID
	b.PublishedID = snap.ID
	b.Revision++
	if err := r.flushLocked(); err != nil {
		return nil, nil, err
	}
	return cloneBinding(b), &snap, nil
}

// ShadowSnapshot points shadow at a frozen draft copy (bypass live traffic).
func (r *Registry) ShadowSnapshot(setID, routeID, endpointID int64) (*Binding, *Version, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sets[setID]
	if !ok || s.Draft == nil || len(s.Draft.Rules) == 0 {
		return nil, nil, fmt.Errorf("draft empty or set missing")
	}
	if _, err := Compile(*s.Draft); err != nil {
		return nil, nil, err
	}
	snap := *s.Draft
	snap.ID = r.nextVer.Add(1) - 1
	snap.CreatedAt = time.Now().UTC()
	snap.Rules = append([]Rule(nil), s.Draft.Rules...)
	s.History = append(s.History, snap)

	key := bindKey(routeID, endpointID)
	b := r.bindings[key]
	if b == nil {
		b = &Binding{RouteID: routeID, EndpointID: endpointID, SetID: setID}
		r.bindings[key] = b
	}
	if b.SetID != 0 && b.SetID != setID {
		return nil, nil, fmt.Errorf("binding already uses set %d", b.SetID)
	}
	b.SetID = setID
	b.ShadowID = snap.ID
	b.Revision++
	if err := r.flushLocked(); err != nil {
		return nil, nil, err
	}
	return cloneBinding(b), &snap, nil
}

// Rollback sets published pointer to a prior history version id.
func (r *Registry) Rollback(routeID, endpointID, versionID int64) (*Binding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := bindKey(routeID, endpointID)
	b := r.bindings[key]
	if b == nil {
		return nil, fmt.Errorf("binding not found")
	}
	s := r.sets[b.SetID]
	if s == nil {
		return nil, fmt.Errorf("set missing")
	}
	found := false
	for _, h := range s.History {
		if h.ID == versionID {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("version %d not in history", versionID)
	}
	b.PublishedID = versionID
	b.Revision++
	if err := r.flushLocked(); err != nil {
		return nil, err
	}
	return cloneBinding(b), nil
}

// ClearPublished disables live transforms for the binding (passthrough).
func (r *Registry) ClearPublished(routeID, endpointID int64) (*Binding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := bindKey(routeID, endpointID)
	b := r.bindings[key]
	if b == nil {
		return nil, fmt.Errorf("binding not found")
	}
	b.PublishedID = 0
	b.Revision++
	if err := r.flushLocked(); err != nil {
		return nil, err
	}
	return cloneBinding(b), nil
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
	for i := range s.History {
		if s.History[i].ID == b.PublishedID {
			c, err := Compile(s.History[i])
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
	for i := range s.History {
		if s.History[i].ID == b.ShadowID {
			c, err := Compile(s.History[i])
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
	if rec.ID == "" {
		rec.ID = time.Now().UTC().Format("20060102T150405") + "-" + strconv.FormatUint(seq, 10)
	}
	if rec.At.IsZero() {
		rec.At = time.Now().UTC()
	}
	r.execs = append([]ExecutionRecord{rec}, r.execs...)
	if len(r.execs) > r.execCap {
		r.execs = r.execs[:r.execCap]
	}
	return rec
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
