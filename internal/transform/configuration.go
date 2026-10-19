package transform

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

type LifecycleState string

const (
	LifecycleActive   LifecycleState = "active"
	LifecycleDisabled LifecycleState = "disabled"
	LifecycleArchived LifecycleState = "archived"
)

var (
	ErrRevisionConflict = errors.New("transform revision conflict")
	ErrNotFound         = errors.New("transform resource not found")
	ErrBindingInUse     = errors.New("transform binding belongs to another set")
)

// A write proposal is private to one serialized writer. Request readers keep
// using the last committed maps while SQLite persists this proposal.
type configuration struct {
	sets     map[int64]*Set
	bindings map[string]*Binding
}

func (r *Registry) changeConfiguration(change func(*configuration) (bool, error)) error {
	return r.changeTargetConfiguration(0, 0, change)
}

func (r *Registry) changeTargetConfiguration(routeID, endpointID int64, change func(*configuration) (bool, error)) error {
	r.writerMu.Lock()
	defer r.writerMu.Unlock()
	candidate := &configuration{sets: make(map[int64]*Set), bindings: make(map[string]*Binding)}
	r.mu.RLock()
	for id, set := range r.sets {
		candidate.sets[id] = cloneSet(set)
	}
	for key, binding := range r.bindings {
		candidate.bindings[key] = cloneBinding(binding)
	}
	r.mu.RUnlock()
	changed, err := change(candidate)
	if err != nil || !changed {
		return err
	}
	if r.persist != nil {
		sets := make([]Set, 0, len(candidate.sets))
		for _, set := range candidate.sets {
			sets = append(sets, *cloneSet(set))
		}
		bindings := make([]Binding, 0, len(candidate.bindings))
		for _, binding := range candidate.bindings {
			bindings = append(bindings, *cloneBinding(binding))
		}
		var err error
		if sink, ok := r.persist.(TargetPersistSink); ok && routeID > 0 && endpointID > 0 {
			err = sink.SaveTransformSnapshotForTarget(sets, bindings, routeID, endpointID)
		} else {
			err = r.persist.SaveTransformSnapshot(sets, bindings)
		}
		if err != nil {
			return fmt.Errorf("%w: %w", ErrPersist, err)
		}
	}
	r.mu.Lock()
	r.sets, r.bindings = candidate.sets, candidate.bindings
	r.mu.Unlock()
	return nil
}

func (r *Registry) CreateSet(name string) (result *Set, err error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("name required")
	}
	if len(name) > 256 {
		return nil, fmt.Errorf("name must be at most 256 bytes")
	}
	err = r.changeConfiguration(func(c *configuration) (bool, error) {
		id := r.nextSet.Add(1) - 1
		set := &Set{ID: id, Name: name, Revision: 1, State: LifecycleActive, CreatedAt: time.Now().UTC(), Draft: &Version{ID: r.nextVer.Add(1) - 1, SetID: id, Revision: 1, CreatedAt: time.Now().UTC(), ReqFailPolicy: FailClosed, ResFailPolicy: FailOpen}}
		c.sets[id] = set
		result = cloneSet(set)
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// UpdateDraft remains a trusted programmatic setup entry. Administrative
// mutations use UpdateDraftAtRevision and never obtain a newer revision here.
func (r *Registry) UpdateDraft(setID int64, rules []Rule, reqPolicy, resPolicy, note string) (*Set, error) {
	return r.updateDraft(setID, nil, rules, reqPolicy, resPolicy, note)
}
func (r *Registry) UpdateDraftAtRevision(setID, expectedRevision int64, rules []Rule, reqPolicy, resPolicy, note string) (*Set, error) {
	if expectedRevision < 1 {
		return nil, fmt.Errorf("expected_revision must be positive")
	}
	return r.updateDraft(setID, &expectedRevision, rules, reqPolicy, resPolicy, note)
}
func (r *Registry) updateDraft(setID int64, expected *int64, rules []Rule, reqPolicy, resPolicy, note string) (result *Set, err error) {
	version := Version{Rules: append([]Rule(nil), rules...), ReqFailPolicy: reqPolicy, ResFailPolicy: resPolicy, Note: note}
	if _, err := Compile(version); err != nil && len(rules) > 0 {
		return nil, err
	}
	err = r.changeConfiguration(func(c *configuration) (bool, error) {
		set := c.sets[setID]
		if set == nil {
			return false, ErrNotFound
		}
		if expected != nil && set.Revision != *expected {
			return false, ErrRevisionConflict
		}
		if set.State == LifecycleArchived {
			return false, fmt.Errorf("archived transform cannot be edited")
		}
		draft := Version{SetID: setID}
		if set.Draft != nil {
			draft = *set.Draft
		}
		draft.ID = r.nextVer.Add(1) - 1
		draft.Revision++
		draft.CreatedAt = time.Now().UTC()
		draft.Rules = append([]Rule(nil), rules...)
		if reqPolicy != "" {
			draft.ReqFailPolicy = reqPolicy
		}
		if resPolicy != "" {
			draft.ResFailPolicy = resPolicy
		}
		draft.Note = note
		set.Draft = &draft
		set.Revision++
		result = cloneSet(set)
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

type PublishPreconditions struct {
	SetRevision     int64
	BindingRevision int64
}
type Publication struct {
	Binding     *Binding `json:"binding"`
	Version     *Version `json:"version"`
	SetRevision int64    `json:"set_revision"`
}

func (r *Registry) PublishSnapshot(setID, routeID, endpointID int64) (*Binding, *Version, error) {
	result, err := r.publish(setID, routeID, endpointID, "published", nil)
	if err != nil {
		return nil, nil, err
	}
	return result.Binding, result.Version, nil
}
func (r *Registry) ShadowSnapshot(setID, routeID, endpointID int64) (*Binding, *Version, error) {
	result, err := r.publish(setID, routeID, endpointID, "shadow", nil)
	if err != nil {
		return nil, nil, err
	}
	return result.Binding, result.Version, nil
}
func (r *Registry) PublishAtRevision(setID, routeID, endpointID int64, shadow bool, expected PublishPreconditions) (*Publication, error) {
	if expected.SetRevision < 1 || expected.BindingRevision < 0 {
		return nil, fmt.Errorf("expected set revision must be positive and binding revision nonnegative")
	}
	mode := "published"
	if shadow {
		mode = "shadow"
	}
	return r.publish(setID, routeID, endpointID, mode, &expected)
}
func (r *Registry) publish(setID, routeID, endpointID int64, mode string, expected *PublishPreconditions) (result *Publication, err error) {
	if routeID < 1 || endpointID < 1 {
		return nil, fmt.Errorf("route_id and endpoint_id must be positive")
	}
	guardRoute, guardEndpoint := int64(0), int64(0)
	if expected != nil {
		guardRoute, guardEndpoint = routeID, endpointID
	}
	err = r.changeTargetConfiguration(guardRoute, guardEndpoint, func(c *configuration) (bool, error) {
		set := c.sets[setID]
		if set == nil {
			return false, ErrNotFound
		}
		if expected != nil && set.Revision != expected.SetRevision {
			return false, ErrRevisionConflict
		}
		if set.State != LifecycleActive {
			return false, fmt.Errorf("only active transforms can be published or shadowed")
		}
		if set.Draft == nil || len(set.Draft.Rules) == 0 {
			return false, fmt.Errorf("draft empty")
		}
		key := bindKey(routeID, endpointID)
		binding := c.bindings[key]
		current := int64(0)
		if binding != nil {
			current = binding.Revision
		}
		if expected != nil && current != expected.BindingRevision {
			return false, ErrRevisionConflict
		}
		if binding != nil && binding.SetID != 0 && binding.SetID != setID {
			return false, ErrBindingInUse
		}
		if _, err := Compile(*set.Draft); err != nil {
			return false, err
		}
		snapshot := *set.Draft
		snapshot.ID = r.nextVer.Add(1) - 1
		snapshot.CreatedAt = time.Now().UTC()
		snapshot.Rules = append([]Rule(nil), set.Draft.Rules...)
		set.History = append(set.History, snapshot)
		set.Revision++
		if binding == nil {
			binding = &Binding{RouteID: routeID, EndpointID: endpointID, SetID: setID}
			c.bindings[key] = binding
		}
		if mode == "shadow" {
			binding.ShadowID = snapshot.ID
		} else {
			binding.PublishedID = snapshot.ID
		}
		binding.Revision++
		resultVersion := snapshot
		resultVersion.Rules = append([]Rule(nil), snapshot.Rules...)
		result = &Publication{Binding: cloneBinding(binding), Version: &resultVersion, SetRevision: set.Revision}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (r *Registry) Rollback(routeID, endpointID, versionID int64) (*Binding, error) {
	return r.setPublished(routeID, endpointID, versionID, nil)
}
func (r *Registry) RollbackAtRevision(routeID, endpointID, versionID, expectedRevision int64) (*Binding, error) {
	if expectedRevision < 1 {
		return nil, fmt.Errorf("expected_revision must be positive")
	}
	return r.setPublished(routeID, endpointID, versionID, &expectedRevision)
}
func (r *Registry) ClearPublished(routeID, endpointID int64) (*Binding, error) {
	return r.setPublished(routeID, endpointID, 0, nil)
}
func (r *Registry) ClearPublishedAtRevision(routeID, endpointID, expectedRevision int64) (*Binding, error) {
	if expectedRevision < 1 {
		return nil, fmt.Errorf("expected_revision must be positive")
	}
	return r.setPublished(routeID, endpointID, 0, &expectedRevision)
}
func (r *Registry) setPublished(routeID, endpointID, versionID int64, expected *int64) (result *Binding, err error) {
	guardRoute, guardEndpoint := int64(0), int64(0)
	if expected != nil {
		guardRoute, guardEndpoint = routeID, endpointID
	}
	err = r.changeTargetConfiguration(guardRoute, guardEndpoint, func(c *configuration) (bool, error) {
		binding := c.bindings[bindKey(routeID, endpointID)]
		if binding == nil {
			return false, ErrNotFound
		}
		if expected != nil && binding.Revision != *expected {
			return false, ErrRevisionConflict
		}
		set := c.sets[binding.SetID]
		if set == nil {
			return false, ErrNotFound
		}
		if set.State != LifecycleActive {
			return false, fmt.Errorf("only active transforms can change published bindings")
		}
		if versionID != 0 {
			found := false
			for _, version := range set.History {
				if version.ID == versionID {
					found = true
					break
				}
			}
			if !found {
				return false, fmt.Errorf("version is not in this transform's immutable history")
			}
		}
		binding.PublishedID = versionID
		binding.Revision++
		result = cloneBinding(binding)
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (r *Registry) SetLifecycleAtRevision(setID, expectedRevision int64, state LifecycleState) (result *Set, err error) {
	if expectedRevision < 1 {
		return nil, fmt.Errorf("expected_revision must be positive")
	}
	if state != LifecycleActive && state != LifecycleDisabled && state != LifecycleArchived {
		return nil, fmt.Errorf("invalid transform lifecycle state")
	}
	err = r.changeConfiguration(func(c *configuration) (bool, error) {
		set := c.sets[setID]
		if set == nil {
			return false, ErrNotFound
		}
		if set.Revision != expectedRevision {
			return false, ErrRevisionConflict
		}
		if set.State == LifecycleArchived && state != LifecycleArchived {
			return false, fmt.Errorf("archived transform is immutable")
		}
		if set.State == state {
			result = cloneSet(set)
			return false, nil
		}
		set.State = state
		set.Revision++
		for _, binding := range c.bindings {
			if binding.SetID == setID {
				binding.Revision++
			}
		}
		result = cloneSet(set)
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (r *Registry) RemoveBindingsForRoute(routeID int64) error {
	if r == nil {
		return nil
	}
	return r.changeConfiguration(func(c *configuration) (bool, error) {
		changed := false
		for key, b := range c.bindings {
			if b.RouteID == routeID {
				delete(c.bindings, key)
				changed = true
			}
		}
		return changed, nil
	})
}
func (r *Registry) RemoveBindingsForEndpoint(endpointID int64) error {
	if r == nil {
		return nil
	}
	return r.changeConfiguration(func(c *configuration) (bool, error) {
		changed := false
		for key, b := range c.bindings {
			if b.EndpointID == endpointID {
				delete(c.bindings, key)
				changed = true
			}
		}
		return changed, nil
	})
}
