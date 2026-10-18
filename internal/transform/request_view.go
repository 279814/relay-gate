package transform

import (
	"fmt"
	"time"
)

// RequestView freezes only the candidate Routes of one client request. Missing
// bindings stay missing, even if a version is published before a later retry.
// Versions and budgets are copied under the same Registry read lock; compilation
// remains local to the actual Attempt so an unrelated broken binding is ignored.
type RequestView struct {
	bindings map[string]requestBinding
	budgets  BudgetLimits
}

type requestBinding struct {
	published requestVersion
	shadow    requestVersion
}

type requestVersion struct {
	version Version
	err     error
}

func (r *Registry) CaptureRoutes(routeIDs []int64) *RequestView {
	wanted := make(map[int64]bool, len(routeIDs))
	for _, id := range routeIDs {
		wanted[id] = true
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	view := &RequestView{bindings: make(map[string]requestBinding), budgets: BudgetLimits{RequestMs: r.requestMs, SSEEventMs: r.sseMs}}
	for key, b := range r.bindings {
		if !wanted[b.RouteID] {
			continue
		}
		view.bindings[key] = requestBinding{published: r.captureVersionLocked(b.SetID, b.PublishedID), shadow: r.captureVersionLocked(b.SetID, b.ShadowID)}
	}
	return view
}

func (r *Registry) captureVersionLocked(setID, versionID int64) requestVersion {
	if versionID == 0 {
		return requestVersion{}
	}
	set := r.sets[setID]
	if set == nil {
		return requestVersion{err: fmt.Errorf("set missing")}
	}
	for _, v := range set.History {
		if v.ID == versionID {
			v.Rules = append([]Rule(nil), v.Rules...)
			return requestVersion{version: v}
		}
	}
	return requestVersion{err: fmt.Errorf("transform version missing")}
}

func (v *RequestView) PublishedCompiled(routeID, endpointID int64) (*Compiled, int64, error) {
	if v == nil {
		return nil, 0, nil
	}
	return v.bindings[bindKey(routeID, endpointID)].published.compile(v.budgets)
}

func (v *RequestView) ShadowCompiled(routeID, endpointID int64) (*Compiled, int64, error) {
	if v == nil {
		return nil, 0, nil
	}
	return v.bindings[bindKey(routeID, endpointID)].shadow.compile(v.budgets)
}

func (v requestVersion) compile(budgets BudgetLimits) (*Compiled, int64, error) {
	if v.err != nil || v.version.ID == 0 {
		return nil, 0, v.err
	}
	version := v.version
	version.Rules = append([]Rule(nil), version.Rules...)
	c, err := Compile(version)
	if c != nil {
		c.reqBudget = time.Duration(budgets.RequestMs) * time.Millisecond
		c.sseBudget = time.Duration(budgets.SSEEventMs) * time.Millisecond
	}
	return c, version.ID, err
}
