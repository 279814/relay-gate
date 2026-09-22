package health

import (
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

type memCaps struct {
	cleared []int64
}

func (m *memCaps) InvalidateScope(scope model.RecipeScope, scopeID int64) {
	if scope == model.RecipeScopeRoute {
		m.cleared = append(m.cleared, scopeID)
	}
}

type memSched struct {
	routes []int64
}

func (m *memSched) InvalidateRoute(routeID int64) {
	m.routes = append(m.routes, routeID)
}

func TestSemanticInvalidatorClearsTrackerGateCapsSchedule(t *testing.T) {
	tr, fs, _ := newTestTracker(t)
	fs.s.FailThreshold = 1
	tr.Report(Report{RouteID: 7, Verdict: VerdictUnavailable, Source: SourceL2})
	if tr.State(7) != model.StateDead {
		t.Fatalf("setup state=%s", tr.State(7))
	}
	gate := NewRecoveryGate()
	rel, ok := gate.TryAcquire(7)
	if !ok {
		t.Fatal("acquire")
	}
	_ = rel
	caps := &memCaps{}
	sched := &memSched{}
	inv := NewSemanticInvalidator(tr, gate, caps, sched, nil)
	inv.InvalidateRoute(7)
	if tr.State(7) != model.StateUnknown {
		t.Fatalf("tracker state=%s want forgotten→unknown", tr.State(7))
	}
	if gate.InFlight(7) {
		t.Fatal("recovery gate still held")
	}
	if len(caps.cleared) != 1 || caps.cleared[0] != 7 {
		t.Fatalf("caps=%v", caps.cleared)
	}
	if len(sched.routes) != 1 || sched.routes[0] != 7 {
		t.Fatalf("sched=%v", sched.routes)
	}
}
