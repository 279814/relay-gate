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

// Upstream network-origin change (§9.2) must Forget child RouteHealth: an old
// alive verdict must not keep selecting routes for the new host.
func TestSemanticInvalidatorInvalidateUpstreamClearsAliveRouteHealth(t *testing.T) {
	tr, _, _ := newTestTracker(t)
	tr.Report(Report{RouteID: 21, Verdict: VerdictOK, Source: SourceReal})
	tr.Report(Report{RouteID: 22, Verdict: VerdictOK, Source: SourceReal})
	if tr.State(21) != model.StateAlive || tr.State(22) != model.StateAlive {
		t.Fatalf("setup alive: %s %s", tr.State(21), tr.State(22))
	}
	// Unrelated route stays intact.
	tr.Report(Report{RouteID: 99, Verdict: VerdictOK, Source: SourceReal})
	inv := NewSemanticInvalidator(tr, nil, nil, nil, nil)
	inv.InvalidateUpstream(3, []int64{21, 22})
	if tr.State(21) != model.StateUnknown || tr.State(22) != model.StateUnknown {
		t.Fatalf("want forgotten→unknown, got %s %s", tr.State(21), tr.State(22))
	}
	if tr.State(99) != model.StateAlive {
		t.Fatalf("unrelated route must stay alive, got %s", tr.State(99))
	}
}

// ModelName Protocol/Name/probe 变更必须立刻丢掉旧 RouteHealth（§9.2），
// 且不得经 ScheduleClearer 去 TriggerL1（那是站级 /models）。
func TestSemanticInvalidatorInvalidateModelNameClearsHealthWithoutSchedule(t *testing.T) {
	tr, fs, _ := newTestTracker(t)
	fs.s.FailThreshold = 1
	tr.Report(Report{RouteID: 11, Verdict: VerdictUnavailable, Source: SourceL2})
	tr.Report(Report{RouteID: 12, Verdict: VerdictUnavailable, Source: SourceL2})
	if tr.State(11) != model.StateDead || tr.State(12) != model.StateDead {
		t.Fatalf("setup dead: %s %s", tr.State(11), tr.State(12))
	}
	gate := NewRecoveryGate()
	if _, ok := gate.TryAcquire(11); !ok {
		t.Fatal("acquire 11")
	}
	caps := &memCaps{}
	sched := &memSched{}
	inv := NewSemanticInvalidator(tr, gate, caps, sched, nil)
	inv.InvalidateModelName(99, []int64{11, 12})

	if tr.State(11) != model.StateUnknown || tr.State(12) != model.StateUnknown {
		t.Fatalf("want both forgotten→unknown, got %s %s", tr.State(11), tr.State(12))
	}
	if gate.InFlight(11) {
		t.Fatal("recovery gate for route 11 must be forgotten")
	}
	if len(caps.cleared) != 2 {
		t.Fatalf("caps cleared=%v", caps.cleared)
	}
	if len(sched.routes) != 0 {
		t.Fatalf("ModelName invalidate must not call ScheduleClearer (would TriggerL1): %v", sched.routes)
	}
}
