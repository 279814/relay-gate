package probe

import (
	"context"
	"math/rand"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/runstate"
	"github.com/279814/relay-gate/internal/store"
)

func TestP012_LazyZeroSyntheticAcrossTicks(t *testing.T) {
	var hits atomic.Int32
	hs := newSchedHarness(t, 2, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(200)
	})
	for _, up := range hs.cfg.snap.Upstreams {
		up.ProbeMode = model.ProbeModeLazy
	}
	for i := 0; i < 5; i++ {
		hs.sched.tick(context.Background())
		hs.sched.wg.Wait()
	}
	hs.sched.PrepareResume()
	hs.sched.ResumeGradually()
	hs.sched.tick(context.Background())
	hs.sched.wg.Wait()
	if hits.Load() != 0 {
		t.Fatalf("Lazy 不得有合成 RoundTrip，实际 %d", hits.Load())
	}
}

func TestP012_ScheduleKeyPendingCoalesces(t *testing.T) {
	sched, track, _ := invHarness()
	sched.mu.Lock()
	sched.inflightL2[100] = true
	sched.mu.Unlock()
	for i := 0; i < 100; i++ {
		sched.Trigger(ScheduleKey{
			UpstreamID: 10, ScopeType: model.RecipeScopeRoute, ScopeID: 100,
			Endpoint: model.EndpointMessages,
		}, ScheduleConfig)
	}
	p := sched.ensureP012()
	p.mu.Lock()
	pending := p.pendingL2[100]
	p.mu.Unlock()
	if !pending {
		t.Fatal("在途期间 Trigger 应只形成一个 pending")
	}
	track.mu.Lock()
	n := len(track.triggered)
	track.mu.Unlock()
	if n != 0 {
		t.Fatalf("在途时不应立即 TriggerL2，实际 %d", n)
	}
	sched.mu.Lock()
	delete(sched.inflightL2, 100)
	sched.mu.Unlock()
	sched.noteL2Finished(100)
	track.mu.Lock()
	n = len(track.triggered)
	track.mu.Unlock()
	if n != 1 {
		t.Fatalf("完成后最多补一次，实际 TriggerL2=%d", n)
	}
}

func TestP012_JitterRangeReproducible(t *testing.T) {
	sched := NewScheduler(&fakeCfg{state: store.StateRunning}, newFakeTransport(),
		newRecordingTracker(), health.NewUpstreamGate(), discardLogger()).
		WithRNG(rand.New(rand.NewSource(42)))
	a := make([]float64, 20)
	for i := range a {
		a[i] = sched.jitterFactor()
		if a[i] < 0.9 || a[i] > 1.1 {
			t.Fatalf("jitter %v 超出 [0.9,1.1]", a[i])
		}
	}
	sched2 := NewScheduler(&fakeCfg{state: store.StateRunning}, newFakeTransport(),
		newRecordingTracker(), health.NewUpstreamGate(), discardLogger()).
		WithRNG(rand.New(rand.NewSource(42)))
	for i := range a {
		if got := sched2.jitterFactor(); got != a[i] {
			t.Fatalf("固定 RNG 应可复现：i=%d want %v got %v", i, a[i], got)
		}
	}
}

func TestP012_ResumePrepareBeforeRunningVisible(t *testing.T) {
	storeMem := &memRunStore{state: model.RunStatePaused, rev: 2}
	ctrl, err := runstate.NewController(storeMem)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	coord := NewSyntheticCoordinator(model.RunStatePaused)
	track := newRecordingTracker()
	sched := NewScheduler(&fakeCfg{state: store.StatePaused}, newFakeTransport(),
		track, health.NewUpstreamGate(), discardLogger())
	watch := &resumeGateWatch{Scheduler: sched, ctrl: ctrl, saw: &atomic.Bool{}}
	if err := coord.BindResumeTarget(watch); err != nil {
		t.Fatal(err)
	}
	if err := ctrl.BindSyntheticController(coord); err != nil {
		t.Fatal(err)
	}
	_, err = ctrl.Set(context.Background(), model.RunStateRunning, 2)
	if err != nil {
		t.Fatal(err)
	}
	if watch.saw.Load() {
		t.Fatal("PrepareResume 期间不得可见 running")
	}
	if track.resets < 1 {
		t.Fatal("PrepareResume 应 DemotePositive")
	}
}

type memRunStore struct {
	mu    sync.Mutex
	state model.RunState
	rev   int64
}

func (m *memRunStore) GetRunStateWithRevision() (model.RunState, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state, m.rev, nil
}

func (m *memRunStore) SetRunStateWithRevision(v model.RunState, expected int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rev != expected {
		return 0, store.ErrRevisionConflict
	}
	if m.state == v {
		return m.rev, nil
	}
	m.state = v
	m.rev++
	return m.rev, nil
}

type resumeGateWatch struct {
	*Scheduler
	ctrl *runstate.Controller
	saw  *atomic.Bool
}

func (w *resumeGateWatch) PrepareResume() {
	if w.ctrl.Current().State == model.RunStateRunning {
		w.saw.Store(true)
	}
	w.Scheduler.PrepareResume()
}

func TestP012_StablePiggybackEventID(t *testing.T) {
	a := StablePiggybackEventID("2026-09-22", model.EndpointMessages, 1, 2, "tok")
	b := StablePiggybackEventID("2026-09-22", model.EndpointMessages, 1, 2, "tok")
	c := StablePiggybackEventID("2026-09-22", model.EndpointMessages, 1, 2, "other")
	if a != b {
		t.Fatal("相同输入应稳定")
	}
	if a == c {
		t.Fatal("token 变化应改变 event ID")
	}
}
