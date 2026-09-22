package runstate

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

type memStore struct {
	mu       sync.Mutex
	state    model.RunState
	revision int64
}

func newMemStore(state model.RunState, rev int64) *memStore {
	return &memStore{state: state, revision: rev}
}

func (m *memStore) GetRunStateWithRevision() (model.RunState, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state, m.revision, nil
}

func (m *memStore) SetRunStateWithRevision(v model.RunState, expected int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.revision != expected {
		return 0, errors.New("revision conflict")
	}
	if m.state == v {
		return m.revision, nil
	}
	m.state = v
	m.revision++
	return m.revision, nil
}

type fakeSynth struct {
	mu            sync.Mutex
	cancels       int
	prepares      int
	resumes       int
	cancelErr     error
	cancelPanic   bool
	cancelBlock   chan struct{} // if set, Cancel waits until closed or ctx done
	admitClosed   atomic.Bool
	prepareBefore atomic.Bool // set true when PrepareResume sees Current still paused
	current       func() Snapshot
}

func (f *fakeSynth) CancelSynthetic(ctx context.Context, _ error) error {
	f.admitClosed.Store(true)
	if f.cancelBlock != nil {
		select {
		case <-f.cancelBlock:
		case <-ctx.Done():
			f.mu.Lock()
			f.cancels++
			f.mu.Unlock()
			return ctx.Err()
		}
	}
	if f.cancelPanic {
		panic("drain boom")
	}
	f.mu.Lock()
	f.cancels++
	f.mu.Unlock()
	return f.cancelErr
}

func (f *fakeSynth) PrepareResume() {
	if f.current != nil && f.current().State == model.RunStatePaused {
		f.prepareBefore.Store(true)
	}
	f.mu.Lock()
	f.prepares++
	f.mu.Unlock()
}

func (f *fakeSynth) ResumeGradually() {
	f.mu.Lock()
	f.resumes++
	f.mu.Unlock()
}

func TestController_LoadAndIdempotentSet(t *testing.T) {
	st := newMemStore(model.RunStateRunning, 1)
	c, err := NewController(st)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	synth := &fakeSynth{}
	if err := c.BindSyntheticController(synth); err != nil {
		t.Fatal(err)
	}
	if got := c.Current(); got.State != model.RunStateRunning || got.Revision != 1 {
		t.Fatalf("Current=%+v", got)
	}
	snap, err := c.Set(context.Background(), model.RunStateRunning, 1)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Revision != 1 {
		t.Fatalf("idempotent set 不应增 revision，got %d", snap.Revision)
	}
	if synth.cancels != 0 || synth.prepares != 0 {
		t.Fatal("相同状态不得触发 cancel/prepare")
	}
}

func TestController_PausePublishesThenDrains(t *testing.T) {
	st := newMemStore(model.RunStateRunning, 1)
	c, err := NewController(st)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	synth := &fakeSynth{}
	_ = c.BindSyntheticController(synth)

	snap, err := c.Set(context.Background(), model.RunStatePaused, 1)
	if err != nil {
		t.Fatal(err)
	}
	if snap.State != model.RunStatePaused || snap.Revision != 2 {
		t.Fatalf("snap=%+v", snap)
	}
	if c.Current().State != model.RunStatePaused {
		t.Fatal("Current 应立即为 paused")
	}
	if !synth.admitClosed.Load() || synth.cancels != 1 {
		t.Fatal("应关闭 admission 并 Cancel 一次")
	}
}

func TestController_ResumePrepareWhileStillPaused(t *testing.T) {
	st := newMemStore(model.RunStatePaused, 2)
	c, err := NewController(st)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	synth := &fakeSynth{current: c.Current}
	_ = c.BindSyntheticController(synth)

	var sawRunningDuringPrepare atomic.Bool
	synth.current = func() Snapshot {
		s := c.Current()
		if s.State == model.RunStateRunning {
			sawRunningDuringPrepare.Store(true)
		}
		return s
	}
	// 覆盖 PrepareResume 钩子：在 Prepare 内检查 Current。
	orig := synth
	wrapped := &prepareWatch{fakeSynth: orig, ctrl: c, saw: &sawRunningDuringPrepare}
	c.mu.Lock()
	c.synth = wrapped
	c.mu.Unlock()

	snap, err := c.Set(context.Background(), model.RunStateRunning, 2)
	if err != nil {
		t.Fatal(err)
	}
	if snap.State != model.RunStateRunning {
		t.Fatal(snap)
	}
	if sawRunningDuringPrepare.Load() {
		t.Fatal("PrepareResume 期间不得已可见 running")
	}
	if wrapped.prepares != 1 || wrapped.resumes != 1 {
		t.Fatalf("prepare=%d resume=%d", wrapped.prepares, wrapped.resumes)
	}
}

type prepareWatch struct {
	*fakeSynth
	ctrl *Controller
	saw  *atomic.Bool
}

func (p *prepareWatch) PrepareResume() {
	if p.ctrl.Current().State == model.RunStateRunning {
		p.saw.Store(true)
	}
	p.fakeSynth.PrepareResume()
}

func TestController_PauseDrainPendingAndOldRevision409(t *testing.T) {
	st := newMemStore(model.RunStateRunning, 1)
	c, err := NewController(st)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.drainRetry = 50 * time.Millisecond

	block := make(chan struct{})
	synth := &fakeSynth{cancelBlock: block}
	_ = c.BindSyntheticController(synth)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	snap, err := c.Set(ctx, model.RunStatePaused, 1)
	var pending *TransitionPendingError
	if !errors.As(err, &pending) || pending.Code != PauseDrainPendingCode {
		t.Fatalf("期望 pause_drain_pending，got %v", err)
	}
	if snap.State != model.RunStatePaused || c.Current().State != model.RunStatePaused {
		t.Fatal("Current/返回必须保持 paused")
	}
	if !c.PauseDrainPending() {
		t.Fatal("应标记 drain pending")
	}

	// 旧 revision 重放 → 冲突
	_, err = c.Set(context.Background(), model.RunStatePaused, 1)
	if !RevisionConflict(err) {
		t.Fatalf("旧 revision 应为 conflict，got %v", err)
	}

	// 同 revision 重建 pending
	_, err = c.Set(context.Background(), model.RunStatePaused, snap.Revision)
	if !errors.As(err, &pending) {
		t.Fatalf("drain 未完成时应可重建 pending，got %v", err)
	}

	close(block)
	deadline := time.Now().Add(2 * time.Second)
	for c.PauseDrainPending() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if c.PauseDrainPending() {
		t.Fatal("后台 drain 应最终清除 pending")
	}
}

func TestController_BindOnceAndFailClosed(t *testing.T) {
	st := newMemStore(model.RunStateRunning, 1)
	c, err := NewController(st)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Set(context.Background(), model.RunStatePaused, 1); !errors.Is(err, ErrNotBound) {
		t.Fatalf("未绑定应失败，got %v", err)
	}
	s := &fakeSynth{}
	if err := c.BindSyntheticController(s); err != nil {
		t.Fatal(err)
	}
	if err := c.BindSyntheticController(s); !errors.Is(err, ErrAlreadyBound) {
		t.Fatalf("重复绑定应失败，got %v", err)
	}
	if err := c.BindSyntheticController(nil); err == nil {
		t.Fatal("nil 绑定应失败")
	}
}
