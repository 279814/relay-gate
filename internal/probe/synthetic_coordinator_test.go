package probe

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

type resumeSpy struct {
	prepares atomic.Int32
	resumes  atomic.Int32
}

func (r *resumeSpy) PrepareResume()   { r.prepares.Add(1) }
func (r *resumeSpy) ResumeGradually() { r.resumes.Add(1) }

func TestSyntheticCoordinator_RejectsWhenClosed(t *testing.T) {
	c := NewSyntheticCoordinator(model.RunStatePaused)
	_, _, err := c.AcquireSynthetic(context.Background(), model.TriggerScheduled)
	if !errors.Is(err, ErrSyntheticClosed) {
		t.Fatalf("paused 应拒绝，got %v", err)
	}
	_, _, err = c.AcquireSynthetic(context.Background(), model.TriggerRealTraffic)
	if !errors.Is(err, ErrRealTrafficNoLease) {
		t.Fatalf("真实流量应 ErrRealTrafficNoLease，got %v", err)
	}
}

func TestSyntheticCoordinator_CancelClosesThenDrains(t *testing.T) {
	c := NewSyntheticCoordinator(model.RunStateRunning)
	ctx, release, err := c.AcquireSynthetic(context.Background(), model.TriggerManual)
	if err != nil {
		t.Fatal(err)
	}
	blocked := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		close(blocked)
		// 模拟慢 drain：稍后再 release
		time.Sleep(30 * time.Millisecond)
		release()
	}()

	drainCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.CancelSynthetic(drainCtx, context.Canceled); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocked:
	default:
		t.Fatal("Cancel 应先广播 cancel")
	}
	wg.Wait()
	if c.AdmissionOpen() {
		t.Fatal("Cancel 后 admission 应关闭")
	}
	_, _, err = c.AcquireSynthetic(context.Background(), model.TriggerScheduled)
	if !errors.Is(err, ErrSyntheticClosed) {
		t.Fatal("新 Acquire 应被拒绝")
	}
}

func TestSyntheticCoordinator_ConcurrentAcquireOrReject(t *testing.T) {
	c := NewSyntheticCoordinator(model.RunStateRunning)
	var acquired, rejected atomic.Int32
	var holds []func()
	var mu sync.Mutex

	var start sync.WaitGroup
	start.Add(1)
	var workers sync.WaitGroup
	for i := 0; i < 50; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			start.Wait()
			_, rel, err := c.AcquireSynthetic(context.Background(), model.TriggerCalibration)
			if err != nil {
				rejected.Add(1)
				return
			}
			acquired.Add(1)
			mu.Lock()
			holds = append(holds, rel)
			mu.Unlock()
		}()
	}
	go func() {
		start.Wait()
		_ = c.CancelSynthetic(context.Background(), context.Canceled)
	}()
	start.Done()
	workers.Wait()
	for _, rel := range holds {
		rel()
	}
	if acquired.Load()+rejected.Load() != 50 {
		t.Fatalf("acquired+rejected=%d+%d", acquired.Load(), rejected.Load())
	}
	// 不得有「admission 开着却拿不到、也不是拒绝」—— 上面两路径已穷尽。
}

func TestSyntheticCoordinator_ResumeDelegates(t *testing.T) {
	c := NewSyntheticCoordinator(model.RunStatePaused)
	spy := &resumeSpy{}
	if err := c.BindResumeTarget(spy); err != nil {
		t.Fatal(err)
	}
	if err := c.BindResumeTarget(spy); err == nil {
		t.Fatal("重复绑定应失败")
	}
	c.PrepareResume()
	if spy.prepares.Load() != 1 {
		t.Fatal("PrepareResume 应委托")
	}
	if c.AdmissionOpen() {
		t.Fatal("PrepareResume 不得打开 admission")
	}
	c.ResumeGradually()
	if !c.AdmissionOpen() || spy.resumes.Load() != 1 {
		t.Fatal("ResumeGradually 应打开 admission 并委托")
	}
}

func TestSyntheticCoordinator_ReleaseIdempotent(t *testing.T) {
	c := NewSyntheticCoordinator(model.RunStateRunning)
	_, rel, err := c.AcquireSynthetic(context.Background(), model.TriggerScheduled)
	if err != nil {
		t.Fatal(err)
	}
	rel()
	rel() // 不得 panic / 双重 Done
	c.Close()
}
