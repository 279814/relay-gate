package probe

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/store"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ── 测试替身 ──────────────────────────────────────────────

type fakeCfg struct {
	mu       sync.Mutex
	snap     *router.Snapshot
	settings model.Settings
	state    store.RunState
	// snapErr 让 Snapshot 报错，用于测「配置读不出来时不崩」的路径。
	snapErr error
}

func (f *fakeCfg) Snapshot() (*router.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.snapErr != nil {
		return nil, f.snapErr
	}
	return f.snap, nil
}
func (f *fakeCfg) Settings() (model.Settings, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.settings, nil
}
func (f *fakeCfg) RunState() (store.RunState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state, nil
}
func (f *fakeCfg) setState(s store.RunState) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state = s
}

// fakeTransport 直接用默认 Transport，靶站是真的 httptest 服务器。
type fakeTransport struct{}

func (fakeTransport) TransportFor(*model.Upstream, model.Settings) (*http.Transport, error) {
	return http.DefaultTransport.(*http.Transport), nil
}

// recordingTracker 记录调度器对状态机的每次调用。
//
// 用假实现而不是真 Tracker：这里要断言的是「谁在什么时候被探」，
// 而真 Tracker 会把这些淹没在状态转换逻辑里。
type recordingTracker struct {
	mu sync.Mutex

	l1Allowed map[int64]bool // ClaimL1 放行哪些 Route（nil 表示全放行）
	l2Allowed map[int64]bool
	states    map[int64]model.HealthState

	l1Claims []int64
	l2Claims []int64
	reports  []health.Report
	// triggered 记 TriggerL2，triggeredL1 记 TriggerL1。分开记是必要的：
	// InvalidateModelName 的正确性正是「只清 L2、不动 L1」（L1 打的是站的
	// /v1/models，与模型无关），混在一个 slice 里就断言不了这件事。
	triggered   []int64
	triggeredL1 []int64
	resets      int
}

func newRecordingTracker() *recordingTracker {
	return &recordingTracker{states: map[int64]model.HealthState{}}
}

func (r *recordingTracker) ClaimL1(id int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.l1Allowed != nil && !r.l1Allowed[id] {
		return false
	}
	r.l1Claims = append(r.l1Claims, id)
	return true
}

func (r *recordingTracker) ClaimL2(id int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.l2Allowed != nil && !r.l2Allowed[id] {
		return false
	}
	r.l2Claims = append(r.l2Claims, id)
	return true
}

func (r *recordingTracker) TriggerL2(id int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.triggered = append(r.triggered, id)
}

func (r *recordingTracker) TriggerL1(id int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.triggeredL1 = append(r.triggeredL1, id)
}

func (r *recordingTracker) Report(rep health.Report) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reports = append(r.reports, rep)
	return true
}

func (r *recordingTracker) State(id int64) model.HealthState {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.states[id]; ok {
		return s
	}
	return model.StateUnknown
}

func (r *recordingTracker) RetainOnly(map[int64]bool) {}

func (r *recordingTracker) ResetAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resets++
}

func (r *recordingTracker) snapshot() ([]int64, []int64, []health.Report, []int64, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]int64(nil), r.l1Claims...),
		append([]int64(nil), r.l2Claims...),
		append([]health.Report(nil), r.reports...),
		append([]int64(nil), r.triggered...),
		r.resets
}

// schedHarness 起若干靶站并配好调度器。
type schedHarness struct {
	sched *Scheduler
	track *recordingTracker
	gate  *health.UpstreamGate
	cfg   *fakeCfg

	l1Hits map[int64]*int32 // 每个 Upstream 收到的 L1 次数
}

// newSchedHarness 配 n 个站，每站一条 Route，全部指向同一个 handler。
func newSchedHarness(t *testing.T, n int, handler http.HandlerFunc) *schedHarness {
	t.Helper()

	mn := &model.ModelName{ID: 1, Name: "claude-opus-5",
		Protocol: model.ProtoAnthropic, MatchMode: model.MatchExact, Enabled: true}
	mn.Defaults()

	var ups []*model.Upstream
	var routes []*model.Route
	for i := 1; i <= n; i++ {
		srv := httptest.NewServer(handler)
		t.Cleanup(srv.Close)
		ups = append(ups, &model.Upstream{
			ID: int64(i * 10), Name: "up" + string(rune('0'+i)), BaseURL: srv.URL,
			APIKey: "sk-probe-key-abcdefgh", AuthStyle: model.AuthAuto,
			L1Path: "/v1/models", Enabled: true,
		})
		routes = append(routes, &model.Route{
			ID: int64(i * 100), ModelNameID: 1, UpstreamID: int64(i * 10),
			Priority: 1, Weight: 100, Enabled: true,
		})
	}

	cfg := &fakeCfg{
		snap:     router.BuildSnapshot([]*model.ModelName{mn}, ups, routes),
		settings: fastSettings(),
		state:    store.StateRunning,
	}
	track := newRecordingTracker()
	gate := health.NewUpstreamGate()

	return &schedHarness{
		sched: NewScheduler(cfg, fakeTransport{}, track, gate, discardLogger()).WithTargets(testTargets(), nil),
		track: track, gate: gate, cfg: cfg,
	}
}

// ── L1 站级传播 ───────────────────────────────────────────

// L1 失败 → 整站 dead：该 Upstream 下所有 Route 一并标记（§4.1）。
// 这是分两级探测的主要收益，一次零 token 的探测就否决了整站。
func TestScheduler_L1FailurePropagatesToAllRoutes(t *testing.T) {
	mn := &model.ModelName{ID: 1, Name: "claude-opus-5",
		Protocol: model.ProtoAnthropic, MatchMode: model.MatchExact, Enabled: true}
	mn.Defaults()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503) // 整站挂了
	}))
	defer srv.Close()

	up := &model.Upstream{ID: 10, Name: "dead-station", BaseURL: srv.URL,
		APIKey: "sk-probe-key-abcdefgh", AuthStyle: model.AuthAuto,
		L1Path: "/v1/models", Enabled: true}
	// 同一个站下挂 3 条 Route
	routes := []*model.Route{
		{ID: 100, ModelNameID: 1, UpstreamID: 10, Priority: 1, Weight: 100, Enabled: true},
		{ID: 101, ModelNameID: 1, UpstreamID: 10, Priority: 2, Weight: 100, Enabled: true},
		{ID: 102, ModelNameID: 1, UpstreamID: 10, Priority: 3, Weight: 100, Enabled: true},
	}

	cfg := &fakeCfg{
		snap: router.BuildSnapshot([]*model.ModelName{mn},
			[]*model.Upstream{up}, routes),
		settings: fastSettings(),
		state:    store.StateRunning,
	}
	track := newRecordingTracker()
	gate := health.NewUpstreamGate()
	sched := NewScheduler(cfg, fakeTransport{}, track, gate, discardLogger()).WithTargets(testTargets(), nil)

	sched.tick(context.Background())
	sched.wg.Wait()

	_, _, reports, _, _ := track.snapshot()

	got := map[int64]bool{}
	for _, rep := range reports {
		if rep.Source == health.SourceL1 {
			got[rep.RouteID] = true
			if rep.Verdict != health.VerdictUnavailable {
				t.Errorf("503 应判不可用，Route %d 得到 %s", rep.RouteID, rep.Verdict)
			}
		}
	}
	for _, rt := range routes {
		if !got[rt.ID] {
			t.Errorf("L1 失败应传播到该站所有 Route，Route %d 没收到", rt.ID)
		}
	}
	if gate.OK(10) {
		t.Error("L1 失败后站级结论应为不通")
	}
}

// L1 失败时跳过 L2：站都连不上，探模型纯属浪费 token。
func TestScheduler_SkipsL2WhenL1Down(t *testing.T) {
	hs := newSchedHarness(t, 1, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	})

	// 第一轮：L1 失败并记下站级结论
	hs.sched.tick(context.Background())
	hs.sched.wg.Wait()

	// 第二轮：这次应跳过 L2
	before := len(hs.track.l2Claims)
	hs.sched.tick(context.Background())
	hs.sched.wg.Wait()

	if len(hs.track.l2Claims) > before {
		t.Error("站级 L1 失败时不该再探 L2 —— 那是白烧 token")
	}
}

// 同一个站下多条 Route 各自判定 L1 到期，但只该发一次请求。
func TestScheduler_CoalescesL1PerUpstream(t *testing.T) {
	var hits int
	var mu sync.Mutex
	mn := &model.ModelName{ID: 1, Name: "claude-opus-5",
		Protocol: model.ProtoAnthropic, MatchMode: model.MatchExact, Enabled: true}
	mn.Defaults()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			mu.Lock()
			hits++
			mu.Unlock()
			w.WriteHeader(200)
			return
		}
		drainBody(r)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(aliveSSE))
	}))
	defer srv.Close()

	up := &model.Upstream{ID: 10, Name: "shared", BaseURL: srv.URL,
		APIKey: "sk-probe-key-abcdefgh", AuthStyle: model.AuthAuto,
		L1Path: "/v1/models", Enabled: true}
	var routes []*model.Route
	for i := 0; i < 5; i++ {
		routes = append(routes, &model.Route{
			ID: int64(100 + i), ModelNameID: 1, UpstreamID: 10,
			Priority: 1, Weight: 100, Enabled: true,
		})
	}

	cfg := &fakeCfg{
		snap:     router.BuildSnapshot([]*model.ModelName{mn}, []*model.Upstream{up}, routes),
		settings: fastSettings(),
		state:    store.StateRunning,
	}
	sched := NewScheduler(cfg, fakeTransport{}, newRecordingTracker(),
		health.NewUpstreamGate(), discardLogger()).WithTargets(testTargets(), nil)

	sched.tick(context.Background())
	sched.wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if hits != 1 {
		t.Errorf("5 条 Route 共享一个站，L1 只该打 1 次，实际打了 %d 次", hits)
	}
}

// ── L1 转通触发 L2（§4.4b）───────────────────────────────

// 站级恢复的发现延迟应收敛到 L1 周期，而不是等 L2 自己的周期。
func TestScheduler_L1RecoveryTriggersDeadRoutesL2(t *testing.T) {
	var down = true
	var mu sync.Mutex

	mn := &model.ModelName{ID: 1, Name: "claude-opus-5",
		Protocol: model.ProtoAnthropic, MatchMode: model.MatchExact, Enabled: true}
	mn.Defaults()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		isDown := down
		mu.Unlock()
		if isDown {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	up := &model.Upstream{ID: 10, Name: "flappy", BaseURL: srv.URL,
		APIKey: "sk-probe-key-abcdefgh", AuthStyle: model.AuthAuto,
		L1Path: "/v1/models", Enabled: true}
	routes := []*model.Route{
		{ID: 100, ModelNameID: 1, UpstreamID: 10, Priority: 1, Weight: 100, Enabled: true},
		{ID: 101, ModelNameID: 1, UpstreamID: 10, Priority: 2, Weight: 100, Enabled: true},
	}

	cfg := &fakeCfg{
		snap:     router.BuildSnapshot([]*model.ModelName{mn}, []*model.Upstream{up}, routes),
		settings: fastSettings(),
		state:    store.StateRunning,
	}
	track := newRecordingTracker()
	// 两条 Route 都已被判死
	track.states[100] = model.StateDead
	track.states[101] = model.StateDead
	gate := health.NewUpstreamGate()
	sched := NewScheduler(cfg, fakeTransport{}, track, gate, discardLogger()).WithTargets(testTargets(), nil)

	// 第一轮：L1 失败，站级记为不通
	sched.tick(context.Background())
	sched.wg.Wait()
	if gate.OK(10) {
		t.Fatal("前置条件：站级应为不通")
	}

	// 站恢复了
	mu.Lock()
	down = false
	mu.Unlock()

	sched.tick(context.Background())
	sched.wg.Wait()

	_, _, _, triggered, _ := track.snapshot()
	got := map[int64]bool{}
	for _, id := range triggered {
		got[id] = true
	}
	for _, rt := range routes {
		if !got[rt.ID] {
			t.Errorf("L1 转通应立即触发 dead Route %d 的 L2（不等 L2 周期）", rt.ID)
		}
	}
}

// ── 并发控制（§4.6）─────────────────────────────────────

// 同一 Upstream 的 L2 必须串行：一个站下挂 5 个模型时，
// 同时探 5 个几乎必然吃 429。
func TestScheduler_SerializesL2PerUpstream(t *testing.T) {
	var mu sync.Mutex
	var concurrent, peak int

	mn := &model.ModelName{ID: 1, Name: "claude-opus-5",
		Protocol: model.ProtoAnthropic, MatchMode: model.MatchExact, Enabled: true}
	mn.Defaults()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.WriteHeader(200)
			return
		}
		drainBody(r)
		mu.Lock()
		concurrent++
		if concurrent > peak {
			peak = concurrent
		}
		mu.Unlock()

		time.Sleep(30 * time.Millisecond) // 拉长重叠窗口

		mu.Lock()
		concurrent--
		mu.Unlock()

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(aliveSSE))
	}))
	defer srv.Close()

	up := &model.Upstream{ID: 10, Name: "shared", BaseURL: srv.URL,
		APIKey: "sk-probe-key-abcdefgh", AuthStyle: model.AuthAuto,
		L1Path: "/v1/models", Enabled: true}
	var routes []*model.Route
	for i := 0; i < 5; i++ {
		routes = append(routes, &model.Route{
			ID: int64(100 + i), ModelNameID: 1, UpstreamID: 10,
			Priority: 1, Weight: 100, Enabled: true,
		})
	}

	cfg := &fakeCfg{
		snap:     router.BuildSnapshot([]*model.ModelName{mn}, []*model.Upstream{up}, routes),
		settings: fastSettings(),
		state:    store.StateRunning,
	}
	sched := NewScheduler(cfg, fakeTransport{}, newRecordingTracker(),
		health.NewUpstreamGate(), discardLogger()).WithTargets(testTargets(), nil)

	// 连跑几轮，让被拒的 Route 有机会重试
	for i := 0; i < 5; i++ {
		sched.tick(context.Background())
	}
	sched.wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if peak > 1 {
		t.Errorf("同一 Upstream 的 L2 必须串行，峰值并发 %d", peak)
	}
}

// 全局 L2 并发上限：不限的话「全部到期」会同时向所有站发请求，
// 那看起来就像一次小型压测。
func TestScheduler_EnforcesGlobalL2Limit(t *testing.T) {
	const limit = 2
	var mu sync.Mutex
	var concurrent, peak int

	hs := newSchedHarness(t, 8, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.WriteHeader(200)
			return
		}
		drainBody(r)
		mu.Lock()
		concurrent++
		if concurrent > peak {
			peak = concurrent
		}
		mu.Unlock()

		time.Sleep(30 * time.Millisecond)

		mu.Lock()
		concurrent--
		mu.Unlock()

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(aliveSSE))
	})
	hs.cfg.settings.GlobalL2Concurrency = limit

	hs.sched.tick(context.Background())
	hs.sched.wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if peak > limit {
		t.Errorf("全局 L2 并发应不超过 %d，峰值 %d", limit, peak)
	}
	if peak == 0 {
		t.Error("应该有 L2 真的跑起来")
	}
}

// 抢不到额度的 Route 要撤掉预占，让下个 tick 重试。
// 不撤的话它要白等一整个 L2 周期（alive 时是 5 分钟）。
func TestScheduler_ReleasesClaimWhenRefused(t *testing.T) {
	hs := newSchedHarness(t, 4, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.WriteHeader(200)
			return
		}
		drainBody(r)
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(aliveSSE))
	})
	hs.cfg.settings.GlobalL2Concurrency = 1

	hs.sched.tick(context.Background())

	_, _, _, triggered, _ := hs.track.snapshot()
	if len(triggered) == 0 {
		t.Error("被并发闸拒掉的 Route 应调 TriggerL2 撤回预占，否则要白等一个周期")
	}
	hs.sched.wg.Wait()
}

// ── 总闸联动（§4.8）─────────────────────────────────────

// 暂停时探活全停 —— 目的正是「不用时不浪费探活额度」。
func TestScheduler_PausedStopsAllProbing(t *testing.T) {
	var hits int
	var mu sync.Mutex
	hs := newSchedHarness(t, 2, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(200)
	})
	hs.cfg.setState(store.StatePaused)

	for i := 0; i < 3; i++ {
		hs.sched.tick(context.Background())
	}
	hs.sched.wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Errorf("暂停时不该发任何探活请求，实际发了 %d 次", hits)
	}
}

// 从暂停恢复时把状态清回 unknown：暂停期间站点可能恢复也可能挂掉，
// 旧状态已经过期。unknown 是乐观的，所以恢复瞬间就能承接流量。
func TestScheduler_ResumeResetsState(t *testing.T) {
	hs := newSchedHarness(t, 1, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	hs.cfg.setState(store.StatePaused)
	hs.sched.tick(context.Background())

	hs.cfg.setState(store.StateRunning)
	hs.sched.tick(context.Background())
	hs.sched.wg.Wait()

	_, _, _, _, resets := hs.track.snapshot()
	if resets != 1 {
		t.Errorf("从暂停恢复应调一次 ResetAll，实际 %d 次", resets)
	}
}

// 恢复只在**状态真的翻转**时才重置。每个 tick 都重置的话，
// 所有 Route 会永远停在 unknown，判死机制完全失效。
func TestScheduler_RunningTicksDoNotRepeatedlyReset(t *testing.T) {
	hs := newSchedHarness(t, 1, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	for i := 0; i < 5; i++ {
		hs.sched.tick(context.Background())
	}
	hs.sched.wg.Wait()

	_, _, _, _, resets := hs.track.snapshot()
	if resets != 0 {
		t.Errorf("一直是 running 时不该重置状态，实际重置了 %d 次", resets)
	}
}

// 探活总开关关掉时不发请求，但总闸状态仍要跟踪。
func TestScheduler_ProbeDisabledSendsNothing(t *testing.T) {
	var hits int
	var mu sync.Mutex
	hs := newSchedHarness(t, 2, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(200)
	})
	hs.cfg.settings.ProbeEnabled = false

	hs.sched.tick(context.Background())
	hs.sched.wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Errorf("probe_enabled=false 时不该探活，实际发了 %d 次", hits)
	}
}

// 停用的 Route/Upstream 不该被探 —— 那是用户显式关掉的。
func TestScheduler_SkipsDisabled(t *testing.T) {
	var hits int
	var mu sync.Mutex
	hs := newSchedHarness(t, 2, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(200)
	})

	hs.cfg.mu.Lock()
	for _, rts := range hs.cfg.snap.RoutesByModelName {
		for _, rt := range rts {
			rt.Enabled = false
		}
	}
	hs.cfg.mu.Unlock()

	hs.sched.tick(context.Background())
	hs.sched.wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Errorf("停用的 Route 不该被探活，实际发了 %d 次", hits)
	}
}

// ── Run 的生命周期 ───────────────────────────────────────

// ctx 结束时 Run 必须返回，且等在途探活收尾 ——
// 不等的话进程退出时会留一批半开连接，上游侧看着像被攻击。
func TestScheduler_RunStopsOnContextCancel(t *testing.T) {
	hs := newSchedHarness(t, 1, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		hs.sched.Run(ctx)
		close(done)
	}()

	time.Sleep(1200 * time.Millisecond) // 至少过一个 tick
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ctx 取消后 Run 应及时返回")
	}
}

// ── 手动探活（§4.5）─────────────────────────────────────

func TestScheduler_ProbeNow(t *testing.T) {
	hs := newSchedHarness(t, 1, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.WriteHeader(200)
			return
		}
		drainBody(r)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(aliveSSE))
	})

	snap, _ := hs.cfg.Snapshot()
	rt := snap.RoutesByModelName[1][0]

	l1, l2, err := hs.sched.ProbeNow(context.Background(), snap, rt)
	if err != nil {
		t.Fatal(err)
	}
	if l1.Verdict != health.VerdictOK {
		t.Errorf("L1 应通过，得到 %s（%v）", l1.Verdict, l1.Err)
	}
	if l2.Verdict != health.VerdictOK {
		t.Errorf("L2 应通过，得到 %s（%v）", l2.Verdict, l2.Err)
	}

	_, _, reports, _, _ := hs.track.snapshot()
	if len(reports) == 0 {
		t.Error("手动探活的结果也要落到状态机，否则界面看到「测试通过」而状态没变")
	}
}

// L1 失败时不必再探 L2，但失败仍要落到状态机。
func TestScheduler_ProbeNowSkipsL2WhenL1Fails(t *testing.T) {
	var l2Hits int
	var mu sync.Mutex
	hs := newSchedHarness(t, 1, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.WriteHeader(503)
			return
		}
		mu.Lock()
		l2Hits++
		mu.Unlock()
		w.WriteHeader(200)
	})

	snap, _ := hs.cfg.Snapshot()
	rt := snap.RoutesByModelName[1][0]

	l1, l2, err := hs.sched.ProbeNow(context.Background(), snap, rt)
	if err != nil {
		t.Fatal(err)
	}
	if l1.Verdict == health.VerdictOK {
		t.Error("L1 应失败")
	}
	if l2.Verdict != health.VerdictOK || l2.Status != 0 {
		// L2 未执行时 Outcome 是零值，而零值的 Verdict 恰好是 VerdictOK。
		// 这里靠 Status == 0 区分「没跑」与「跑了且通过」。
		if l2.Status != 0 {
			t.Errorf("L1 失败时不该探 L2，但 L2 有结果：%+v", l2)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if l2Hits != 0 {
		t.Errorf("L1 失败时不该发 L2 请求，实际发了 %d 次", l2Hits)
	}

	_, _, reports, _, _ := hs.track.snapshot()
	if len(reports) == 0 {
		t.Error("L1 失败也要落到状态机，否则手动测试看到「站挂了」而状态没变")
	}
}

// 配置不一致时要报错，而不是无声无息什么都不发生。
func TestScheduler_ProbeNowRejectsBrokenConfig(t *testing.T) {
	hs := newSchedHarness(t, 1, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	snap, _ := hs.cfg.Snapshot()

	if _, _, err := hs.sched.ProbeNow(context.Background(), snap,
		&model.Route{ID: 999, ModelNameID: 1, UpstreamID: 88888}); err == nil {
		t.Error("Upstream 不存在应报错")
	}
	if _, _, err := hs.sched.ProbeNow(context.Background(), snap,
		&model.Route{ID: 999, ModelNameID: 88888, UpstreamID: 10}); err == nil {
		t.Error("ModelName 不存在应报错")
	}
}
