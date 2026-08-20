package probe

import (
	"errors"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/store"
)

// errBoom 是测试用的哨兵错误，只为触发「读配置失败」的分支。
var errBoom = errors.New("boom")

// invHarness 配 1 个 ModelName、2 个 Upstream、每站一条 Route。
//
// 不复用 newSchedHarness：那个会起真的 httptest 靶站（它要测探活的往返），
// 而这里只关心「谁的预占被清了」—— 一次网络请求都不需要。
func invHarness() (*Scheduler, *recordingTracker, *fakeCfg) {
	mn := &model.ModelName{ID: 1, Name: "claude-opus-5",
		Protocol: model.ProtoAnthropic, MatchMode: model.MatchExact, Enabled: true}
	mn.Defaults()

	ups := []*model.Upstream{
		{ID: 10, Name: "up1", BaseURL: "https://a.example.com", Enabled: true},
		{ID: 20, Name: "up2", BaseURL: "https://b.example.com", Enabled: true},
	}
	routes := []*model.Route{
		{ID: 100, ModelNameID: 1, UpstreamID: 10, Priority: 1, Weight: 100, Enabled: true},
		{ID: 200, ModelNameID: 1, UpstreamID: 20, Priority: 1, Weight: 100, Enabled: true},
	}

	cfg := &fakeCfg{
		snap:     router.BuildSnapshot([]*model.ModelName{mn}, ups, routes),
		settings: fastSettings(),
		state:    store.StateRunning,
	}
	track := newRecordingTracker()
	sched := NewScheduler(cfg, newFakeTransport(), track, health.NewUpstreamGate(), discardLogger()).WithTargets(testTargets(), nil)
	return sched, track, cfg
}

func TestInvalidateRoute_ClearsBothLevels(t *testing.T) {
	// 改了 key 或 base_url 之后 L1 的结论同样过期。不清 L1 的话，
	// 一个刚被改对的站仍会因为旧的 L1 失败结论而被 gate 挡住，
	// 于是 L2 永远探不到（§4.1）。
	sched, track, _ := invHarness()
	sched.InvalidateRoute(100)

	track.mu.Lock()
	defer track.mu.Unlock()
	if len(track.triggeredL1) != 1 || track.triggeredL1[0] != 100 {
		t.Errorf("应清 Route 100 的 L1 预占，得到 %v", track.triggeredL1)
	}
	if len(track.triggered) != 1 || track.triggered[0] != 100 {
		t.Errorf("应清 Route 100 的 L2 预占，得到 %v", track.triggered)
	}
}

func TestInvalidateUpstream_CoversAllItsRoutesOnly(t *testing.T) {
	sched, track, _ := invHarness()
	sched.InvalidateUpstream(10)

	track.mu.Lock()
	defer track.mu.Unlock()
	// 只有 upstream 10 下的 Route 100 被触发，Route 200 不受影响。
	if len(track.triggered) != 1 || track.triggered[0] != 100 {
		t.Errorf("只应触发 upstream 10 下的 Route 100，得到 %v", track.triggered)
	}
	if len(track.triggeredL1) != 1 || track.triggeredL1[0] != 100 {
		t.Errorf("L1 同理，得到 %v", track.triggeredL1)
	}
}

func TestInvalidateUpstream_ForgetsGateVerdict(t *testing.T) {
	// 这条是整个钩子里最容易漏、后果最难查的一点。
	//
	// 改 key 前站是 401（L1 失败 → gate.OK 为 false），改对之后若不作废
	// 这个站级结论，maybeProbe 会在 `if !s.gate.OK(up.ID) { return }` 处
	// 直接跳过 L2 —— 用户明明改对了 key，界面上却一直显示不可用，
	// 而唯一的出路是等一次 L1 周期。
	sched, _, _ := invHarness()
	sched.gate.Report(10, false, nil) // 模拟 L1 失败
	if sched.gate.OK(10) {
		t.Fatal("前置条件不成立：gate 应为失败态")
	}

	sched.InvalidateUpstream(10)

	if !sched.gate.OK(10) {
		t.Error("InvalidateUpstream 必须作废旧的站级 L1 结论，否则 L2 会被一直挡住")
	}
}

func TestInvalidateModelName_ClearsL2Only(t *testing.T) {
	// L1 打的是站的 /v1/models，与模型无关。改 probe_prompt 去清 L1
	// 等于白发一次请求 —— 而 §5.2d 刚让这些请求变得可见。
	sched, track, _ := invHarness()
	sched.InvalidateModelName(1)

	track.mu.Lock()
	defer track.mu.Unlock()
	if len(track.triggered) != 2 {
		t.Errorf("该 ModelName 下两条 Route 都应清 L2，得到 %v", track.triggered)
	}
	if len(track.triggeredL1) != 0 {
		t.Errorf("改模型级配置不该清 L1，却清了 %v", track.triggeredL1)
	}
}

func TestInvalidateModelName_UnknownIDIsNoOp(t *testing.T) {
	// 删掉的 ModelName 或并发下的竞态可能传进一个不存在的 ID。
	sched, track, _ := invHarness()
	sched.InvalidateModelName(999)

	track.mu.Lock()
	defer track.mu.Unlock()
	if len(track.triggered) != 0 || len(track.triggeredL1) != 0 {
		t.Errorf("未知 ModelName 不该触发任何东西，得到 L2=%v L1=%v",
			track.triggered, track.triggeredL1)
	}
}

func TestInvalidateUpstream_SnapshotErrorIsSafe(t *testing.T) {
	// 配置读不出来时静默跳过。这里只是「等下一个探活周期」，
	// 不是错误状态 —— 绝不能 panic 或让调用方的 CRUD 失败。
	sched, track, cfg := invHarness()
	cfg.mu.Lock()
	cfg.snapErr = errBoom
	cfg.mu.Unlock()

	sched.InvalidateUpstream(10) // 不应 panic

	track.mu.Lock()
	defer track.mu.Unlock()
	if len(track.triggered) != 0 {
		t.Errorf("读不到配置时不该触发，得到 %v", track.triggered)
	}
}
