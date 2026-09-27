package probe

import (
	"context"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/store"
)

// §8.10：下一次到期时间从本次 Probe 完成时计算。同站 Route 被 beginL1 收敛进
// 一次 /models 后，也必须按这次完成时刻重算，并与发起者保持同一到期时刻；
// 否则跟随者按 Claim 时刻到期，下一次 /models 早于完成后一个周期，且同站
// 各 Route 到期逐渐错开，一个周期内重复调用 /models。
func TestScheduler_L1CompletionRearmsFoldedSiblings(t *testing.T) {
	const l1Latency = 300 * time.Millisecond
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			time.Sleep(l1Latency)
		}
		drainBody(r)
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)

	mn := &model.ModelName{ID: 1, Name: "claude-opus-5",
		Protocol: model.ProtoAnthropic, MatchMode: model.MatchExact, Enabled: true}
	mn.Defaults()
	ups := []*model.Upstream{{ID: 10, Name: "up1", BaseURL: srv.URL,
		APIKey: "sk-probe-key-abcdefgh", AuthStyle: model.AuthXAPIKey,
		L1Path: "/v1/models", Enabled: true}}
	routes := []*model.Route{
		{ID: 100, ModelNameID: 1, UpstreamID: 10, Priority: 1, Weight: 100, Enabled: true},
		{ID: 101, ModelNameID: 1, UpstreamID: 10, Priority: 2, Weight: 100, Enabled: true},
	}
	cfg := &fakeCfg{
		snap:     router.BuildSnapshot([]*model.ModelName{mn}, ups, routes),
		settings: fastSettings(),
		state:    store.StateRunning,
	}
	track := health.NewTracker(cfg)
	for _, rt := range routes {
		track.Report(health.Report{RouteID: rt.ID, Verdict: health.VerdictFatal})
		// 冷却挡住合成 L2，本用例只看 L1。
		track.Report(health.Report{RouteID: rt.ID, Verdict: health.VerdictRateLimited, RetryAfter: time.Hour})
	}
	sched := NewScheduler(cfg, newFakeTransport(), track, health.NewUpstreamGate(), discardLogger()).
		WithTargets(testTargets(), nil).
		WithRNG(rand.New(rand.NewSource(7)))

	start := time.Now()
	sched.tick(context.Background())
	sched.wg.Wait()

	lead, follower := track.Status(100).NextL1At, track.Status(101).NextL1At
	if lead != follower {
		t.Fatalf("同站 Route 的下次 L1 应同为完成时刻起算：lead=%d follower=%d", lead, follower)
	}
	l1 := time.Duration(cfg.settings.L1IntervalDeadSec) * time.Second
	earliest := start.Add(l1Latency + l1*9/10).UnixMilli()
	if follower < earliest {
		t.Fatalf("跟随者 NextL1At=%d 早于完成时刻 + 周期下限 %d", follower, earliest)
	}
}

// §8.10：周期到期因同站串行 / 全局上限 / 自身在途被拒时不得留下 pending，
// 否则该 Route 下一次完成后会立刻再补一发，绕过从完成时刻起算的间隔。
func TestScheduler_RefusedL2DoesNotBurstAfterCompletion(t *testing.T) {
	cfg := &fakeCfg{settings: fastSettings(), state: store.StateRunning}
	track := health.NewTracker(cfg)
	for _, id := range []int64{100, 101} {
		track.Report(health.Report{RouteID: id, Verdict: health.VerdictFatal})
	}
	sched := NewScheduler(cfg, newFakeTransport(), track, health.NewUpstreamGate(), discardLogger())

	hold, ok := sched.beginL2(10, 100)
	if !ok {
		t.Fatal("setup: beginL2(100)")
	}
	if _, ok := sched.beginL2(10, 101); ok {
		t.Fatal("setup: 同站串行应拒绝 101")
	}
	if _, ok := sched.beginL2(10, 100); ok {
		t.Fatal("setup: 在途的 100 不得重入")
	}
	sched.completeL2(100)
	sched.endL2(10, 100, hold)
	if track.Status(100).NextL2At == 0 {
		t.Fatal("自身在途时的周期到期不得在完成后立刻补发")
	}

	hold, ok = sched.beginL2(10, 101)
	if !ok {
		t.Fatal("100 结束后 101 应能开始")
	}
	sched.completeL2(101)
	sched.endL2(10, 101, hold)
	if track.Status(101).NextL2At == 0 {
		t.Fatal("被同站串行拒绝过的 Route 完成后不得立刻再补一发")
	}
}
