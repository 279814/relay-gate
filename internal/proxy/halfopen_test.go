package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/store"
)

// ── 半开放行（§4.4c）─────────────────────────────────────

// 全部 Route 都 dead 时,半开让真实流量自己去试一次,避免只能干等探活周期。
func TestHandler_HalfOpenWhenAllDead(t *testing.T) {
	hs := newHarness(t, nil)
	hs.cfg.settings.HalfOpenEnabled = true
	hs.health.dead[100] = true

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))
	if rec.Code != 200 {
		t.Errorf("半开应放行一次试探,得到 %d", rec.Code)
	}
	// §2.3: 半开成功后仍是上游响应，不得新增 X-Relay-Half-Open；标记进 request_log。
	if rec.Header().Get("X-Relay-Half-Open") != "" {
		t.Error("半开成功的上游响应不该带 X-Relay-Half-Open")
	}
	if hs.gotReq.method == "" {
		t.Error("半开应实际转发到上游")
	}
}

// 半开开关关掉时,全 dead 应回 503 而不是放行（这是旧测试的前提）。
func TestHandler_NoHalfOpenWhenDisabled(t *testing.T) {
	hs := newHarness(t, nil)
	hs.cfg.settings.HalfOpenEnabled = false
	hs.health.dead[100] = true

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))
	if rec.Code != 503 {
		t.Errorf("关掉半开时全 dead 应回 503,得到 %d", rec.Code)
	}
	if hs.gotReq.method != "" {
		t.Error("关掉半开时不该转发到上游")
	}
}

// 半开只在 ErrNoRouteAvailable 时尝试。模型没配（404）或协议不匹配（400）
// 是配置错误,放行多少次都不会好,试探只是把一个明确的错误变成一次超时。
func TestHandler_NoHalfOpenOnConfigError(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{"模型没配 → 404", `{"model":"gpt-5.6-sol"}`, 404},
		{"协议不匹配 → 400", `{"model":"claude-opus-5"}`, 400},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hs := newHarness(t, nil)
			hs.cfg.settings.HalfOpenEnabled = true

			var r *http.Request
			if c.want == 400 {
				// 协议不匹配:发到错误的端点
				r = httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(c.body))
				r.Header = claudeCodeHeaders()
				r.Header.Set("X-Api-Key", hs.relayPW)
			} else {
				r = hs.anthropicRequest(c.body)
			}

			rec := hs.serve(r)
			if rec.Code != c.want {
				t.Errorf("配置错误不该半开,期望 %d 得到 %d", c.want, rec.Code)
			}
			if rec.Header().Get("X-Relay-Half-Open") != "" {
				t.Error("配置错误不该打半开标记")
			}
			if hs.gotReq.method != "" {
				t.Error("配置错误时半开不该转发")
			}
		})
	}
}

// 半开放行的 Route 也要占并发额度,否则就绕过了 max_concurrency。
func TestHandler_HalfOpenRespectsMaxConcurrency(t *testing.T) {
	blocked := make(chan struct{})
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		<-blocked // 卡住第一个请求
		w.WriteHeader(200)
	})
	defer close(blocked)

	hs.cfg.settings.HalfOpenEnabled = true
	// 直接改快照里的 Route。BuildSnapshot 返回的是新对象,改它是安全的。
	hs.cfg.snap.RoutesByModelName[1][0].MaxConcurrency = 1
	hs.health.dead[100] = true

	// 第一个请求抢到额度并阻塞
	done := make(chan int, 1)
	go func() {
		rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))
		done <- rec.Code
	}()

	// 等它进入转发（在途计数 > 0）
	for i := 0; i < 50; i++ {
		_, open, _ := hs.health.stats()
		if open > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 第二个请求应拿不到额度,直接 503
	rec2 := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))
	if rec2.Code != 503 {
		t.Errorf("半开也要受 max_concurrency 约束,得到 %d", rec2.Code)
	}

	blocked <- struct{}{} // 放行第一个
	<-done
}

// RecoveryGate：max_concurrency=0（不限普通并发）时半开仍 single-flight（§9.4）。
func TestHandler_HalfOpenRecoveryGateEvenWhenMaxConcurrencyUnlimited(t *testing.T) {
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(200)
	})
	hs.cfg.settings.HalfOpenEnabled = true
	hs.cfg.snap.RoutesByModelName[1][0].MaxConcurrency = 0
	hs.health.dead[100] = true

	done := make(chan int, 2)
	go func() {
		done <- hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`)).Code
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first half-open never reached upstream")
	}
	rec2 := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))
	if rec2.Code != 503 {
		t.Errorf("second half-open must be blocked by RecoveryGate, got %d", rec2.Code)
	}
	close(release)
	<-done
}

// §2.3: 半开试探若连不上上游、由网关自生成 502/504，应带 X-Relay-Half-Open；
// 成功透传上游响应则不得带（见 TestHandler_HalfOpenWhenAllDead）。
func TestHandler_HalfOpenGatewayErrorCarriesHeader(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	})
	hs.cfg.settings.HalfOpenEnabled = true
	hs.cfg.settings.RealFirstTokenSec = 1
	hs.cfg.settings.RealResponseHeaderSec = 1
	hs.cfg.settings.RealFirstByteSec = 1
	hs.cfg.settings.RealFirstSemanticSec = 1
	hs.cfg.settings.RealConnectSec = 1
	hs.cfg.settings.RealTotalSec = 5
	hs.health.dead[100] = true

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))
	if rec.Code != http.StatusGatewayTimeout && rec.Code != http.StatusBadGateway {
		t.Fatalf("半开失败应回网关错误，得到 %d：%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Relay-Half-Open") != "1" {
		t.Error("半开失败的网关错误应带 X-Relay-Half-Open=1")
	}
}

// gatingConfig freezes the second Snapshot (armed halfOpenStillEnabled)
// until the test disables the target and closes blockSecond.
type gatingConfig struct {
	inner       *fakeConfig
	snapCalls   atomic.Int32
	blockSecond chan struct{}
	secondSeen  chan struct{}
}

func (g *gatingConfig) Snapshot() (*router.Snapshot, error) {
	n := g.snapCalls.Add(1)
	if n == 1 {
		return g.inner.Snapshot()
	}
	select {
	case <-g.secondSeen:
	default:
		close(g.secondSeen)
	}
	<-g.blockSecond
	return g.inner.Snapshot()
}
func (g *gatingConfig) Settings() (model.Settings, error) { return g.inner.Settings() }
func (g *gatingConfig) RunState() (store.RunState, error) { return g.inner.RunState() }

// Armed half-open must not RoundTrip after the Route is disabled between
// RecoveryGate acquire and send. Re-enable does not replay the skipped send.
func TestHandler_ArmedHalfOpenSkipsRoundTripAfterDisable(t *testing.T) {
	var hits atomic.Int32
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"msg_1","type":"message"}`))
	})
	hs.cfg.settings.HalfOpenEnabled = true
	hs.health.dead[100] = true

	rt := hs.cfg.snap.RoutesByModelName[1][0]
	gate := &gatingConfig{
		inner:       hs.cfg,
		blockSecond: make(chan struct{}),
		secondSeen:  make(chan struct{}),
	}
	hs.h = NewHandler(gate, hs.health, hs.sink, []string{hs.relayPW}, discardLog()).
		WithTargets(testTargets(hs.cfg), nil)
	t.Cleanup(hs.h.CloseIdleConnections)

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))
	}()

	select {
	case <-gate.secondSeen:
	case <-time.After(3 * time.Second):
		t.Fatal("armed half-open never re-checked Snapshot")
	}

	rt.Enabled = false
	close(gate.blockSecond)

	var rec *httptest.ResponseRecorder
	select {
	case rec = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not finish after disable")
	}
	if rec.Code != 503 {
		t.Fatalf("disabled Route 的已武装半开应得 503，got %d body=%s", rec.Code, rec.Body.String())
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("disabled Route 的已武装半开不得 RoundTrip，hits=%d", n)
	}

	// Re-enable: do not force an immediate half-open replay; next send waits
	// for a later client request that re-selects.
	rt.Enabled = true
	hits.Store(0)
	if n := hits.Load(); n != 0 {
		t.Fatalf("重新启用不得重放被跳过的半开，hits=%d", n)
	}
	gate.snapCalls.Store(0)
	gate.blockSecond = make(chan struct{})
	gate.secondSeen = make(chan struct{})
	close(gate.blockSecond)
	rec2 := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))
	if rec2.Code != 200 {
		t.Fatalf("重新启用后新请求半开仍应 RoundTrip，got %d", rec2.Code)
	}
	if n := hits.Load(); n == 0 {
		t.Fatal("重新启用后新客户端请求仍应 RoundTrip")
	}
}
