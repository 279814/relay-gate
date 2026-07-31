package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	if rec.Header().Get("X-Relay-Half-Open") != "1" {
		t.Error("半开放行时应打标记,否则日志里分不清是正常选路还是试探")
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
