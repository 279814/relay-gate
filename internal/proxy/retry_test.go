package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/store"
)

// 请求内重试（§3.5）。
//
// 这一组盯的是四类静默失败 —— 全都不会报错，只会让人误以为系统正常：
//
//  1. **换站时复用了上一次的出站产物**。A 站的 key 发给 B 站 → B 站回 401
//     → B 站被判死。一个好站因为我们的 bug 被踢出池子，而日志里看到的是
//     「B 站鉴权失败」，排查方向会完全跑偏。
//  2. **不该重试的也重试了**。4xx 换站只是多花一次额度；而把「200 但内容里
//     有 error 字样」判成错误，会丢掉一个已经生成好的答案 —— 表现为
//     「偶尔慢一倍」，没人会想到是网关自己丢的。
//  3. **重试丢掉的那次不回写健康状态**。站挂了却因为「重试成功兜住了」
//     而一直显示 alive，直到下一个定时探活撞上去。§3.5 把真实请求的回写
//     列为最快的故障发现路径,漏了它就等于放弃了这条路径。
//  4. **预读的字节没接回流的最前面**。客户端收到的 SSE 少了 message_start，
//     或 JSON 少了左半边 —— 上游明明回了完整响应。

// ── 多站测试台 ────────────────────────────────────────────

// station 是一个 mock 上游，带自己的 key，并记录收到的请求。
type station struct {
	name string
	key  string
	srv  *httptest.Server

	mu   sync.Mutex
	hits int
	// gotKeys 是每次收到请求时 X-Api-Key 的值，按顺序。
	// 用它验证「每次尝试都用了**这个站自己的** key」。
	gotKeys []string
	gotBody []string
}

func (s *station) record(r *http.Request, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits++
	s.gotKeys = append(s.gotKeys, r.Header.Get("X-Api-Key"))
	s.gotBody = append(s.gotBody, string(body))
}

func (s *station) stats() (hits int, keys, bodies []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits, append([]string(nil), s.gotKeys...), append([]string(nil), s.gotBody...)
}

// multiHarness 是 N 个站按 priority 1..N 串起来的测试台。
//
// newHarness 只有一个 Route，表达不了「换站」—— 而重试的全部行为都在
// 「换到哪个站、发了什么过去」上。
type multiHarness struct {
	h        *Handler
	cfg      *fakeConfig
	stations []*station
	health   *countingHealth
	sink     *recordingSink
	relayPW  string
}

// newMultiHarness 起 len(responders) 个站。responders[i] 是第 i 个站的处理函数，
// priority = i+1（也就是说 responders[0] 是首选，失败后依次往后换）。
func newMultiHarness(t *testing.T, responders ...http.HandlerFunc) *multiHarness {
	t.Helper()

	hs := &multiHarness{health: newCountingHealth(),
		sink: &recordingSink{}, relayPW: "rk-client-key"}

	mn := &model.ModelName{ID: 1, Name: "claude-opus-5",
		Protocol: model.ProtoAnthropic, MatchMode: model.MatchExact, Enabled: true}
	var ups []*model.Upstream
	var routes []*model.Route

	for i, respond := range responders {
		st := &station{
			name: fmt.Sprintf("st%d", i),
			// 每站一个**不同**的 key。这是「A 站的 key 发给 B 站」
			// 唯一能被观测到的方式 —— key 相同的话那个 bug 是隐形的。
			key: fmt.Sprintf("sk-station-%d-secret", i),
		}
		fn := respond
		st.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body := readAllBody(r)
			st.record(r, body)
			fn(w, r)
		}))
		t.Cleanup(st.srv.Close)
		hs.stations = append(hs.stations, st)

		upID := int64(10 + i)
		ups = append(ups, &model.Upstream{ID: upID, Name: st.name, BaseURL: st.srv.URL,
			APIKey: st.key, AuthStyle: model.AuthAuto, Enabled: true})
		routes = append(routes, &model.Route{ID: 100 + int64(i)*100, ModelNameID: 1,
			UpstreamID: upID, Priority: i + 1, Weight: 100, Enabled: true})
	}

	s := testSettings()
	s.HalfOpenEnabled = false
	hs.cfg = &fakeConfig{
		snap:     router.BuildSnapshot([]*model.ModelName{mn}, ups, routes),
		settings: s,
		state:    store.StateRunning,
	}
	hs.h = NewHandler(hs.cfg, hs.health, hs.sink, []string{hs.relayPW}, discardLog())
	t.Cleanup(hs.h.CloseIdleConnections)
	return hs
}

func readAllBody(r *http.Request) []byte {
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 512)
	for {
		n, err := r.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			return buf
		}
	}
}

func (hs *multiHarness) serve(body string) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	hs.h.Routes(mux)
	r := httptest.NewRequest("POST", "/v1/messages?beta=true", strings.NewReader(body))
	r.Header = claudeCodeHeaders()
	r.Header.Set("X-Api-Key", hs.relayPW)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	return rec
}

func (hs *multiHarness) req() string { return `{"model":"claude-opus-5","max_tokens":1}` }

// assertHits 断言每个站分别收到了几个请求。
func (hs *multiHarness) assertHits(t *testing.T, want ...int) {
	t.Helper()
	for i, w := range want {
		if got, _, _ := hs.stations[i].stats(); got != w {
			t.Errorf("站 %s 应收到 %d 个请求，实际 %d", hs.stations[i].name, w, got)
		}
	}
}

// ── 各类可重试条件（§3.5）──────────────────────────────────

func respondStatus(code int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		w.Write([]byte(body))
	}
}

func respondOK(text string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(text))
	}
}

// §3.5 的可重试清单，逐条验证：换站之后客户端拿到的是好站的响应。
func TestRetry_RetryableConditionsSwitchStation(t *testing.T) {
	cases := []struct {
		name string
		bad  http.HandlerFunc
	}{
		{"500", respondStatus(500, `{"error":"internal"}`)},
		{"502", respondStatus(502, `bad gateway`)},
		{"503", respondStatus(503, `unavailable`)},
		{"429 限流", respondStatus(429, `{"error":{"type":"rate_limit_error"}}`)},
		{
			// 200 但流里第一个事件就是 error（§3.5 明确列为可重试）
			name: "200 但载荷是错误",
			bad: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.Write([]byte("event: error\ndata: {\"type\":\"error\"," +
					"\"error\":{\"type\":\"overloaded_error\"}}\n\n"))
				w.(http.Flusher).Flush()
			},
		},
		{
			// 响应头都不回。首 Token 超时（Send 阶段的 headerTimer）
			name: "响应头阶段卡死",
			bad: func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(3 * time.Second) // > RealFirstTokenSec(2)
			},
		},
		{
			// 头回了、flush 了，但 body 一个字节都不吐。
			// 这条走的是 Peek 里的首 Token 计时器,与上一条是不同的代码路径。
			name: "响应头已回但 body 卡死",
			bad: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(200)
				w.(http.Flusher).Flush()
				time.Sleep(3 * time.Second)
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hs := newMultiHarness(t, c.bad, respondOK(`{"id":"from-good-station"}`))
			hs.cfg.settings.RealTotalSec = 30 // 容得下两次尝试

			rec := hs.serve(hs.req())

			if rec.Code != 200 {
				t.Fatalf("应换站成功，得到 %d：%s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "from-good-station") {
				t.Errorf("客户端应拿到好站的响应，得到 %q", rec.Body.String())
			}
			if got := rec.Header().Get("X-Relay-Attempts"); got != "2" {
				t.Errorf("X-Relay-Attempts 应为 2，得到 %q", got)
			}
			hs.assertHits(t, 1, 1)
		})
	}
}

// 4xx（除 429）不重试：换个站会拿到同一个 4xx，只是多花一次额度，
// 还把一个明确的错误信息推迟了。
func TestRetry_ClientErrorsAreNotRetried(t *testing.T) {
	for _, code := range []int{400, 401, 403, 404, 422} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			hs := newMultiHarness(t,
				respondStatus(code, `{"error":{"message":"nope"}}`),
				respondOK(`{"id":"should-not-reach"}`))

			rec := hs.serve(hs.req())

			if rec.Code != code {
				t.Errorf("状态码应原样透传，want %d got %d", code, rec.Code)
			}
			if strings.Contains(rec.Body.String(), "should-not-reach") {
				t.Error("4xx 不该换站 —— 第二个站被打到了")
			}
			hs.assertHits(t, 1, 0)
			// 一次过的响应必须与 M5 逐字节相同,不能凭空多一个头
			if got := rec.Header().Get("X-Relay-Attempts"); got != "" {
				t.Errorf("没重试过就不该带 X-Relay-Attempts，得到 %q", got)
			}
		})
	}
}

// 首次就成功时绝不重试。这条防的是「循环条件写反」这类基础错误 ——
// 它会让每个正常请求都在上游花两份额度。
func TestRetry_SuccessDoesNotRetry(t *testing.T) {
	hs := newMultiHarness(t,
		respondOK(`{"id":"first-try"}`),
		respondOK(`{"id":"second-station"}`))

	rec := hs.serve(hs.req())

	if !strings.Contains(rec.Body.String(), "first-try") {
		t.Errorf("应用首选站的响应，得到 %q", rec.Body.String())
	}
	hs.assertHits(t, 1, 0)
}

// ── 最危险的一条：每次尝试都必须从入站原文重建出站产物 ──────

// A 站的 key 绝不能出现在发往 B 站的请求里。
//
// 这是重试最容易出的错，也是后果最重的一个：复用上一次的 outHeader 会把
// A 站的 key 发给 B 站 → B 站必然 401 → B 站被判死。一个好站因为我们的
// bug 被踢出池子,而日志里显示的是「B 站鉴权失败」,排查方向完全跑偏。
func TestRetry_RebuildsOutboundPerAttempt(t *testing.T) {
	hs := newMultiHarness(t,
		respondStatus(502, `down`),
		respondOK(`{"id":"ok"}`))

	if rec := hs.serve(hs.req()); rec.Code != 200 {
		t.Fatalf("应换站成功，得到 %d", rec.Code)
	}

	for i, st := range hs.stations {
		_, keys, _ := st.stats()
		if len(keys) != 1 {
			t.Fatalf("站 %s 应收到 1 个请求，得到 %d", st.name, len(keys))
		}
		if keys[0] != st.key {
			t.Errorf("站 %s 收到的 key 是 %q，应是它自己的 %q"+
				"（复用了上一次尝试的出站头？）", st.name, keys[0], st.key)
		}
		// 反向也查一遍：别的站的 key 一个都不能出现在这里
		for j, other := range hs.stations {
			if i != j && keys[0] == other.key {
				t.Errorf("站 %s 收到了站 %s 的 key —— A 站的 key 发给了 B 站",
					st.name, other.name)
			}
		}
	}
}

// model 映射必须按**各站自己**的配置重算,不能把上一站的映射结果再映射一次。
func TestRetry_ModelMappingIsPerStation(t *testing.T) {
	hs := newMultiHarness(t,
		respondStatus(502, `down`),
		respondOK(`{"id":"ok"}`))
	// 两站映射到不同的上游模型名
	hs.cfg.snap.RoutesByModelName[1][0].UpstreamModel = "model-for-station-0"
	hs.cfg.snap.RoutesByModelName[1][1].UpstreamModel = "model-for-station-1"

	if rec := hs.serve(hs.req()); rec.Code != 200 {
		t.Fatalf("应换站成功，得到 %d", rec.Code)
	}

	for i, st := range hs.stations {
		_, _, bodies := st.stats()
		want := fmt.Sprintf(`"model":"model-for-station-%d"`, i)
		if len(bodies) != 1 || !strings.Contains(bodies[0], want) {
			t.Errorf("站 %s 应收到 %s，得到 %q", st.name, want, bodies)
		}
		// 二次套用映射会留下上一站的模型名
		for j := range hs.stations {
			if i == j {
				continue
			}
			bad := fmt.Sprintf("model-for-station-%d", j)
			if len(bodies) > 0 && strings.Contains(bodies[0], bad) {
				t.Errorf("站 %s 的请求里出现了 %s —— 映射被套用了两次",
					st.name, bad)
			}
		}
	}
}

// ── 次数与预算的上限 ──────────────────────────────────────

// retry_max_attempts 是**总**尝试次数。全站皆坏时应恰好发这么多次，
// 然后把最后一次的响应交给客户端。
func TestRetry_StopsAtMaxAttempts(t *testing.T) {
	hs := newMultiHarness(t,
		respondStatus(500, `s0 down`),
		respondStatus(500, `s1 down`),
		respondStatus(500, `s2 down`),
		respondStatus(500, `s3 down`))
	hs.cfg.settings.RetryMaxAttempts = 3
	hs.cfg.settings.RealTotalSec = 30

	rec := hs.serve(hs.req())

	// 最后一次的上游响应原样透传（§3.3：响应方向不碰）
	if rec.Code != 500 {
		t.Errorf("应透传最后一次的 500，得到 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "s2 down") {
		t.Errorf("应是第 3 个站的响应体，得到 %q", rec.Body.String())
	}
	hs.assertHits(t, 1, 1, 1, 0)
	if got := rec.Header().Get("X-Relay-Attempts"); got != "3" {
		t.Errorf("X-Relay-Attempts 应为 3，得到 %q", got)
	}
}

// retry_max_attempts=1 表示不重试。这是 M5 的行为，必须能退回去。
func TestRetry_DisabledWithOneAttempt(t *testing.T) {
	hs := newMultiHarness(t,
		respondStatus(500, `s0 down`),
		respondOK(`{"id":"never"}`))
	hs.cfg.settings.RetryMaxAttempts = 1

	rec := hs.serve(hs.req())

	if rec.Code != 500 {
		t.Errorf("不重试时应直接透传 500，得到 %d", rec.Code)
	}
	hs.assertHits(t, 1, 0)
	if got := rec.Header().Get("X-Relay-Attempts"); got != "" {
		t.Errorf("不重试时不该带 X-Relay-Attempts，得到 %q", got)
	}
}

// 站不够时按站数收敛,不能死循环也不能重复打同一个站。
func TestRetry_NeverRepeatsSameStation(t *testing.T) {
	hs := newMultiHarness(t, respondStatus(500, `only station down`))
	hs.cfg.settings.RetryMaxAttempts = 5
	hs.cfg.settings.RealTotalSec = 30

	rec := hs.serve(hs.req())

	// 只有一个站,且它已经试过 —— 不该再试它,而是把它的响应交给客户端
	if rec.Code != 500 {
		t.Errorf("应透传那个站的 500，得到 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "only station down") {
		t.Errorf("上游错误体应原样透传，得到 %q", rec.Body.String())
	}
	hs.assertHits(t, 1)
}

// 无站可换时，必须把**当前这次**的响应交给客户端，而不是丢掉它回一个空响应。
//
// 这条对应一个真实的实现顺序错误：先 Discard 当前尝试、再去选下一个站。
// 那样在「只有一个 Route」这个最常见的配置下，一个本该原样透传的上游 500
// 会变成 HTTP 200 空 body —— 客户端把它当成功，既看不到原因也不会重试。
func TestRetry_NoNextStationStillCommitsCurrentResponse(t *testing.T) {
	hs := newMultiHarness(t, respondStatus(503, `{"error":"the only station is down"}`))
	hs.cfg.settings.RetryMaxAttempts = 3

	rec := hs.serve(hs.req())

	if rec.Code == 200 {
		t.Fatalf("上游 503 却回了 200 —— 响应被丢掉了。body=%q", rec.Body.String())
	}
	if rec.Code != 503 {
		t.Errorf("应透传 503，得到 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "the only station is down") {
		t.Errorf("上游错误体应原样透传，得到 %q", rec.Body.String())
	}
}

// 总时长预算由所有尝试**共享**（§4.2）。
//
// 不共享的话每次尝试各拿一份完整的 30 分钟，3 次重试 = 客户端最坏等 90 分钟,
// 而配置里写的明明是 30 分钟。
func TestRetry_SharesTotalTimeBudget(t *testing.T) {
	// 每个站都卡住不回响应头,各吃掉一次首 Token 超时
	stall := func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}
	hs := newMultiHarness(t, stall, stall, stall)
	hs.cfg.settings.RetryMaxAttempts = 3
	hs.cfg.settings.RealFirstTokenSec = 1
	hs.cfg.settings.RealConnectSec = 1
	// 预算只够一次尝试多一点：第一次吃掉 1s，剩下 0.5s 不足一次连接成本(1s)
	hs.cfg.settings.RealTotalSec = 2

	start := time.Now()
	rec := hs.serve(hs.req())
	elapsed := time.Since(start)

	if rec.Code != http.StatusGatewayTimeout {
		t.Errorf("应回 504，得到 %d：%s", rec.Code, rec.Body.String())
	}
	// 预算是 2s。3 次各 1s 的尝试若不共享预算就会跑到 3s 以上。
	if elapsed > 3*time.Second {
		t.Errorf("耗时 %v，超过总预算 —— 每次尝试各拿了一份完整超时", elapsed)
	}
	hits := 0
	for _, st := range hs.stations {
		n, _, _ := st.stats()
		hits += n
	}
	if hits > 2 {
		t.Errorf("预算耗尽后不该继续重试，实际打了 %d 个站", hits)
	}
}

// ── 健康回写（§3.5：任何失败都立刻回写）─────────────────────

// 被丢弃的那次尝试**必须**回写健康状态。
//
// 漏掉的后果很隐蔽：站挂了，但因为重试成功兜住了，没人报告它失败 ——
// 于是它一直显示 alive，直到下一个定时探活撞上去。而 §3.5 把真实请求的
// 回写列为「最快的故障发现路径」，漏了它就等于放弃了这条路径。
func TestRetry_ReportsHealthForEveryAttempt(t *testing.T) {
	hs := newMultiHarness(t,
		respondStatus(500, `s0 down`),
		respondOK(`{"id":"ok"}`))
	spy := &multiReporter{}
	hs.h.WithHealthReporter(spy)

	if rec := hs.serve(hs.req()); rec.Code != 200 {
		t.Fatalf("应换站成功，得到 %d", rec.Code)
	}

	got := spy.all()
	if len(got) != 2 {
		t.Fatalf("两次尝试都该回写，得到 %d 次：%+v", len(got), got)
	}
	// 失败的那次：Route 100，状态 500
	if got[0].routeID != 100 || got[0].status != 500 {
		t.Errorf("第一条应是 Route 100 的 500，得到 route=%d status=%d",
			got[0].routeID, got[0].status)
	}
	// 成功的那次：Route 200，状态 200
	if got[1].routeID != 200 || got[1].status != 200 {
		t.Errorf("第二条应是 Route 200 的 200，得到 route=%d status=%d",
			got[1].routeID, got[1].status)
	}
}

// 被丢弃的 5xx 也要带上响应体。
//
// 少了它，ClassifyHTTP 只能看状态码 —— 而「500 + body 里写着 rate limit」
// （Anthropic 的 529 overloaded 就是这个形态）会因此被判成 Unavailable 而
// 累计判死,本该只是冷却。一个热门的好站会就这样被踢出池子。
func TestRetry_DiscardedAttemptCarriesErrBody(t *testing.T) {
	hs := newMultiHarness(t,
		respondStatus(529, `{"error":{"type":"overloaded_error","message":"rate limit"}}`),
		respondOK(`{"id":"ok"}`))
	spy := &multiReporter{}
	hs.h.WithHealthReporter(spy)

	if rec := hs.serve(hs.req()); rec.Code != 200 {
		t.Fatalf("应换站成功，得到 %d", rec.Code)
	}

	got := spy.all()
	if len(got) < 1 {
		t.Fatal("应有回写")
	}
	if !strings.Contains(string(got[0].errBody), "overloaded_error") {
		t.Errorf("被丢弃的尝试应带上响应体供健康判定，得到 %q", got[0].errBody)
	}
}

// 每次尝试的 ErrBody 必须用**那一次自己的** key 脱敏。
//
// 用第一次的 key 去脱敏第二次的响应体,B 站回显的 key 就会明文流进
// route_health.last_error 并显示在管理界面上（§3.6.3b 的要求是无条件的）。
func TestRetry_RedactsEachAttemptWithItsOwnKey(t *testing.T) {
	// 两个站都把自己收到的 key 回显在错误信息里（真实中转站的常见格式）
	echoKey := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		fmt.Fprintf(w, `{"error":"Invalid API key: %s"}`, r.Header.Get("X-Api-Key"))
	}
	hs := newMultiHarness(t, echoKey, echoKey)
	hs.cfg.settings.RetryMaxAttempts = 2
	hs.cfg.settings.RealTotalSec = 30
	spy := &multiReporter{}
	hs.h.WithHealthReporter(spy)

	hs.serve(hs.req())

	got := spy.all()
	if len(got) != 2 {
		t.Fatalf("应回写 2 次，得到 %d", len(got))
	}
	for i, rep := range got {
		for _, st := range hs.stations {
			if strings.Contains(string(rep.errBody), st.key) {
				t.Errorf("第 %d 次回写的 ErrBody 里有明文 key %q —— 它会落进 "+
					"route_health.last_error 并显示在管理界面上：%q",
					i+1, st.key, rep.errBody)
			}
		}
		// 脱敏不该毁掉错误信息本身
		if !strings.Contains(string(rep.errBody), "Invalid API key") {
			t.Errorf("第 %d 次回写丢掉了错误信息本身：%q", i+1, rep.errBody)
		}
	}
}

// multiReporter 按顺序记下每次回写。
type multiReporter struct {
	mu   sync.Mutex
	got  []reportedView
	prob []int64
}

type reportedView struct {
	routeID int64
	status  int
	errBody []byte
	err     error
}

func (m *multiReporter) ReportResult(routeID int64, res *ResultView) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.got = append(m.got, reportedView{routeID: routeID, status: res.Status,
		errBody: res.ErrBody, err: res.Err})
}

func (m *multiReporter) TriggerProbe(routeID int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prob = append(m.prob, routeID)
}

func (m *multiReporter) all() []reportedView {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]reportedView(nil), m.got...)
}

// ── 并发额度：被丢弃的尝试必须立刻归还 ──────────────────────

// 三次重试不该同时占住三个站的额度。
//
// 攒到函数出口统一 Release 的话，一次三连重试会把并发上限当场翻三倍 ——
// 而配 max_concurrency 的通常是「多开一路就限流甚至封号」的公益站。
func TestRetry_ReleasesConcurrencyPerAttempt(t *testing.T) {
	hs := newMultiHarness(t,
		respondStatus(500, `down`),
		respondStatus(500, `down`),
		respondOK(`{"id":"ok"}`))
	hs.cfg.settings.RetryMaxAttempts = 3
	hs.cfg.settings.RealTotalSec = 30

	if rec := hs.serve(hs.req()); rec.Code != 200 {
		t.Fatalf("应换站成功，得到 %d", rec.Code)
	}

	acquired, open, peak := hs.health.stats()
	if len(acquired) != 3 {
		t.Errorf("三次尝试应各占一次额度，得到 %v", acquired)
	}
	if open != 0 {
		t.Errorf("结束后在途应归零，得到 %d", open)
	}
	// 换站时会先占下一个站的额度再放当前的（先确认有站可换，才敢丢响应），
	// 所以峰值是 2 而不是 1。3 说明被丢弃的尝试一直没还。
	if peak > 2 {
		t.Errorf("峰值并发 %d —— 被丢弃的尝试没有立刻归还额度", peak)
	}
}

// ── 预读必须无损 ──────────────────────────────────────────

// Peek 读走的字节必须原样接回流的最前面。
//
// 漏掉重放就是**静默吞掉响应的开头**：客户端收到的 SSE 少了 message_start，
// 或 JSON 少了左半边。上游明明回了完整响应，日志也显示 200。
func TestRetry_PeekedBytesAreReplayed(t *testing.T) {
	const body = `{"id":"msg_1","type":"message","content":[{"text":"完整响应"}]}`
	hs := newMultiHarness(t, respondOK(body))

	rec := hs.serve(hs.req())

	if rec.Code != 200 {
		t.Fatalf("应成功，得到 %d", rec.Code)
	}
	if rec.Body.String() != body {
		t.Errorf("响应体必须逐字节完整\nwant %s\ngot  %s", body, rec.Body.String())
	}
}

// 超过预读缓冲的长响应同样要完整 —— 预读只拿走开头一段,余下的从原 body 接着读。
func TestRetry_LongResponseSurvivesPeek(t *testing.T) {
	// 远大于 peekLimit(32KB)
	payload := strings.Repeat("abcdefghij", 12000) // 120KB
	hs := newMultiHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(payload))
	})

	rec := hs.serve(hs.req())

	if rec.Code != 200 {
		t.Fatalf("应成功，得到 %d", rec.Code)
	}
	if got := rec.Body.String(); got != payload {
		t.Errorf("长响应应完整回传，want %d 字节 got %d 字节", len(payload), len(got))
	}
}

// SSE 流经过预读后仍要逐块 flush,且事件一个不少。
//
// 预读会把首块从流里取走。若重放实现成「先攒够再一起写」,SSE 就退化成
// 「长时间无输出后一次性刷出」—— 而那正是 §3.3.5 要防的。
func TestRetry_SSEStillStreamsAfterPeek(t *testing.T) {
	events := []string{"message_start", "content_block_start",
		"content_block_delta", "message_stop"}
	hs := newMultiHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		for _, ev := range events {
			w.Write([]byte("event: " + ev + "\ndata: {\"type\":\"" + ev + "\"}\n\n"))
			fl.Flush()
			time.Sleep(30 * time.Millisecond)
		}
	})

	mux := http.NewServeMux()
	hs.h.Routes(mux)
	rec := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	r := httptest.NewRequest("POST", "/v1/messages",
		strings.NewReader(`{"model":"claude-opus-5","stream":true}`))
	r.Header = claudeCodeHeaders()
	r.Header.Set("X-Api-Key", hs.relayPW)
	mux.ServeHTTP(rec, r)

	if rec.Code != 200 {
		t.Fatalf("应成功，得到 %d", rec.Code)
	}
	for _, ev := range events {
		if !strings.Contains(rec.Body.String(), ev) {
			t.Errorf("事件 %s 丢了", ev)
		}
	}
	if rec.flushes < len(events) {
		t.Errorf("应逐块 flush（至少 %d 次），实际 %d 次 —— 预读之后流被攒起来了",
			len(events), rec.flushes)
	}
}

// ── 客户端已经走了就别再花额度 ────────────────────────────

// 客户端断开后不该继续换站重试：没人在等这个响应，
// 而每次重试都在别人的站上真花一次额度。
func TestRetry_StopsWhenClientGone(t *testing.T) {
	// 站会一直卡住，给测试留出取消的时间
	hs := newMultiHarness(t,
		func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(3 * time.Second)
		},
		respondOK(`{"id":"should-not-reach"}`))
	hs.cfg.settings.RetryMaxAttempts = 3
	hs.cfg.settings.RealFirstTokenSec = 5
	hs.cfg.settings.RealTotalSec = 30

	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequest("POST", "/v1/messages",
		strings.NewReader(hs.req())).WithContext(ctx)
	r.Header = claudeCodeHeaders()
	r.Header.Set("X-Api-Key", hs.relayPW)

	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	mux := http.NewServeMux()
	hs.h.Routes(mux)
	mux.ServeHTTP(httptest.NewRecorder(), r)

	if n, _, _ := hs.stations[1].stats(); n != 0 {
		t.Errorf("客户端已断开，不该再换站重试，第二个站被打了 %d 次", n)
	}
}

// ── 样本：客户端的一次请求 = 一条样本 ─────────────────────

// 重试不该让一次客户端请求变成多条样本。
//
// 样本浏览器把每一行显示成一次客户端请求；一次请求记 N 行会让人以为
// 客户端发了 N 次。逐次尝试的留档归 request_log（M6 PR-B）。
func TestRetry_RecordsOneSamplePerClientRequest(t *testing.T) {
	hs := newMultiHarness(t,
		respondStatus(500, `down`),
		respondOK(`{"id":"ok"}`))
	hs.cfg.settings.RealTotalSec = 30

	if rec := hs.serve(hs.req()); rec.Code != 200 {
		t.Fatalf("应换站成功，得到 %d", rec.Code)
	}

	got := hs.sink.all()
	if len(got) != 1 {
		t.Fatalf("一次客户端请求应只记 1 条样本，得到 %d 条", len(got))
	}
	// 记的必须是**最终**那次尝试：客户端拿到的就是它
	smp := got[0]
	if smp.RouteID != 200 {
		t.Errorf("样本应记最终尝试的 Route 200，得到 %d", smp.RouteID)
	}
	if smp.RespStatus != 200 {
		t.Errorf("样本应记最终的 200，得到 %d", smp.RespStatus)
	}
	if smp.Outcome != model.OutcomeOK {
		t.Errorf("最终成功了，outcome 应为 ok，得到 %q", smp.Outcome)
	}
	// 被丢弃那次的响应字节绝不能混进来（每次尝试各用一个新 tee）
	if strings.Contains(string(smp.RespBody), "down") {
		t.Errorf("样本里混进了被丢弃尝试的响应：%q", smp.RespBody)
	}
}
