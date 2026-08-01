package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestLogin_ThrottleIsPerRequestNotAQueue 记录节流的**实际强度**。
//
// 这条测试不是在断言一个理想性质，而是��当前实现的真实行为钉住，
// 免得日后有人（包括我）以为它比实际更强。
//
// 事实：throttle 在锁外 sleep，所以并发请求各自延迟、不排队。N 个并发
// 猜测的总耗时是 1 个延迟，不是 N 个。也就是说这个机制**抑制的是串行
// 暴破的速率，不是并发暴破的吞吐**。
//
// 为什么这样仍然可接受：
//   - 威胁模型是「服务不小心暴露在局域网/公网」，而不是「有人专门写并发
//     爆破器打它」。前者用现成工具串行试，正是这个延迟能挡的
//   - 真正的防线是 ADMIN_PASSWORD 的熵，不是这个延迟。延迟只是��
//     「几分钟撞开一个弱口令」变成「要花几天」，给人留出发现的时间
//   - 做成真队列（全局串行化登录）就等于给了一个免费的 DoS 面：
//     攻击者持续发错误口令，正常登录就得排在后面
//
// 若哪天要加强，正确的方向是按来源计数 + 临时封禁，而不是把这个 sleep
// 改成串行队列。
func TestLogin_ThrottleIsPerRequestNotAQueue(t *testing.T) {
	s, h := newTestServer(t)

	var sleeps int64
	var wall sync.Mutex
	var total time.Duration
	s.sessions.sleep = func(d time.Duration) {
		atomic.AddInt64(&sleeps, 1)
		wall.Lock()
		total += d
		wall.Unlock()
		// 不真的 sleep，只记账。
	}

	// 先把失败计数推过阈值。
	for i := 0; i <= loginLockThreshold; i++ {
		do(t, h, "POST", "/admin/api/login", `{"password":"wrong"}`, false)
	}
	atomic.StoreInt64(&sleeps, 0)

	// 并发发 20 个错误口令。
	const n = 20
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("POST", "/admin/api/login",
				strings.NewReader(`{"password":"wrong"}`))
			h.ServeHTTP(httptest.NewRecorder(), req)
		}()
	}
	wg.Wait()

	// 每个请求各自延迟一次 —— 它们是并行的，不排队。
	if got := atomic.LoadInt64(&sleeps); got != n {
		t.Errorf("并发 %d 个失败请求应各延迟一次，得到 %d 次", n, got)
	}
	// 这是关键：累计延迟 = n × delay，但**墙钟只过了 1 个 delay**，
	// 因为它们并行。记在这里是为了让人看清这个机制的边界。
}

// TestLogin_ThrottleDoesNotBlockOtherEndpoints 守一条更实际的性质：
// 登录被节流时，其余管理端点不受影响。
//
// 如果哪天有人把 throttle 改成持锁 sleep，或者改成全局串行队列，
// 这条测试未必会红（sessionStore 的锁不在其他端点的路径上）——
// 但真正会红的是下面那句 valid() 的调用：带 Cookie 的请求要读会话表，
// 持锁 sleep 会把它一起堵死。
func TestLogin_ThrottleDoesNotBlockOtherEndpoints(t *testing.T) {
	s, h := newTestServer(t)

	// 先登录拿一个有效会话。
	login := do(t, h, "POST", "/admin/api/login",
		`{"password":"`+testAdminPW+`"}`, false)
	var sess *http.Cookie
	for _, c := range login.Result().Cookies() {
		if c.Name == sessionCookie {
			sess = c
		}
	}
	if sess == nil {
		t.Fatal("登录没拿到 Cookie")
	}

	// 让节流生效，并在 sleep 期间验证会话仍可用。
	blocked := make(chan struct{})
	released := make(chan struct{})
	s.sessions.sleep = func(time.Duration) {
		close(blocked)
		<-released
	}

	for i := 0; i < loginLockThreshold; i++ {
		do(t, h, "POST", "/admin/api/login", `{"password":"wrong"}`, false)
	}
	go func() {
		do(t, h, "POST", "/admin/api/login", `{"password":"wrong"}`, false)
	}()

	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("节流没有生效")
	}

	// 节流请求正卡在 sleep 里，此时用会话 Cookie 访问其他端点。
	done := make(chan int, 1)
	go func() {
		req := httptest.NewRequest("GET", "/admin/api/upstreams", nil)
		req.AddCookie(sess)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		done <- rec.Code
	}()

	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Errorf("节流期间其他端点应正常，得到 %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Error("登录节流把其他端点也堵住了 —— sleep 不该在持锁状态下发生")
	}
	close(released)
}
