package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

// sessionCookie 是会话 Cookie 的名字。
const sessionCookie = "relay_session"

// sessionTTL 是会话有效期。
//
// 7 天：这是单人自用的管理界面，每次打开都要重输口令是没有收益的摩擦。
// 真正的防线是 Cookie 的 HttpOnly + SameSite 与「口令仍然必须正确」，
// 而不是把有效期压短 —— 压短只会让人把口令存进浏览器密码管理器，
// 那比一个 HttpOnly Cookie 更容易被拿走。
const sessionTTL = 7 * 24 * time.Hour

// loginLockThreshold / loginLockDelay 是登录失败的节流参数。
//
// 为什么现在需要它：M1–M4 只有 Bearer 口令，攻击面是「猜一个头」；
// M5 加了**登录表单**，而表单是招暴力破解的东西。ADMIN_PASSWORD 的下限
// 只有 8 字符（config.validate），不限速的话在局域网里是可枚举的。
//
// 做法刻意选最简的「连续失败 N 次后每次响应延迟 D」，而不是计数封禁：
//   - 封禁要考虑「封谁」（IP 会变、单人自用又没有账号体系）与解封路径，
//     而把自己锁在管理界面外面、还得去改数据库解锁，代价比暴破更现实
//   - 延迟对暴破的抑制是乘法级的：每次 1 秒，10 万次就是 27 小时，
//     而对正常人只是「输错三次后感觉卡了一下」
//
// 计数不按 IP 分桶，是全局的：单人自用的服务没有「别的用户在正常登录」
// 这种需要保护的并发场景，而按 IP 分桶反而给了换 IP 绕过的余地。
const (
	loginLockThreshold = 3
	loginLockDelay     = time.Second
)

// sessionStore 是内存会话表。
//
// 刻意不落库：会话是进程级的临时状态，重启后要求重新登录是可接受的
// （单人自用，重启不频繁），而落库要多一张表、多一份清理逻辑，
// 还会让「改了 ADMIN_PASSWORD 但旧会话仍然有效」变成一个真实的问题。
// 进程重启即全部失效，语义简单且安全。
type sessionStore struct {
	mu   sync.Mutex
	toks map[string]time.Time // token → 过期时刻
	now  func() time.Time     // 测试注入时钟

	// failures 是连续登录失败次数，成功即归零。
	failures int
	// sleep 可注入，让测试不必真的等一秒。
	sleep func(time.Duration)
}

func newSessionStore() *sessionStore {
	return &sessionStore{
		toks:  map[string]time.Time{},
		now:   time.Now,
		sleep: time.Sleep,
	}
}

// throttle 在连续失败超过阈值后延迟本次响应。
//
// 延迟发生在**校验之后、响应之前**，且成功路径不延迟：
// 正常登录永远是快的，即使之前失败过很多次。
//
// 判定用 `>` 而不是 `>=`：调用方在 noteFailure 之后才调它，所以第 N 次
// 失败时计数已经是 N。用 `>=` 的话阈值 3 会让第 3 次就开始延迟，
// 而语义应当是「连续错满 3 次之后」。
func (s *sessionStore) throttle() {
	s.mu.Lock()
	n, sleep := s.failures, s.sleep
	s.mu.Unlock()
	if n > loginLockThreshold {
		sleep(loginLockDelay)
	}
}

func (s *sessionStore) noteFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures++
}

func (s *sessionStore) noteSuccess() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures = 0
}

// issue 生成一个新会话令牌。
//
// 256 位随机数，crypto/rand。用 math/rand 的话，令牌可以被预测 ——
// 而这个令牌等价于管理口令，能读写所有上游 key。
func (s *sessionStore) issue() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	tok := base64.RawURLEncoding.EncodeToString(buf)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	s.toks[tok] = s.now().Add(sessionTTL)
	return tok, nil
}

// valid 校验令牌，顺带清理过期项。
//
// 这里可以直接用 map 查找而不必定长比较：令牌是 256 位随机数，
// 攻击者无法通过时序反推出一个有效值（不像口令那样有「猜对前几位」
// 的渐进空间）。定长比较的场景在 requireAdmin 里 —— 那边比的是口令。
func (s *sessionStore) valid(tok string) bool {
	if tok == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.toks[tok]
	if !ok {
		return false
	}
	if !s.now().Before(exp) {
		delete(s.toks, tok)
		return false
	}
	return true
}

func (s *sessionStore) revoke(tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.toks, tok)
}

// gcLocked 清理过期令牌。调用方必须已持有锁。
//
// 挂在 issue 上而不是起一个后台 goroutine：会话表最多几十项，
// 遍历的成本远低于维护一个 goroutine 的生命周期。
func (s *sessionStore) gcLocked() {
	now := s.now()
	for tok, exp := range s.toks {
		if !now.Before(exp) {
			delete(s.toks, tok)
		}
	}
}

// ── HTTP 端点 ────────────────────────────────────────────

// login 用管理口令换一个会话 Cookie。
//
// 保留 Bearer 口令鉴权不动（脚本与冒烟测试在用），这里是**增加**一条
// 浏览器友好的路径，不是替换。两条路径共用同一个口令，所以没有
// 「改了口令但某条路径还认旧的」这种问题。
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}

	// adminPW 为空时无人能登录，理由同 bearerOK：
	// ConstantTimeCompare("", "") 返回相等，不挡的话空口令会登录成功。
	if s.adminPW == "" ||
		subtle.ConstantTimeCompare([]byte(body.Password), []byte(s.adminPW)) != 1 {
		s.sessions.noteFailure()
		// 连续失败到阈值后延迟响应，抑制暴力破解。放在这里而不是入口：
		// 正常登录永远不被延迟，即使之前失败过很多次。
		s.sessions.throttle()
		// 不区分「口令为空」与「口令错误」：两者都是没登录成功，
		// 分开说等于告诉调用方「这次至少格式对了」。
		s.log.Warn("管理界面登录失败", "remote", r.RemoteAddr)
		writeJSON(w, http.StatusUnauthorized, errBody{"口令错误"})
		return
	}
	s.sessions.noteSuccess()

	tok, err := s.sessions.issue()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:  sessionCookie,
		Value: tok,
		Path:  "/",
		// HttpOnly：JS 读不到，XSS 也偷不走这个 Cookie。
		HttpOnly: true,
		// SameSite=Strict：跨站请求一律不带上它。管理接口全是状态变更操作，
		// 没有任何需要跨站携带凭据的合理场景。
		SameSite: http.SameSiteStrictMode,
		// 不设 Secure：这个网关的默认监听地址是 127.0.0.1，本地 HTTP 访问
		// 时带 Secure 的 Cookie 会被浏览器直接丢弃 —— 那会让本地部署
		// （§8 明确的主路径）根本登不上。上公网时 TLS 由 M7 的反代终结，
		// 届时应在反代上加 Secure。
		MaxAge: int(sessionTTL.Seconds()),
	})
	s.log.Info("管理界面登录成功", "remote", r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.revoke(c.Value)
	}
	// MaxAge < 0 让浏览器立刻删掉它。
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// session 报告当前是否已登录，供前端决定显示登录页还是主界面。
//
// 走鉴权中间件之外：未登录时要能问「我登录了吗」并得到一个明确的否，
// 而不是 401 —— 前端据此渲染登录页，那是正常流程，不是错误。
func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": s.authenticated(r),
	})
}

// authenticated 判断一个请求是否已授权：会话 Cookie 或 Bearer 口令。
func (s *Server) authenticated(r *http.Request) bool {
	if c, err := r.Cookie(sessionCookie); err == nil && s.sessions.valid(c.Value) {
		return true
	}
	return s.bearerOK(r)
}
