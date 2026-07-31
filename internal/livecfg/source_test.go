package livecfg

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	c, err := store.NewCipher("test-encryption-key-32-bytes-long")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// newSource 返回一个用可控时钟的 Source，避免测试依赖真实时间流逝。
func newSource(t *testing.T, st *store.Store) (*Source, *time.Time) {
	t.Helper()
	clock := time.Now()
	s := New(st, discardLog())
	s.now = func() time.Time { return clock }
	return s, &clock
}

// seed 建一套最简可用配置：1 个 ModelName + 1 个 Upstream + 1 条 Route。
func seed(t *testing.T, st *store.Store) (mnID, upID, rtID int64) {
	t.Helper()
	mn := &model.ModelName{Name: "claude-opus-5", Protocol: model.ProtoAnthropic, Enabled: true}
	if err := st.CreateModelName(mn); err != nil {
		t.Fatal(err)
	}
	up := &model.Upstream{Name: "s1", BaseURL: "https://s1.example.com",
		APIKey: "sk-real-upstream-key", Enabled: true}
	if err := st.CreateUpstream(up); err != nil {
		t.Fatal(err)
	}
	rt := &model.Route{ModelNameID: mn.ID, UpstreamID: up.ID, Enabled: true}
	if err := st.CreateRoute(rt); err != nil {
		t.Fatal(err)
	}
	return mn.ID, up.ID, rt.ID
}

func TestSource_LoadsFullConfig(t *testing.T) {
	st := testStore(t)
	mnID, upID, rtID := seed(t, st)
	s, _ := newSource(t, st)

	snap, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.ModelNames) != 1 || snap.ModelNames[0].ID != mnID {
		t.Errorf("ModelName 未正确加载：%+v", snap.ModelNames)
	}
	if snap.Upstreams[upID] == nil {
		t.Fatalf("Upstream %d 未加载", upID)
	}
	// key 必须已解密：出站要用它注入鉴权头，拿到密文会导致 401
	if got := snap.Upstreams[upID].APIKey; got != "sk-real-upstream-key" {
		t.Errorf("api_key 应已解密，得到 %q", got)
	}
	rs := snap.RoutesByModelName[mnID]
	if len(rs) != 1 || rs[0].ID != rtID {
		t.Errorf("Route 未按 ModelName 索引：%+v", rs)
	}

	// 未初始化时应拿到默认值，而不是零值
	settings, err := s.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if settings.RealFirstTokenSec != model.DefaultSettings().RealFirstTokenSec {
		t.Errorf("应返回默认设置，得到 %d", settings.RealFirstTokenSec)
	}
	state, err := s.RunState()
	if err != nil {
		t.Fatal(err)
	}
	if state != store.StateRunning {
		t.Errorf("默认应为 running，得到 %q", state)
	}
}

// TTL 内不重查库。缓存的意义就在这里：SQLite 单连接，
// 每请求 5 次查询会与样本落库抢同一条连接。
func TestSource_CachesWithinTTL(t *testing.T) {
	st := testStore(t)
	seed(t, st)
	s, _ := newSource(t, st)

	first, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}

	// 绕过 Source 直接改库，缓存期内不该被看到
	mn2 := &model.ModelName{Name: "added-behind-the-cache",
		Protocol: model.ProtoAnthropic, Enabled: true}
	if err := st.CreateModelName(mn2); err != nil {
		t.Fatal(err)
	}

	second, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Error("TTL 内应返回同一个快照指针（未重新加载）")
	}
	if len(second.ModelNames) != 1 {
		t.Errorf("TTL 内不该看到新增的 ModelName，得到 %d 个", len(second.ModelNames))
	}
}

// TTL 过后必须看到配置变更，否则「在界面上改了不生效」。
func TestSource_RefreshesAfterTTL(t *testing.T) {
	st := testStore(t)
	seed(t, st)
	s, clock := newSource(t, st)

	if _, err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}

	mn2 := &model.ModelName{Name: "claude-sonnet-5", Protocol: model.ProtoAnthropic, Enabled: true}
	if err := st.CreateModelName(mn2); err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(DefaultTTL + time.Millisecond)

	snap, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.ModelNames) != 2 {
		t.Errorf("TTL 过后应看到 2 个 ModelName，得到 %d", len(snap.ModelNames))
	}
}

// 总闸切换必须在 TTL 后生效 —— 点了「暂停」却还在转发是很糟的。
func TestSource_PicksUpRunStateChange(t *testing.T) {
	st := testStore(t)
	seed(t, st)
	s, clock := newSource(t, st)

	if state, _ := s.RunState(); state != store.StateRunning {
		t.Fatalf("初始应 running，得到 %q", state)
	}
	if err := st.SetRunState(store.StatePaused); err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(DefaultTTL + time.Millisecond)

	state, err := s.RunState()
	if err != nil {
		t.Fatal(err)
	}
	if state != store.StatePaused {
		t.Errorf("应看到 paused，得到 %q", state)
	}
}

// 三个方法必须来自同一次加载，否则可能出现「用新快照配旧超时」这种撕裂状态。
func TestSource_ThreeGettersShareOneLoad(t *testing.T) {
	st := testStore(t)
	seed(t, st)
	s, _ := newSource(t, st)

	snap1, _ := s.Snapshot()
	if _, err := s.Settings(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunState(); err != nil {
		t.Fatal(err)
	}
	snap2, _ := s.Snapshot()
	if snap1 != snap2 {
		t.Error("三个 getter 应共用一次加载的结果")
	}
}

// 数据库读不出来时，有旧配置就继续用 —— 可用性正是这个项目存在的理由。
func TestSource_ServesStaleOnLoadError(t *testing.T) {
	st := testStore(t)
	seed(t, st)
	s, clock := newSource(t, st)

	good, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}

	st.Close() // 让后续查询全部失败
	*clock = clock.Add(DefaultTTL + time.Millisecond)

	stale, err := s.Snapshot()
	if err != nil {
		t.Fatalf("有旧配置时不该返回错误，得到 %v", err)
	}
	if stale != good {
		t.Error("应继续返回上一次成功加载的配置")
	}
	// Settings 与 RunState 也要能继续服务
	if _, err := s.Settings(); err != nil {
		t.Errorf("Settings 也应回退到旧配置，得到 %v", err)
	}
	if _, err := s.RunState(); err != nil {
		t.Errorf("RunState 也应回退到旧配置，得到 %v", err)
	}
}

// 首次加载就失败时必须报错，不能返回零值配置：
// 零值 Settings 的超时全是 0，会让每个请求立刻「超时」且看不出原因。
func TestSource_FirstLoadErrorPropagates(t *testing.T) {
	st := testStore(t)
	st.Close()
	s, _ := newSource(t, st)

	if _, err := s.Snapshot(); err == nil {
		t.Error("首次加载失败应返回错误")
	}
	if _, err := s.Settings(); err == nil {
		t.Error("Settings 首次加载失败应返回错误")
	}
}

// 失败也要计入 lastAttempt，否则库读不出来时每个请求都重试并刷日志。
func TestSource_FailedLoadStillCountsAsAttempt(t *testing.T) {
	st := testStore(t)
	seed(t, st)
	s, clock := newSource(t, st)
	if _, err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}

	st.Close()
	*clock = clock.Add(DefaultTTL + time.Millisecond)
	if _, err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}
	before := s.lastAttempt

	// 同一时刻再取一次：不该再尝试加载
	if _, err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}
	if !s.lastAttempt.Equal(before) {
		t.Error("失败后应进入新的 TTL 窗口，不该每个请求都重试")
	}
}

// 库里的 settings 不合法时降级到默认值，而不是把 0 传给转发层。
// SaveSettings 会校验，所以这只可能发生在手改库或版本降级之后。
func TestSource_InvalidSettingsFallsBackToDefaults(t *testing.T) {
	st := testStore(t)
	seed(t, st)

	// 直接写库绕过 SaveSettings 的校验
	_, err := st.DB().Exec(
		`INSERT INTO setting (key, value, updated_at) VALUES ('settings', ?, 0)`,
		`{"real_first_token_sec":1,"real_total_sec":1}`)
	if err != nil {
		t.Fatal(err)
	}

	s, _ := newSource(t, st)
	got, err := s.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if got.RealFirstTokenSec < model.MinRealFirstTokenSec {
		t.Errorf("不合法的 settings 应降级为默认值，得到 real_first_token_sec=%d",
			got.RealFirstTokenSec)
	}
}

// 并发读不能撕裂，也不该重复加载。
func TestSource_ConcurrentReads(t *testing.T) {
	st := testStore(t)
	seed(t, st)
	s := New(st, discardLog()) // 用真实时钟：并发场景下正是它在起作用

	const n = 50
	done := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			snap, err := s.Snapshot()
			if err != nil {
				done <- err
				return
			}
			if len(snap.ModelNames) != 1 {
				done <- io.ErrUnexpectedEOF // 配置撕裂
				return
			}
			if _, err := s.Settings(); err != nil {
				done <- err
				return
			}
			_, err = s.RunState()
			done <- err
		}()
	}
	for i := 0; i < n; i++ {
		if err := <-done; err != nil {
			t.Fatalf("并发读失败：%v", err)
		}
	}
}
