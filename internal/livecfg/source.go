// Package livecfg 提供数据库业务配置的带缓存只读视图。
//
// 与 internal/config 的分工：那边是启动时读一次的环境变量（进程级不可变，
// 缺失即拒绝启动）；这边是运行时可热改的业务配置（上游、路由、超时、总闸）。
package livecfg

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/store"
)

// DefaultTTL 是缓存有效期。
//
// 为什么要缓存：SQLite 被限制为单连接（store.Open 里 MaxOpenConns(1)），
// 而一次转发要读 5 张表。样本落库（最大 256KB 的 BLOB）与探活的状态回写
// 共用这条连接，不缓存就会队头阻塞 —— 一次样本写入拖慢所有在途请求的选路。
//
// 为什么不做写后失效通知：2 秒的陈旧度对「在管理界面改配置 → 生效」是无感的，
// 换来的是不必把缓存实例穿到 api 层、再在每个写操作后手工调一次失效 ——
// 那种挂钩漏一处就会变成「改了不生效」的疑难问题。
const DefaultTTL = 2 * time.Second

// Source 是 proxy.ConfigSource 的生产实现。
type Source struct {
	st  *store.Store
	ttl time.Duration
	log *slog.Logger
	now func() time.Time // 测试注入时钟，生产为 time.Now

	mu  sync.RWMutex
	cur *bundle
	// lastAttempt 记的是**尝试**加载的时刻，不是成功时刻。
	// 失败也要计时，否则数据库读不出来时每个请求都会重试并刷日志。
	lastAttempt time.Time
}

// bundle 是一次加载得到的完整配置。整体替换、绝不原地改 ——
// 因此持有旧 bundle 的并发读者始终看到一份自洽的配置，不需要加锁。
type bundle struct {
	snap     *router.Snapshot
	settings model.Settings
	state    store.RunState
}

func New(st *store.Store, log *slog.Logger) *Source {
	return &Source{st: st, ttl: DefaultTTL, log: log, now: time.Now}
}

func (s *Source) Snapshot() (*router.Snapshot, error) {
	b, err := s.get()
	if err != nil {
		return nil, err
	}
	return b.snap, nil
}

func (s *Source) Settings() (model.Settings, error) {
	b, err := s.get()
	if err != nil {
		return model.Settings{}, err
	}
	return b.settings, nil
}

func (s *Source) RunState() (store.RunState, error) {
	b, err := s.get()
	if err != nil {
		return "", err
	}
	return b.state, nil
}

func (s *Source) get() (*bundle, error) {
	s.mu.RLock()
	cur, last := s.cur, s.lastAttempt
	s.mu.RUnlock()
	if cur != nil && s.now().Sub(last) < s.ttl {
		return cur, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// 双检：等锁期间可能已被别的请求刷新过了。
	if s.cur != nil && s.now().Sub(s.lastAttempt) < s.ttl {
		return s.cur, nil
	}
	s.lastAttempt = s.now()

	nb, err := s.load()
	if err != nil {
		// 有旧配置就继续用它服务，别让所有请求变成 500。
		// 配置没变的情况下，数据库暂时读不出来（文件锁、WAL checkpoint）
		// 不该导致网关中断 —— 可用性正是这个项目存在的理由。
		if s.cur != nil {
			s.log.Error("刷新配置失败，继续使用上一次的配置", "err", err)
			return s.cur, nil
		}
		return nil, err
	}
	s.cur = nb
	return nb, nil
}

func (s *Source) load() (*bundle, error) {
	mns, err := s.st.ListModelNames()
	if err != nil {
		return nil, fmt.Errorf("读取 model_name: %w", err)
	}
	ups, err := s.st.ListUpstreams()
	if err != nil {
		return nil, fmt.Errorf("读取 upstream: %w", err)
	}
	rts, err := s.st.ListRoutes(0)
	if err != nil {
		return nil, fmt.Errorf("读取 route: %w", err)
	}
	settings, err := s.st.GetSettings()
	if err != nil {
		return nil, fmt.Errorf("读取 settings: %w", err)
	}
	state, err := s.st.GetRunState()
	if err != nil {
		return nil, fmt.Errorf("读取运行状态: %w", err)
	}

	// SaveSettings 已经校验过，所以这里失败只可能是有人手改了库或降级了版本。
	// 但代价太大不能放过：RealFirstTokenSec = 0 会让 time.AfterFunc(0) 立刻开火，
	// 每个请求都以「首 Token 超时」失败，而且看不出原因。
	if err := settings.Validate(); err != nil {
		s.log.Error("库里的 settings 不合法，本次改用默认值。请在管理界面重新保存设置",
			"err", err)
		settings = model.DefaultSettings()
	}

	return &bundle{
		snap:     router.BuildSnapshot(mns, ups, rts),
		settings: settings,
		state:    state,
	}, nil
}
