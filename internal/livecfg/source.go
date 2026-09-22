package livecfg

// Package livecfg 提供数据库业务配置的带缓存只读视图。
//
// 与 internal/config 的分工：那边是启动时读一次的环境变量（进程级不可变，
// 缺失即拒绝启动）；这边是运行时可热改的业务配置（上游、路由、超时、总闸）。
//
// P0-10 起：LoadConfigBundle 一次事务读完全部行；Source 构建同代 routing+Probe
// 快照后以单个原子指针发布。真实流量在 Refresh 失败时仍可读旧 routing；
// ProbeSnapshot 在 Invalidate 后未成功 Refresh 前返回 config_snapshot_unavailable。

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/store"
)

// DefaultTTL 是真实流量 routing 缓存有效期。
//
// Probe 路径不走 TTL：管理员写入后必须 Invalidate+Refresh；失败时 Probe
// 拒绝发送，真实转发仍可用最后一份 routing。
const DefaultTTL = 2 * time.Second

// Source 是 proxy.ConfigSource 的生产实现，也是 ConfigPublisher。
type Source struct {
	st  *store.Store
	ttl time.Duration
	log *slog.Logger
	now func() time.Time

	mu  sync.RWMutex
	cur *PublishedConfig
	// probeReady 为 false 时 ProbeSnapshot 返回 unavailable（Invalidate 之后、
	// Refresh 成功之前）。routing 仍可读 cur。
	probeReady bool
	// lastAttempt 记的是**尝试**加载的时刻，不是成功时刻。
	lastAttempt time.Time
	generation  atomic.Uint64
}

func New(st *store.Store, log *slog.Logger) *Source {
	return &Source{st: st, ttl: DefaultTTL, log: log, now: time.Now, probeReady: true}
}

func (s *Source) Snapshot() (*router.Snapshot, error) {
	pub, err := s.get(false)
	if err != nil {
		return nil, err
	}
	return pub.Routing, nil
}

func (s *Source) Settings() (model.Settings, error) {
	pub, err := s.get(false)
	if err != nil {
		return model.Settings{}, err
	}
	return pub.Settings, nil
}

func (s *Source) RunState() (store.RunState, error) {
	pub, err := s.get(false)
	if err != nil {
		return "", err
	}
	return pub.RunState, nil
}

// Bundle 返回当前已发布的同代配置。
func (s *Source) Bundle() (*PublishedConfig, error) {
	return s.get(false)
}

// ProbeSnapshot 返回探活快照。Invalidate 后未 Refresh 成功时返回 unavailable。
func (s *Source) ProbeSnapshot() (*ProbeSnapshot, error) {
	s.mu.RLock()
	ready, cur := s.probeReady, s.cur
	s.mu.RUnlock()
	if !ready || cur == nil || cur.Probe == nil {
		return nil, ErrProbeSnapshotUnavailable
	}
	// TTL 过期时尝试刷新；失败仍返回旧 Probe（与「Invalidate 后失败」不同——
	// 后者明确禁止发送）。
	pub, err := s.get(true)
	if err != nil {
		return nil, err
	}
	if pub.Probe == nil {
		return nil, ErrProbeSnapshotUnavailable
	}
	return pub.Probe, nil
}

// Invalidate 标记 Probe 快照不可用，要求随后 Refresh。
func (s *Source) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.probeReady = false
	s.lastAttempt = time.Time{} // 强制下一次 get 重新加载
}

// Refresh 同步从 Store 加载并原子发布新配置。成功后 Probe 恢复可用。
func (s *Source) Refresh() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastAttempt = s.now()
	pub, err := s.loadLocked()
	if err != nil {
		return err
	}
	s.cur = pub
	s.probeReady = true
	return nil
}

func (s *Source) get(requireProbe bool) (*PublishedConfig, error) {
	s.mu.RLock()
	cur, last, ready := s.cur, s.lastAttempt, s.probeReady
	s.mu.RUnlock()
	if requireProbe && (!ready || cur == nil || cur.Probe == nil) {
		return nil, ErrProbeSnapshotUnavailable
	}
	if cur != nil && s.now().Sub(last) < s.ttl {
		return cur, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur != nil && s.now().Sub(s.lastAttempt) < s.ttl {
		if requireProbe && (!s.probeReady || s.cur.Probe == nil) {
			return nil, ErrProbeSnapshotUnavailable
		}
		return s.cur, nil
	}
	s.lastAttempt = s.now()

	pub, err := s.loadLocked()
	if err != nil {
		if s.cur != nil {
			s.log.Error("刷新配置失败，继续使用上一次的配置", "err", err)
			if requireProbe && (!s.probeReady || s.cur.Probe == nil) {
				return nil, ErrProbeSnapshotUnavailable
			}
			return s.cur, nil
		}
		return nil, err
	}
	s.cur = pub
	// 自动 TTL 刷新成功也恢复 probeReady（仅当之前未显式 Invalidate，
	// 或 Invalidate 后最终读到了新 bundle）。
	s.probeReady = true
	return pub, nil
}

func (s *Source) loadLocked() (*PublishedConfig, error) {
	bundle, err := s.st.LoadConfigBundle(context.Background())
	if err != nil {
		return nil, fmt.Errorf("LoadConfigBundle: %w", err)
	}
	generation := s.generation.Add(1)
	pub, err := buildPublishedConfig(bundle, generation, s.now())
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// Endpoint 实现 outbound.EndpointConfigSource：优先读同代 Probe 快照。
func (s *Source) Endpoint(ctx context.Context, upstreamID int64, endpoint model.EndpointKind) (*model.UpstreamEndpoint, error) {
	pub, err := s.Bundle()
	if err != nil {
		return nil, err
	}
	if pub == nil || pub.Probe == nil {
		return nil, ErrProbeSnapshotUnavailable
	}
	return pub.Probe.Endpoint(ctx, upstreamID, endpoint)
}
