package probe

// CapabilityRegistry 是 Endpoint 能力的内存热路径（§4.8）。
//
// 五态只持久化 unknown/supported/unsupported/transient_error/config_error；
// 过期由 ExpiresAt <= now 派生为 effective unknown，不写第六种 stale。
// 本 Registry **永不**写 RouteHealth（§P0-10 验收第 19 条）。

import (
	"sync"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

// capabilityKey 唯一标识一行 EndpointCapability。
type capabilityKey struct {
	scopeType model.RecipeScope
	scopeID   int64
	endpoint  model.EndpointKind
}

// CapabilityRegistry 持有已提交的 Capability 行。
type CapabilityRegistry struct {
	mu       sync.Mutex
	rows     map[capabilityKey]*model.EndpointCapability
	now      func() time.Time
	settings SettingsSource
}

// SettingsSource 提供读侧失效所需的当前 Settings。
type SettingsSource interface {
	Settings() (model.Settings, error)
}

// NewCapabilityRegistry 构造空 Registry。
func NewCapabilityRegistry(settings SettingsSource) *CapabilityRegistry {
	return &CapabilityRegistry{
		rows:     map[capabilityKey]*model.EndpointCapability{},
		now:      time.Now,
		settings: settings,
	}
}

// ApplyCommitted 仅在 CommitProbeObservation 返回 ApplyCurrent 后调用。
//
// CAS：同 token 且更大 order 才覆盖；强制反转两个已提交结果的返回顺序时，
// 仍保留 committed row 中 order 最大者。
func (registry *CapabilityRegistry) ApplyCommitted(row *model.EndpointCapability) {
	if registry == nil || row == nil || row.ScopeID <= 0 || !row.Endpoint.Valid() {
		return
	}
	key := capabilityKey{scopeType: row.ScopeType, scopeID: row.ScopeID, endpoint: row.Endpoint}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	current := registry.rows[key]
	if current != nil {
		if current.ObservationToken == row.ObservationToken &&
			current.LastObservationOrder >= row.LastObservationOrder {
			return
		}
		if current.LastObservationOrder > row.LastObservationOrder {
			return
		}
	}
	copyValue := *row
	registry.rows[key] = &copyValue
}

// Effective 返回读侧生效状态。token 失配、TTL 过期或无行 → unknown。
func (registry *CapabilityRegistry) Effective(scope model.RecipeScope, scopeID int64,
	endpoint model.EndpointKind, expectedToken string) model.CapabilityState {

	row := registry.Snapshot(scope, scopeID, endpoint)
	if row == nil {
		return model.CapabilityUnknown
	}
	if expectedToken != "" && row.ObservationToken != expectedToken {
		return model.CapabilityUnknown
	}
	if !registry.rowCurrent(row) {
		return model.CapabilityUnknown
	}
	if row.ExpiresAt > 0 && !registry.now().Before(time.UnixMilli(row.ExpiresAt)) {
		return model.CapabilityUnknown
	}
	return row.State
}

// Snapshot 返回已提交行的深拷贝。
func (registry *CapabilityRegistry) Snapshot(scope model.RecipeScope, scopeID int64,
	endpoint model.EndpointKind) *model.EndpointCapability {

	registry.mu.Lock()
	defer registry.mu.Unlock()
	row := registry.rows[capabilityKey{scopeType: scope, scopeID: scopeID, endpoint: endpoint}]
	if row == nil {
		return nil
	}
	copyValue := *row
	return &copyValue
}

// Invalidate 丢弃一行（配置变更后立即 effective unknown）。
func (registry *CapabilityRegistry) Invalidate(scope model.RecipeScope, scopeID int64, endpoint model.EndpointKind) {
	if registry == nil {
		return
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	delete(registry.rows, capabilityKey{scopeType: scope, scopeID: scopeID, endpoint: endpoint})
}

// InvalidateAfterCalibration 在校准成功或鉴权穷尽写 config_error 后丢弃内存行。
//
// DB 侧的失效/写入由 Store.CommitCalibrationSuccess / AdvanceCalibrationAfterExecution
// 负责；Registry 只清热路径，避免读到已过期的 supported。
func (registry *CapabilityRegistry) InvalidateAfterCalibration(routeID, upstreamID int64, endpoint model.EndpointKind) {
	if registry == nil {
		return
	}
	if routeID > 0 {
		registry.Invalidate(model.RecipeScopeRoute, routeID, endpoint)
	}
	if upstreamID > 0 {
		registry.Invalidate(model.RecipeScopeUpstream, upstreamID, endpoint)
	}
}

// InvalidateScope 丢弃某 scope 下全部 endpoint。
func (registry *CapabilityRegistry) InvalidateScope(scope model.RecipeScope, scopeID int64) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	for key := range registry.rows {
		if key.scopeType == scope && key.scopeID == scopeID {
			delete(registry.rows, key)
		}
	}
}

// DemotePositive 丢弃未过期的 supported 正结论，保留负状态。
func (registry *CapabilityRegistry) DemotePositive() {
	if registry == nil {
		return
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	now := registry.now()
	for key, row := range registry.rows {
		if row.State != model.CapabilitySupported {
			continue
		}
		if row.ExpiresAt > 0 && !now.Before(time.UnixMilli(row.ExpiresAt)) {
			continue // 已过期，读侧已是 unknown
		}
		delete(registry.rows, key)
	}
}

// InvalidateAll 清空。
func (registry *CapabilityRegistry) InvalidateAll() {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.rows = map[capabilityKey]*model.EndpointCapability{}
}

// InvalidateStaleByToken 移除 observation token 不在 keep 集合中的正结论。
func (registry *CapabilityRegistry) InvalidateStaleByToken(keep map[string]bool) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	for key, row := range registry.rows {
		if !keep[row.ObservationToken] {
			delete(registry.rows, key)
		}
	}
}

func (registry *CapabilityRegistry) rowCurrent(row *model.EndpointCapability) bool {
	settings := model.DefaultSettings()
	if registry.settings != nil {
		if s, err := registry.settings.Settings(); err == nil {
			settings = s
		}
	}
	policy, err := revisioncodec.BuildCapabilityEvidencePolicy(settings, row.PolicySelector)
	if err != nil {
		return false
	}
	fp := revisioncodec.ProbeSettingsFingerprint(policy)
	return fp == row.ProbeSettingsFingerprint
}
