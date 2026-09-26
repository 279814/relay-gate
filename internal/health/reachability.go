package health

// ReachabilityTracker 是站级可达性的内存热路径（§4.8）。
//
// SQLite 存可恢复快照；读侧失效：用行内 PolicySelector 从 current Settings
// 重建 fingerprint，再与 NetworkRevision/token 比较，不同即 effective unknown。

import (
	"sync"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

// ReachabilityTracker 持有每个 Upstream 最新已提交的 Reachability 行。
type ReachabilityTracker struct {
	mu       sync.Mutex
	rows     map[int64]*model.UpstreamReachability
	now      func() time.Time
	settings SettingsSource
}

// NewReachabilityTracker 构造空 Tracker。settings 用于 effective 读侧失效。
func NewReachabilityTracker(settings SettingsSource) *ReachabilityTracker {
	return &ReachabilityTracker{
		rows:     map[int64]*model.UpstreamReachability{},
		now:      time.Now,
		settings: settings,
	}
}

// ApplyCommitted 仅在 CommitProbeObservation 返回 ApplyCurrent 后调用。
//
// CAS：同 token 时只接受更大（或相等时保留已有）order，回调返回顺序反转
// 也不能让旧行盖住新行。token 不同表示新 incarnation（含 Mark* 等用
// UnixMilli 占位 order 的旁路写入之后，sequencer 提交的新 token），即使
// order 更低也必须替换，否则新行会输给上一 incarnation 留下的更高 order。
func (tracker *ReachabilityTracker) ApplyCommitted(row *model.UpstreamReachability) {
	if tracker == nil || row == nil || row.UpstreamID <= 0 {
		return
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	current := tracker.rows[row.UpstreamID]
	if current != nil && current.ObservationToken == row.ObservationToken &&
		current.LastObservationOrder >= row.LastObservationOrder {
		return
	}
	copyValue := *row
	tracker.rows[row.UpstreamID] = &copyValue
}

// Effective 返回读侧生效状态。token/fingerprint 失配或无行 → unknown。
func (tracker *ReachabilityTracker) Effective(upstreamID int64, networkRevision int64) model.ReachabilityState {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	row := tracker.rows[upstreamID]
	if row == nil {
		return model.ReachabilityUnknown
	}
	if !tracker.rowCurrentLocked(row, networkRevision) {
		return model.ReachabilityUnknown
	}
	return row.State
}

// OK 在 effective unreachable 时返回 false；unknown/reachable 为 true（乐观）。
func (tracker *ReachabilityTracker) OK(upstreamID int64, networkRevision int64) bool {
	return tracker.Effective(upstreamID, networkRevision) != model.ReachabilityUnreachable
}

// Snapshot 返回已提交行的深拷贝（含可能已 stale 的历史诊断）。
func (tracker *ReachabilityTracker) Snapshot(upstreamID int64) *model.UpstreamReachability {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	row := tracker.rows[upstreamID]
	if row == nil {
		return nil
	}
	copyValue := *row
	return &copyValue
}

// Invalidate 丢弃某个站的内存结论（配置变更后立即 effective unknown）。
func (tracker *ReachabilityTracker) Invalidate(upstreamID int64) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	delete(tracker.rows, upstreamID)
}

// DemotePositive 丢弃 reachable 正结论，保留 unreachable。
func (tracker *ReachabilityTracker) DemotePositive() {
	if tracker == nil {
		return
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	for id, row := range tracker.rows {
		if row.State == model.ReachabilityReachable {
			delete(tracker.rows, id)
		}
	}
}

// InvalidateAll 清空（暂停恢复 / 测试）。
func (tracker *ReachabilityTracker) InvalidateAll() {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	tracker.rows = map[int64]*model.UpstreamReachability{}
}

// RetainOnly 只保留 keep 中的 Upstream。
func (tracker *ReachabilityTracker) RetainOnly(keep map[int64]bool) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	for id := range tracker.rows {
		if !keep[id] {
			delete(tracker.rows, id)
		}
	}
}

// InvalidateStale 按当前 network revision 移除 token 已失配的正结论。
func (tracker *ReachabilityTracker) InvalidateStale(networkByUpstream map[int64]int64) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	for id, row := range tracker.rows {
		rev := networkByUpstream[id]
		if !tracker.rowCurrentLocked(row, rev) {
			delete(tracker.rows, id)
		}
	}
}

func (tracker *ReachabilityTracker) rowCurrentLocked(row *model.UpstreamReachability, networkRevision int64) bool {
	if row.ObservedNetworkRevision != networkRevision {
		return false
	}
	settings := model.DefaultSettings()
	if tracker.settings != nil {
		if s, err := tracker.settings.Settings(); err == nil {
			settings = s
		}
	}
	policy, err := revisioncodec.BuildReachabilityEvidencePolicy(settings, row.PolicySelector)
	if err != nil {
		return false
	}
	fp := revisioncodec.ReachabilitySettingsFingerprint(policy)
	if fp != row.SettingsFingerprint {
		return false
	}
	token := revisioncodec.NewReachabilityToken(model.ReachabilityRevision{
		NetworkRevision: networkRevision, SettingsFingerprint: fp,
	})
	return token == row.ObservationToken
}
