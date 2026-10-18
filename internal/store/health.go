package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

// RouteHealth 是 route_health 表的一行：健康状态的持久化快照。
//
// 运行时以内存为准。冷启动仅使用同事务核对当前身份的负快照；无身份的
// legacy 负快照只要求受控恢复，不能当作当前配置已被证明失败。
type RouteHealth struct {
	RouteID          int64                      `json:"route_id"`
	State            model.HealthState          `json:"state"`
	ConsecutiveOK    int                        `json:"consecutive_ok"`
	ConsecutiveFail  int                        `json:"consecutive_fail"`
	LastOKAt         int64                      `json:"last_ok_at"`
	LastErrAt        int64                      `json:"last_err_at"`
	LastError        string                     `json:"last_error"`
	LastTTFTMS       int64                      `json:"last_ttft_ms"`
	UpdatedAt        int64                      `json:"updated_at"`
	CooldownUntil    int64                      `json:"cooldown_until"`
	DeadSince        int64                      `json:"dead_since"`
	RecoveryRequired bool                       `json:"recovery_required"`
	Identity         *model.RouteHealthIdentity `json:"-"`
	LegacyUnverified bool                       `json:"-"`
}

const routeHealthCols = `route_id, state, consecutive_ok, consecutive_fail,
	last_ok_at, last_err_at, last_error, last_ttft_ms, updated_at,
	cooldown_until,dead_since,recovery_required,identity_json`

// ListRouteHealth 读出全部健康快照，按 route_id 升序。
func (s *Store) ListRouteHealth() ([]*RouteHealth, error) {
	rows, err := s.db.Query(`SELECT ` + routeHealthCols +
		` FROM route_health ORDER BY route_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*RouteHealth{}
	for rows.Next() {
		h, err := scanRouteHealth(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// SaveRouteHealth 写入一批健康快照。
//
// 整批走一个事务：SQLite 每个未显式包事务的写入都要自己 fsync 一次，
// N 个 Route 就是 N 次磁盘同步。而这些写入是**同一时刻**的状态快照，
// 拆开落库既慢又可能让 UI 读到半新半旧的一批。
//
// route_id 不存在时静默跳过（外键约束会拒绝）：Route 可能在快照采集
// 与落库之间被删掉，那不是错误。
func (s *Store) SaveRouteHealth(list []*RouteHealth) error {
	if len(list) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // 提交成功后 Rollback 是无操作

	// 用 UPDATE 而不是 upsert：route_health 行由 CreateRoute 建，
	// 这里只更新。Route 被删掉时对应行已随外键级联消失，
	// UPDATE 影响 0 行，正是想要的「静默跳过」。
	stmt, err := tx.Prepare(`UPDATE route_health SET
		state=?, consecutive_ok=?, consecutive_fail=?,
		last_ok_at=?, last_err_at=?, last_error=?, last_ttft_ms=?, updated_at=?,
		cooldown_until=?,dead_since=?,recovery_required=?,identity_json=?
		WHERE route_id=?`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := nowMS()
	for _, h := range list {
		if h == nil {
			continue
		}
		if h.Identity != nil {
			current, err := routeHealthIdentityCurrent(context.Background(), tx, h.RouteID, h.Identity)
			if err != nil {
				return err
			}
			if !current {
				continue
			}
		}
		var identity string
		if h.Identity != nil {
			raw, err := json.Marshal(h.Identity)
			if err != nil {
				return err
			}
			identity = string(raw)
		}
		if _, err := stmt.Exec(h.State, h.ConsecutiveOK, h.ConsecutiveFail,
			h.LastOKAt, h.LastErrAt, h.LastError, h.LastTTFTMS, now, h.CooldownUntil, h.DeadSince, h.RecoveryRequired, identity, h.RouteID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func scanRouteHealth(row interface{ Scan(...any) error }) (*RouteHealth, error) {
	h := &RouteHealth{}
	var identity string
	if err := row.Scan(&h.RouteID, &h.State, &h.ConsecutiveOK, &h.ConsecutiveFail, &h.LastOKAt, &h.LastErrAt, &h.LastError, &h.LastTTFTMS, &h.UpdatedAt, &h.CooldownUntil, &h.DeadSince, &h.RecoveryRequired, &identity); err != nil {
		return nil, err
	}
	if identity != "" {
		var proof model.RouteHealthIdentity
		decoder := json.NewDecoder(strings.NewReader(identity))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&proof); err != nil || !validRouteHealthProof(&proof) {
			return nil, fmt.Errorf("route health identity invalid: route_id=%d", h.RouteID)
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			return nil, fmt.Errorf("route health identity invalid: route_id=%d", h.RouteID)
		}
		h.Identity = &proof
	}
	return h, nil
}

func validRouteHealthProof(proof *model.RouteHealthIdentity) bool {
	if proof == nil || proof.Version != 1 || proof.ModelNameID <= 0 || proof.HealthSettingsFingerprint == "" || proof.Route.Target.Scope != model.RecipeScopeRoute {
		return false
	}
	endpoint := proof.Route.Target.Endpoint
	if endpoint != model.EndpointMessages && endpoint != model.EndpointResponses && endpoint != model.EndpointChatCompletions {
		return false
	}
	if proof.RouteContextOnly && proof.Reachability == nil {
		return false
	}
	for _, expected := range []*model.SemanticExpectation{&proof.Route, proof.Evidence} {
		if expected == nil {
			continue
		}
		if expected.Target.Validate() != nil || expected.PolicySelector.Validate() != nil || expected.Revision.RecipeIdentity.Validate() != nil || expected.Target.UpstreamID != proof.Route.Target.UpstreamID || expected.PolicySelector.Endpoint != expected.Target.Endpoint || expected.ObservationToken == "" || expected.ObservationToken != revisioncodec.NewObservationToken(expected.Revision) {
			return false
		}
	}
	if expected := proof.Reachability; expected != nil {
		endpoint := proof.Route.Target.Endpoint
		if proof.Evidence != nil {
			endpoint = proof.Evidence.Target.Endpoint
		}
		if expected.UpstreamID != proof.Route.Target.UpstreamID || expected.PolicySelector.Validate() != nil || expected.PolicySelector.Endpoint != endpoint || expected.ObservationToken == "" || expected.ObservationToken != revisioncodec.NewReachabilityToken(expected.Revision) {
			return false
		}
	}
	return true
}

// LoadCurrentRouteHealth verifies each durable negative in the same transaction
// as its current configuration. Positive conclusions are never restored.
func (s *Store) LoadCurrentRouteHealth(ctx context.Context) ([]*RouteHealth, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT `+routeHealthCols+` FROM route_health ORDER BY route_id`)
	if err != nil {
		return nil, err
	}
	var candidates []*RouteHealth
	for rows.Next() {
		h, err := scanRouteHealth(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		candidates = append(candidates, h)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	var result []*RouteHealth
	now := time.Now().UnixMilli()
	for _, h := range candidates {
		negative := h.State == model.StateDead || h.State == model.StateRecovering || h.RecoveryRequired
		if !negative && h.CooldownUntil <= now {
			continue
		}
		if h.Identity != nil {
			current, err := routeHealthIdentityCurrent(ctx, tx, h.RouteID, h.Identity)
			if err != nil {
				return nil, err
			}
			if !current {
				continue
			}
		} else {
			var routeCreated, upstreamCreated, modelCreated int64
			err := tx.QueryRowContext(ctx, `SELECT r.created_at,u.created_at,m.created_at FROM route r JOIN upstream u ON u.id=r.upstream_id JOIN model_name m ON m.id=r.model_name_id WHERE r.id=? AND r.enabled=1 AND u.enabled=1 AND m.enabled=1`, h.RouteID).Scan(&routeCreated, &upstreamCreated, &modelCreated)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return nil, err
			}
			observed := max(h.LastErrAt, h.LastOKAt)
			if observed == 0 {
				observed = h.UpdatedAt
			}
			// Equal milliseconds cannot prove a different incarnation. Only an
			// observation strictly before an existing parent/child rejects it.
			if observed > 0 && observed < max(routeCreated, upstreamCreated, modelCreated) {
				continue
			}
			h = &RouteHealth{RouteID: h.RouteID, State: model.StateRecovering, RecoveryRequired: true, LegacyUnverified: true}
		}
		result = append(result, h)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func routeHealthIdentityCurrent(ctx context.Context, tx *sql.Tx, routeID int64, identity *model.RouteHealthIdentity) (bool, error) {
	if identity == nil || identity.Version != 1 || identity.Route.Target.Scope != model.RecipeScopeRoute || identity.Route.Target.RouteID != routeID {
		return false, nil
	}
	var modelID, modelCreated int64
	err := tx.QueryRowContext(ctx, `SELECT m.id,m.created_at FROM route r JOIN upstream u ON u.id=r.upstream_id JOIN model_name m ON m.id=r.model_name_id WHERE r.id=? AND r.upstream_id=? AND r.enabled=1 AND u.enabled=1 AND m.enabled=1`, routeID, identity.Route.Target.UpstreamID).Scan(&modelID, &modelCreated)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if modelID != identity.ModelNameID || modelCreated != identity.ModelNameCreatedAt {
		return false, nil
	}
	settings, err := loadSettingsTx(ctx, tx)
	if err != nil {
		return false, err
	}
	if identity.HealthSettingsFingerprint != revisioncodec.RouteHealthSettingsFingerprint(settings) {
		return false, nil
	}
	for _, expected := range []*model.SemanticExpectation{&identity.Route, identity.Evidence} {
		if expected == nil {
			continue
		}
		if expected.ObservationToken == "" || revisioncodec.NewObservationToken(expected.Revision) != expected.ObservationToken {
			return false, nil
		}
		current, err := currentSemanticRevision(ctx, tx, expected)
		if errors.Is(err, ErrNotFound) || errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if identity.RouteContextOnly {
			if identity.Reachability == nil || identity.Reachability.UpstreamID != identity.Route.Target.UpstreamID || identity.Reachability.PolicySelector.Kind == model.EvidenceCountTokens {
				return false, nil
			}
			current.ProbeSettingsFingerprint = expected.Revision.ProbeSettingsFingerprint
		}
		if !reflect.DeepEqual(current, expected.Revision) {
			return false, nil
		}
		currentBinding, err := recipeBindingFactsCurrent(ctx, tx, expected)
		if err != nil || !currentBinding {
			return false, err
		}
	}
	if expected := identity.Reachability; expected != nil {
		if expected.ObservationToken == "" || revisioncodec.NewReachabilityToken(expected.Revision) != expected.ObservationToken {
			return false, nil
		}
		current, err := currentReachabilityRevisionForUpstream(ctx, tx, expected.UpstreamID, expected.PolicySelector)
		if errors.Is(err, ErrNotFound) || errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if current != expected.Revision {
			return false, nil
		}
	}
	return true, nil
}
