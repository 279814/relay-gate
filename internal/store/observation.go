package store

// 观察结果的只读查询面。写入侧在 capability.go：那里是唯一的
// CommitProbeObservation 事务入口，本文件不做任何状态推进。

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/279814/relay-gate/internal/model"
)

const probeExecutionCols = `id,trigger,upstream_id,upstream_network_revision,upstream_credential_revision,
	reachability_evidence_kind,reachability_timeout_profile,capability_evidence_kind,
	capability_timeout_profile,reachability_settings_fingerprint,probe_settings_fingerprint,
	COALESCE(endpoint_id,0),endpoint_revision,model_capability_revision,route_capability_revision,
	auth_profile_revision,probe_secret_revisions_hash,request_transform_binding_revision,
	COALESCE(route_id,0),endpoint,recipe_binding_use,COALESCE(recipe_id,0),COALESCE(recipe_version_id,0),
	recipe_storage,recipe_origin,COALESCE(client_profile_id,0),template_id,recipe_binding_revision,
	recipe_identity_revision,recipe_binding_facts_json,real_request_shape_hash,
	real_request_shape_learnable,real_request_shape_unavailable_reason,reachability_token,
	capability_token,resolved_url_hash,request_url_hash,evidence_hash,status_code,error_class,
	capability_state,observation_scope,reachable,final,success,semantic_seen,normal_end_seen,partial,
	candidate_disposition,redacted_detail,sent_at_ms,tls_handshake_start_at_ms,tls_handshake_done_at_ms,
	got_conn_at_ms,response_header_at_ms,first_byte_at_ms,first_event_at_ms,first_semantic_at_ms,
	done_at_ms,request_bytes,response_bytes,estimated_input_tokens,observed_input_tokens,
	observed_output_tokens,retry_after_until_ms,observation_order,expected_cancel,observer_incomplete,
	observer_incomplete_reason,reachability_disposition,capability_disposition,
	COALESCE(calibration_run_id,''),candidate_ordinal`

func scanProbeExecution(scanner interface{ Scan(...any) error }) (*model.ProbeExecution, error) {
	var execution model.ProbeExecution
	var factsJSON string
	if err := scanner.Scan(&execution.ID, &execution.Trigger, &execution.UpstreamID,
		&execution.UpstreamNetworkRevision, &execution.UpstreamCredentialRevision,
		&execution.ReachabilityPolicySelector.Kind, &execution.ReachabilityPolicySelector.TimeoutProfile,
		&execution.CapabilityPolicySelector.Kind, &execution.CapabilityPolicySelector.TimeoutProfile,
		&execution.ReachabilitySettingsFingerprint, &execution.ProbeSettingsFingerprint,
		&execution.EndpointID, &execution.EndpointRevision, &execution.ModelCapabilityRevision,
		&execution.RouteCapabilityRevision, &execution.AuthProfileRevision,
		&execution.ProbeSecretRevisionsHash, &execution.RequestTransformBindingRevision,
		&execution.RouteID, &execution.Endpoint, &execution.RecipeBindingUse, &execution.RecipeID,
		&execution.RecipeVersionID, &execution.RecipeStorage, &execution.RecipeOrigin,
		&execution.ClientProfileID, &execution.TemplateID, &execution.RecipeBindingRevision,
		&execution.RecipeIdentityRevision, &factsJSON, &execution.RealRequestShapeHash,
		&execution.RealRequestShapeLearnable, &execution.RealRequestShapeUnavailableReason,
		&execution.ReachabilityToken, &execution.CapabilityToken, &execution.ResolvedURLHash,
		&execution.RequestURLHash, &execution.EvidenceHash, &execution.StatusCode, &execution.ErrorClass,
		&execution.Capability, &execution.Scope, &execution.Reachable, &execution.Final,
		&execution.Success, &execution.SemanticSeen, &execution.NormalEndSeen, &execution.Partial,
		&execution.CandidateDisposition, &execution.RedactedDetail, &execution.SentAtMS,
		&execution.TLSHandshakeStartAtMS, &execution.TLSHandshakeDoneAtMS, &execution.GotConnAtMS,
		&execution.ResponseHeaderAtMS, &execution.FirstByteAtMS, &execution.FirstEventAtMS,
		&execution.FirstSemanticAtMS, &execution.DoneAtMS, &execution.RequestBytes,
		&execution.ResponseBytes, &execution.EstimatedInputTokens, &execution.ObservedInputTokens,
		&execution.ObservedOutputTokens, &execution.RetryAfterUntilMS, &execution.ObservationOrder,
		&execution.ExpectedCancel, &execution.ObserverIncomplete, &execution.ObserverIncompleteReason,
		&execution.ReachabilityDisposition, &execution.CapabilityDisposition,
		&execution.CalibrationRunID, &execution.CandidateOrdinal); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	execution.ReachabilityPolicySelector.Endpoint = execution.Endpoint
	execution.CapabilityPolicySelector.Endpoint = execution.Endpoint
	if err := json.Unmarshal([]byte(factsJSON), &execution.RecipeBindingFacts); err != nil {
		return nil, fmt.Errorf("execution %s 的 recipe_binding_facts_json: %w", execution.ID, err)
	}
	return &execution, nil
}

func (store *Store) GetProbeExecution(ctx context.Context, id string) (*model.ProbeExecution, error) {
	return scanProbeExecution(store.db.QueryRowContext(ctx, `SELECT `+probeExecutionCols+
		` FROM probe_execution WHERE id=?`, id))
}

// ListProbeExecutions 按 (sent_at_ms, id) 倒序翻页 —— 最近的先看，
// 与 idx_probe_execution_*_sent 的方向一致。sent_at_ms 会重复（同一 tick
// 批量发出的探活毫秒相同），所以必须带 id 做 tie-breaker。
func (store *Store) ListProbeExecutions(ctx context.Context, filter model.ProbeExecutionFilter) (model.Page[*model.ProbeExecution], error) {
	limit, err := normalizePageLimit(filter.Limit)
	if err != nil {
		return model.Page[*model.ProbeExecution]{}, err
	}
	cursorFilter := filter
	cursorFilter.PageRequest = model.PageRequest{}
	keys, err := decodePageCursor(filter.Cursor, "probe-executions", cursorFilter, 2)
	if err != nil {
		return model.Page[*model.ProbeExecution]{}, err
	}
	conditions := []string{"1=1"}
	args := make([]any, 0, 9)
	if filter.UpstreamID > 0 {
		conditions = append(conditions, "upstream_id=?")
		args = append(args, filter.UpstreamID)
	}
	if filter.RouteID > 0 {
		conditions = append(conditions, "route_id=?")
		args = append(args, filter.RouteID)
	}
	if filter.Endpoint != "" {
		if !filter.Endpoint.Valid() {
			return model.Page[*model.ProbeExecution]{}, model.WrapValidation("endpoint filter 无效")
		}
		conditions = append(conditions, "endpoint=?")
		args = append(args, filter.Endpoint)
	}
	if filter.ErrorClass != "" {
		conditions = append(conditions, "error_class=?")
		args = append(args, filter.ErrorClass)
	}
	if filter.Trigger != "" {
		if !filter.Trigger.Valid() {
			return model.Page[*model.ProbeExecution]{}, model.WrapValidation("trigger filter 无效")
		}
		conditions = append(conditions, "trigger=?")
		args = append(args, filter.Trigger)
	}
	if filter.CapabilityState != "" {
		conditions = append(conditions, "capability_state=?")
		args = append(args, filter.CapabilityState)
	}
	if len(keys) == 2 {
		sentAt, parseErr := strconv.ParseInt(keys[0], 10, 64)
		if parseErr != nil || sentAt < 0 {
			return model.Page[*model.ProbeExecution]{}, ErrInvalidCursor
		}
		conditions = append(conditions, "(sent_at_ms<? OR (sent_at_ms=? AND id<?))")
		args = append(args, sentAt, sentAt, keys[1])
	}
	args = append(args, limit+1)
	rows, err := store.db.QueryContext(ctx, `SELECT `+probeExecutionCols+` FROM probe_execution WHERE `+
		strings.Join(conditions, " AND ")+` ORDER BY sent_at_ms DESC,id DESC LIMIT ?`, args...)
	if err != nil {
		return model.Page[*model.ProbeExecution]{}, err
	}
	defer rows.Close()
	items := make([]*model.ProbeExecution, 0, limit+1)
	for rows.Next() {
		item, scanErr := scanProbeExecution(rows)
		if scanErr != nil {
			return model.Page[*model.ProbeExecution]{}, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return model.Page[*model.ProbeExecution]{}, err
	}
	page := model.Page[*model.ProbeExecution]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor, err = encodePageCursor("probe-executions", cursorFilter,
			strconv.FormatInt(last.SentAtMS, 10), last.ID)
		if err != nil {
			return model.Page[*model.ProbeExecution]{}, err
		}
	}
	return page, nil
}

const capabilityCols = `id,scope_upstream_id,scope_route_id,endpoint,endpoint_id,evidence_kind,
	timeout_profile,state,observation_token,resolved_url_hash,upstream_network_revision,
	upstream_credential_revision,endpoint_revision,model_capability_revision,route_capability_revision,
	auth_profile_revision,recipe_binding_revision,probe_settings_fingerprint,probe_secret_revisions_hash,
	request_transform_binding_revision,observed_at,expires_at,status_code,error_class,redacted_detail,
	last_observation_order,last_real_ok_at,last_real_ok_token`

// scanCapabilityRow 与 capability.go 的 loadCapability 读同一张表，但那边是按
// scope 精确取一行、scope 由调用方的 execution 给出；这里 scope 只能从行里读回来。
func scanCapabilityRow(scanner interface{ Scan(...any) error }) (*model.EndpointCapability, int64, error) {
	var value model.EndpointCapability
	var id int64
	var upstreamID, routeID sql.NullInt64
	if err := scanner.Scan(&id, &upstreamID, &routeID, &value.Endpoint, &value.EndpointID,
		&value.PolicySelector.Kind, &value.PolicySelector.TimeoutProfile, &value.State,
		&value.ObservationToken, &value.ResolvedURLHash, &value.UpstreamNetworkRevision,
		&value.UpstreamCredentialRevision, &value.EndpointRevision, &value.ModelCapabilityRevision,
		&value.RouteCapabilityRevision, &value.AuthProfileRevision, &value.RecipeBindingRevision,
		&value.ProbeSettingsFingerprint, &value.ProbeSecretRevisionsHash,
		&value.RequestTransformBindingRevision, &value.ObservedAt, &value.ExpiresAt, &value.StatusCode,
		&value.ErrorClass, &value.RedactedDetail, &value.LastObservationOrder, &value.LastRealOKAt,
		&value.LastRealOKToken); errors.Is(err, sql.ErrNoRows) {
		return nil, 0, ErrNotFound
	} else if err != nil {
		return nil, 0, err
	}
	value.PolicySelector.Endpoint = value.Endpoint
	if upstreamID.Valid {
		value.ScopeType, value.ScopeID = model.RecipeScopeUpstream, upstreamID.Int64
	} else {
		value.ScopeType, value.ScopeID = model.RecipeScopeRoute, routeID.Int64
	}
	return &value, id, nil
}

// ListCapabilities 按 id 倒序翻页。endpoint_capability 每个 scope+endpoint 只有一行，
// 用 observed_at 排会在「同一轮 tick 写入多行」时撞上相同时间戳，
// 而 id 是自增主键，本身就唯一且稳定。
//
// nowMS 由调用方通过 filter.Expired 隐式决定：Expired 需要与当前时间比较，
// 所以在 SQL 里直接用参数化的当前毫秒，不依赖 SQLite 的时间函数。
func (store *Store) ListCapabilities(ctx context.Context, filter model.CapabilityFilter) (model.Page[*model.EndpointCapability], error) {
	limit, err := normalizePageLimit(filter.Limit)
	if err != nil {
		return model.Page[*model.EndpointCapability]{}, err
	}
	cursorFilter := filter
	cursorFilter.PageRequest = model.PageRequest{}
	keys, err := decodePageCursor(filter.Cursor, "capabilities", cursorFilter, 1)
	if err != nil {
		return model.Page[*model.EndpointCapability]{}, err
	}
	conditions := []string{"1=1"}
	args := make([]any, 0, 7)
	if filter.UpstreamID > 0 {
		conditions = append(conditions, "scope_upstream_id=?")
		args = append(args, filter.UpstreamID)
	}
	if filter.RouteID > 0 {
		conditions = append(conditions, "scope_route_id=?")
		args = append(args, filter.RouteID)
	}
	if filter.Endpoint != "" {
		if !filter.Endpoint.Valid() {
			return model.Page[*model.EndpointCapability]{}, model.WrapValidation("endpoint filter 无效")
		}
		conditions = append(conditions, "endpoint=?")
		args = append(args, filter.Endpoint)
	}
	if filter.State != "" {
		conditions = append(conditions, "state=?")
		args = append(args, filter.State)
	}
	if filter.Expired != nil {
		// expires_at=0 表示「没有 TTL」，永远不算过期。
		if *filter.Expired {
			conditions = append(conditions, "expires_at!=0 AND expires_at<=?")
		} else {
			conditions = append(conditions, "(expires_at=0 OR expires_at>?)")
		}
		args = append(args, nowMS())
	}
	if len(keys) == 1 {
		id, cursorErr := cursorID(keys[0])
		if cursorErr != nil {
			return model.Page[*model.EndpointCapability]{}, cursorErr
		}
		conditions = append(conditions, "id<?")
		args = append(args, id)
	}
	args = append(args, limit+1)
	rows, err := store.db.QueryContext(ctx, `SELECT `+capabilityCols+` FROM endpoint_capability WHERE `+
		strings.Join(conditions, " AND ")+` ORDER BY id DESC LIMIT ?`, args...)
	if err != nil {
		return model.Page[*model.EndpointCapability]{}, err
	}
	defer rows.Close()
	type capabilityPageRow struct {
		value *model.EndpointCapability
		id    int64
	}
	scanned := make([]capabilityPageRow, 0, limit+1)
	for rows.Next() {
		item, id, scanErr := scanCapabilityRow(rows)
		if scanErr != nil {
			return model.Page[*model.EndpointCapability]{}, scanErr
		}
		scanned = append(scanned, capabilityPageRow{value: item, id: id})
	}
	if err := rows.Err(); err != nil {
		return model.Page[*model.EndpointCapability]{}, err
	}
	page := model.Page[*model.EndpointCapability]{}
	hasMore := len(scanned) > limit
	if hasMore {
		scanned = scanned[:limit]
	}
	page.Items = make([]*model.EndpointCapability, 0, len(scanned))
	for _, row := range scanned {
		page.Items = append(page.Items, row.value)
	}
	if hasMore {
		page.NextCursor, err = encodePageCursor("capabilities", cursorFilter,
			strconv.FormatInt(scanned[len(scanned)-1].id, 10))
		if err != nil {
			return model.Page[*model.EndpointCapability]{}, err
		}
	}
	return page, nil
}

// 列名带 r. 前缀：filter.Current 要用相关子查询比对 upstream 当前 network_revision，
// 子查询里也有 upstream_id，不加别名 SQLite 会按最近作用域解析成外层错的那一个。
const reachabilityCols = `r.upstream_id,r.evidence_kind,r.endpoint,r.timeout_profile,r.state,
	r.consecutive_ok,r.consecutive_fail,r.last_ok_at,r.last_error_at,r.last_error,r.last_connect_ms,
	r.last_tls_ms,r.last_header_ms,r.observed_network_revision,r.settings_fingerprint,
	r.observation_token,r.last_observation_order`

func scanReachabilityRow(scanner interface{ Scan(...any) error }) (*model.UpstreamReachability, error) {
	var value model.UpstreamReachability
	if err := scanner.Scan(&value.UpstreamID, &value.PolicySelector.Kind, &value.PolicySelector.Endpoint,
		&value.PolicySelector.TimeoutProfile, &value.State, &value.ConsecutiveOK, &value.ConsecutiveFail,
		&value.LastOKAt, &value.LastErrorAt, &value.LastError, &value.LastConnectMS, &value.LastTLSMS,
		&value.LastHeaderMS, &value.ObservedNetworkRevision, &value.SettingsFingerprint,
		&value.ObservationToken, &value.LastObservationOrder); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	return &value, nil
}

// ListReachability 按 upstream_id 升序翻页 —— 它就是主键，天然唯一。
//
// filter.Current 判断的是「这行的 network revision 是否仍等于 Upstream 当前值」：
// 改了 base_url/代理之类的网络字段后，旧观察结果不再代表现在的连通性。
func (store *Store) ListReachability(ctx context.Context, filter model.ReachabilityFilter) (model.Page[*model.UpstreamReachability], error) {
	limit, err := normalizePageLimit(filter.Limit)
	if err != nil {
		return model.Page[*model.UpstreamReachability]{}, err
	}
	cursorFilter := filter
	cursorFilter.PageRequest = model.PageRequest{}
	keys, err := decodePageCursor(filter.Cursor, "reachability", cursorFilter, 1)
	if err != nil {
		return model.Page[*model.UpstreamReachability]{}, err
	}
	conditions := []string{"1=1"}
	args := make([]any, 0, 5)
	if filter.UpstreamID > 0 {
		conditions = append(conditions, "r.upstream_id=?")
		args = append(args, filter.UpstreamID)
	}
	if filter.State != "" {
		conditions = append(conditions, "r.state=?")
		args = append(args, filter.State)
	}
	if filter.Current != nil {
		comparison := "="
		if !*filter.Current {
			comparison = "!="
		}
		conditions = append(conditions, `r.observed_network_revision`+comparison+
			`(SELECT u.network_revision FROM upstream u WHERE u.id=r.upstream_id)`)
	}
	if len(keys) == 1 {
		id, cursorErr := cursorID(keys[0])
		if cursorErr != nil {
			return model.Page[*model.UpstreamReachability]{}, cursorErr
		}
		conditions = append(conditions, "r.upstream_id>?")
		args = append(args, id)
	}
	args = append(args, limit+1)
	rows, err := store.db.QueryContext(ctx, `SELECT `+reachabilityCols+
		` FROM upstream_reachability r WHERE `+strings.Join(conditions, " AND ")+
		` ORDER BY r.upstream_id LIMIT ?`, args...)
	if err != nil {
		return model.Page[*model.UpstreamReachability]{}, err
	}
	defer rows.Close()
	items := make([]*model.UpstreamReachability, 0, limit+1)
	for rows.Next() {
		item, scanErr := scanReachabilityRow(rows)
		if scanErr != nil {
			return model.Page[*model.UpstreamReachability]{}, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return model.Page[*model.UpstreamReachability]{}, err
	}
	page := model.Page[*model.UpstreamReachability]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextCursor, err = encodePageCursor("reachability", cursorFilter,
			strconv.FormatInt(page.Items[len(page.Items)-1].UpstreamID, 10))
		if err != nil {
			return model.Page[*model.UpstreamReachability]{}, err
		}
	}
	return page, nil
}
