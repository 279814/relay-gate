package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/279814/relay-gate/internal/model"
)

// These fixed SQL identifiers are internal. No request value becomes SQL text.
const attemptMetadataCols = `metadata_version,execution_id,attempt,attempts,config_generation,settings_revision,endpoint_id,endpoint_revision,auth_profile_revision,upstream_network_revision,upstream_credential_revision,route_revision,route_capability_revision,model_revision,model_capability_revision,transform_version_id,request_transform_revision,response_header_at_ms,first_event_at_ms,first_semantic_at_ms,retry_policy,retry_reason,request_write_state,capability_effect,error_class,retried,half_open,duplicate_risk,synthetic_completion,request_input_hash,request_output_hash,request_body_changed,request_headers_changed,request_diff_reason,response_input_hash,response_output_hash,response_body_changed,response_headers_changed,response_diff_reason`

func normalizedAttemptMetadata(m model.AttemptMetadata) (model.AttemptMetadata, error) {
	if m.Version == 0 {
		return model.UnknownAttemptMetadata(), nil
	}
	if m.Version != 1 {
		return m, model.WrapValidation("attempt metadata version 无效")
	}
	if m.RetryPolicy == "" {
		m.RetryPolicy = "unknown"
	}
	if m.RequestWriteState == "" {
		m.RequestWriteState = "unknown"
	}
	if m.CapabilityEffect == "" {
		m.CapabilityEffect = "unknown"
	}
	if m.ErrorClass == "" {
		m.ErrorClass = "unknown"
	}
	if m.RequestDiffReason == "" {
		m.RequestDiffReason = "unknown"
	}
	if m.ResponseDiffReason == "" {
		m.ResponseDiffReason = "unknown"
	}
	if m.ExecutionID != "" && !validMetadataID(m.ExecutionID) {
		return m, model.WrapValidation("attempt execution id 无效")
	}
	if m.RetryPolicy != "unknown" && m.RetryPolicy != model.RetryPolicySafe && m.RetryPolicy != model.RetryPolicyBalanced && m.RetryPolicy != model.RetryPolicyAggressive {
		return m, model.WrapValidation("attempt retry policy 无效")
	}
	switch m.RequestWriteState {
	case "unknown", "not_written", "possibly_written", "written":
	default:
		return m, model.WrapValidation("attempt write state 无效")
	}
	switch m.CapabilityEffect {
	case "unknown", "pending", "unavailable", "dropped", "applied", "config_stale", "superseded", "not_applicable", "ignored":
	default:
		return m, model.WrapValidation("attempt capability effect 无效")
	}
	if m.ErrorClass != "unknown" && !m.ErrorClass.Valid() {
		return m, model.WrapValidation("attempt error class 无效")
	}
	switch m.RetryReason {
	case "", "safe_connect_failure", "policy_retry_after_possible_upstream_accept":
	default:
		return m, model.WrapValidation("attempt retry reason 无效")
	}
	for _, reason := range []string{m.RequestDiffReason, m.ResponseDiffReason} {
		switch reason {
		case "unknown", "recorded", "secret_taint", "incomplete", "sample_disabled":
		default:
			return m, model.WrapValidation("attempt diff reason 无效")
		}
	}
	for _, hash := range []string{m.RequestInputHash, m.RequestOutputHash, m.ResponseInputHash, m.ResponseOutputHash} {
		if hash != "" && !validMetadataHex(hash, 64) {
			return m, model.WrapValidation("attempt hash 无效")
		}
	}
	if m.RequestDiffReason != "recorded" && (m.RequestInputHash != "" || m.RequestOutputHash != "" || m.RequestBodyChanged || m.RequestHeadersChanged) {
		return m, model.WrapValidation("omitted request diff cannot contain facts")
	}
	if m.ResponseDiffReason != "recorded" && (m.ResponseInputHash != "" || m.ResponseOutputHash != "" || m.ResponseBodyChanged || m.ResponseHeadersChanged) {
		return m, model.WrapValidation("omitted response diff cannot contain facts")
	}
	m.DescribeResponseView()
	return m, nil
}

func validMetadataID(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
			return false
		}
	}
	return true
}

func validMetadataHex(value string, length int) bool {
	if len(value) != length || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func insertAttemptMetadata(tx *sql.Tx, table string, ownerID int64, m model.AttemptMetadata) error {
	if m.Version == 0 {
		return nil
	}
	m, err := normalizedAttemptMetadata(m)
	if err != nil {
		return err
	}
	if m.ExecutionID != "" {
		var effect string
		var class model.ErrorClass
		var header, event, semantic int64
		err := tx.QueryRow(`SELECT capability_disposition,error_class,response_header_at_ms,first_event_at_ms,first_semantic_at_ms FROM probe_execution WHERE id=?`, m.ExecutionID).Scan(&effect, &class, &header, &event, &semantic)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil {
			m.CapabilityEffect, m.ErrorClass = effect, class
			m.ResponseHeaderAtMS = max(m.ResponseHeaderAtMS, header)
			m.FirstEventAtMS = max(m.FirstEventAtMS, event)
			m.FirstSemanticAtMS = max(m.FirstSemanticAtMS, semantic)
		}
	}
	args := []any{ownerID, m.Version, m.ExecutionID, m.Attempt, m.Attempts, m.ConfigGeneration, m.SettingsRevision, m.EndpointID, m.EndpointRevision, m.AuthProfileRevision, m.UpstreamNetworkRevision, m.UpstreamCredentialRevision, m.RouteRevision, m.RouteCapabilityRevision, m.ModelRevision, m.ModelCapabilityRevision, m.TransformVersionID, m.RequestTransformRevision, m.ResponseHeaderAtMS, m.FirstEventAtMS, m.FirstSemanticAtMS, m.RetryPolicy, m.RetryReason, m.RequestWriteState, m.CapabilityEffect, m.ErrorClass, m.Retried, m.HalfOpen, m.DuplicateRisk, m.SyntheticCompletion, m.RequestInputHash, m.RequestOutputHash, m.RequestBodyChanged, m.RequestHeadersChanged, m.RequestDiffReason, m.ResponseInputHash, m.ResponseOutputHash, m.ResponseBodyChanged, m.ResponseHeadersChanged, m.ResponseDiffReason}
	_, err = tx.Exec("INSERT INTO "+table+"(owner_id,"+attemptMetadataCols+") VALUES ("+strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")+")", args...)
	return err
}

// The existing observation transaction persists its actual apply result. This
// also keeps facts when execution retention later removes the linked detail.
func recordAttemptObservationTx(ctx context.Context, tx *sql.Tx, execution *model.ProbeExecution) error {
	if execution.Trigger != model.TriggerRealTraffic {
		return nil
	}
	for _, table := range []string{"request_log_metadata", "sample_attempt_metadata"} {
		_, err := tx.ExecContext(ctx, `UPDATE `+table+` SET capability_effect=?,error_class=?,response_header_at_ms=MAX(response_header_at_ms,?),first_event_at_ms=MAX(first_event_at_ms,?),first_semantic_at_ms=MAX(first_semantic_at_ms,?) WHERE execution_id=?`, execution.CapabilityDisposition, execution.ErrorClass, execution.ResponseHeaderAtMS, execution.FirstEventAtMS, execution.FirstSemanticAtMS, execution.ID)
		if err != nil {
			return err
		}
	}
	return nil
}

func scanAttemptMetadata(scanner interface{ Scan(...any) error }) (int64, model.AttemptMetadata, error) {
	var ownerID int64
	m := model.UnknownAttemptMetadata()
	err := scanner.Scan(&ownerID, &m.Version, &m.ExecutionID, &m.Attempt, &m.Attempts, &m.ConfigGeneration, &m.SettingsRevision, &m.EndpointID, &m.EndpointRevision, &m.AuthProfileRevision, &m.UpstreamNetworkRevision, &m.UpstreamCredentialRevision, &m.RouteRevision, &m.RouteCapabilityRevision, &m.ModelRevision, &m.ModelCapabilityRevision, &m.TransformVersionID, &m.RequestTransformRevision, &m.ResponseHeaderAtMS, &m.FirstEventAtMS, &m.FirstSemanticAtMS, &m.RetryPolicy, &m.RetryReason, &m.RequestWriteState, &m.CapabilityEffect, &m.ErrorClass, &m.Retried, &m.HalfOpen, &m.DuplicateRisk, &m.SyntheticCompletion, &m.RequestInputHash, &m.RequestOutputHash, &m.RequestBodyChanged, &m.RequestHeadersChanged, &m.RequestDiffReason, &m.ResponseInputHash, &m.ResponseOutputHash, &m.ResponseBodyChanged, &m.ResponseHeadersChanged, &m.ResponseDiffReason, &m.ExecutionStored)
	m.DescribeResponseView()
	return ownerID, m, err
}

// One bounded metadata query per page. The LEFT JOIN is exact by Execution ID;
// its durable disposition supports either writer ordering without another queue.
func loadAttemptMetadata(ctx context.Context, db schemaQuerier, table string, ids []int64) (map[int64]model.AttemptMetadata, error) {
	result := make(map[int64]model.AttemptMetadata, len(ids))
	if len(ids) == 0 {
		return result, nil
	}
	columns := strings.Split(attemptMetadataCols, ",")
	for i, col := range columns {
		columns[i] = "m." + col
		switch col {
		case "capability_effect":
			columns[i] = "COALESCE(p.capability_disposition,m.capability_effect)"
		case "error_class":
			columns[i] = "COALESCE(p.error_class,m.error_class)"
		case "response_header_at_ms", "first_event_at_ms", "first_semantic_at_ms":
			columns[i] = "CASE WHEN p." + col + ">0 THEN p." + col + " ELSE m." + col + " END"
		}
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := db.QueryContext(ctx, "SELECT m.owner_id,"+strings.Join(columns, ",")+",p.id IS NOT NULL FROM "+table+" m LEFT JOIN probe_execution p ON p.id=m.execution_id WHERE m.owner_id IN ("+strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")+")", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		id, m, err := scanAttemptMetadata(rows)
		if err != nil {
			return nil, err
		}
		result[id] = m
	}
	return result, rows.Err()
}

func attachRequestLogMetadata(ctx context.Context, db schemaQuerier, logs []*model.RequestLog) error {
	ids := make([]int64, len(logs))
	for i, row := range logs {
		ids[i] = row.ID
		row.Metadata = model.UnknownAttemptMetadata()
	}
	values, err := loadAttemptMetadata(ctx, db, "request_log_metadata", ids)
	if err != nil {
		return err
	}
	for _, row := range logs {
		if m, ok := values[row.ID]; ok {
			row.Metadata = m
		}
	}
	return nil
}
