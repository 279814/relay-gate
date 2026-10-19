package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

const auditEventColumns = `id,operation_id,at_ms,finished_at_ms,category,action,resource_type,resource_id,actor_hash,outcome,reason_code`

var ErrAuditUnavailable = errors.New("持久审计不可用")

func (s *Store) BeginAuditEvent(ctx context.Context, action, resourceID, actorHash string) (int64, error) {
	event, err := prepareAuditEvent(action, resourceID, actorHash)
	if err != nil {
		return 0, err
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO audit_event(operation_id,at_ms,category,action,resource_type,resource_id,actor_hash)
		VALUES (?,?,?,?,?,?,?)`, event.OperationID, event.AtMS, event.Category, event.Action, event.ResourceType, event.ResourceID, event.ActorHash)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func prepareAuditEvent(action, resourceID, actorHash string) (*model.AuditEvent, error) {
	spec, ok := model.AuditActionSpec(action)
	actor, err := hex.DecodeString(actorHash)
	if !ok || !validAuditResourceID(resourceID) || err != nil || len(actor) != 32 || actorHash != strings.ToLower(actorHash) {
		return nil, model.WrapValidation("审计动作、资源或参与者标识无效")
	}
	var operation [16]byte
	if _, err := rand.Read(operation[:]); err != nil {
		return nil, err
	}
	return &model.AuditEvent{OperationID: hex.EncodeToString(operation[:]), AtMS: nowMS(), Category: spec.Category, Action: action, ResourceType: spec.ResourceType, ResourceID: resourceID, ActorHash: actorHash}, nil
}

func calibrationAuditActor() string {
	sum := sha256.Sum256([]byte("relay-gate:audit-actor:v1:calibration"))
	return hex.EncodeToString(sum[:])
}

func insertCalibrationPublishAuditTx(ctx context.Context, tx *sql.Tx, runID string) error {
	event, err := prepareAuditEvent("calibration_publish", runID, calibrationAuditActor())
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_event(operation_id,at_ms,finished_at_ms,category,action,resource_type,resource_id,actor_hash,outcome)
		VALUES (?,?,?,?,?,?,?,?,'succeeded')`, event.OperationID, event.AtMS, event.AtMS, event.Category, event.Action, event.ResourceType, event.ResourceID, event.ActorHash)
	return err
}

func (s *Store) recordCalibrationPublishFailure(ctx context.Context, runID string, failure error) error {
	reason := "operation_failed"
	switch {
	case errors.Is(failure, model.ErrValidation):
		reason = "validation"
	case errors.Is(failure, ErrRevisionConflict):
		reason = "conflict"
	case errors.Is(failure, context.Canceled), errors.Is(failure, context.DeadlineExceeded):
		reason = "canceled"
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	id, err := s.BeginAuditEvent(ctx, "calibration_publish", runID, calibrationAuditActor())
	if err != nil {
		return err
	}
	return s.CompleteAuditEvent(ctx, id, "failed", reason)
}

// CompleteAuditEvent cannot turn a failure into success or replay an operation.
// A failed terminal write leaves the durable attempt visibly pending.
func (s *Store) CompleteAuditEvent(ctx context.Context, id int64, outcome, reason string) error {
	return s.completeAuditEvent(ctx, id, "", outcome, reason)
}

// CompleteAuditAction permits only a server-owned refinement in the same
// category/resource, e.g. route_update → route_disable after decoding input.
func (s *Store) CompleteAuditAction(ctx context.Context, id int64, action, outcome, reason string) error {
	if _, ok := model.AuditActionSpec(action); !ok {
		return model.WrapValidation("审计动作无效")
	}
	return s.completeAuditEvent(ctx, id, action, outcome, reason)
}

func (s *Store) completeAuditEvent(ctx context.Context, id int64, action, outcome, reason string) error {
	if id < 1 || !validAuditCompletion(outcome, reason) {
		return model.WrapValidation("审计结果或原因码无效")
	}
	statement := `UPDATE audit_event SET outcome=?,reason_code=?,finished_at_ms=MAX(at_ms,?) WHERE id=? AND outcome='pending'`
	args := []any{outcome, reason, nowMS(), id}
	if action != "" {
		spec, _ := model.AuditActionSpec(action)
		statement = `UPDATE audit_event SET action=?,outcome=?,reason_code=?,finished_at_ms=MAX(at_ms,?) WHERE id=? AND outcome='pending' AND category=? AND resource_type=?`
		args = []any{action, outcome, reason, nowMS(), id, spec.Category, spec.ResourceType}
	}
	result, err := s.db.ExecContext(ctx, statement, args...)
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); err != nil {
		return err
	} else if affected == 1 {
		return nil
	}
	var currentAction, currentOutcome, currentReason string
	if err := s.db.QueryRowContext(ctx, `SELECT action,outcome,reason_code FROM audit_event WHERE id=?`, id).Scan(&currentAction, &currentOutcome, &currentReason); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if currentOutcome == outcome && currentReason == reason && (action == "" || action == currentAction) {
		return nil
	}
	return ErrRevisionConflict
}

func validAuditCompletion(outcome, reason string) bool {
	if outcome == "succeeded" {
		return reason == "" || reason == "activation_pending"
	}
	if outcome == "unknown" {
		return reason == "restart_before_completion" || reason == "forward_recovery_required"
	}
	if outcome != "failed" {
		return false
	}
	switch reason {
	case "validation", "unauthorized", "forbidden", "not_found", "conflict", "unavailable", "canceled", "operation_failed", "rollback_completed", "rollback_failed":
		return true
	}
	return false
}

func validAuditResourceID(value string) bool {
	if len(value) > 128 {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_:.-", r) {
			continue
		}
		return false
	}
	return true
}

func (s *Store) interruptPendingAuditEvents(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE audit_event SET outcome='unknown',reason_code='restart_before_completion',finished_at_ms=MAX(at_ms,?) WHERE outcome='pending'`, nowMS())
	return err
}

func (s *Store) ListAuditEventsPage(ctx context.Context, filter model.AuditEventFilter) (model.Page[*model.AuditEvent], error) {
	empty := model.Page[*model.AuditEvent]{}
	limit, err := normalizePageLimit(filter.Limit)
	if err != nil {
		return empty, err
	}
	if filter.Category != "" && !model.AuditCategoryKnown(filter.Category) || filter.Outcome != "" && !model.AuditOutcomeKnown(filter.Outcome) ||
		filter.ResourceType != "" && !model.AuditResourceKnown(filter.ResourceType) || !validAuditResourceID(filter.ResourceID) ||
		filter.AfterMS < 0 || filter.BeforeMS < 0 || filter.BeforeMS != 0 && filter.AfterMS > filter.BeforeMS {
		return empty, model.WrapValidation("审计筛选无效")
	}
	if filter.Action != "" {
		if _, ok := model.AuditActionSpec(filter.Action); !ok {
			return empty, model.WrapValidation("审计动作无效")
		}
	}
	cursorFilter := filter
	cursorFilter.PageRequest = model.PageRequest{}
	keys, err := decodePageCursor(filter.Cursor, "audit_events", cursorFilter, 2)
	if err != nil {
		return empty, err
	}
	var ceiling, beforeID int64
	if len(keys) == 0 {
		if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(id),0) FROM audit_event`).Scan(&ceiling); err != nil {
			return empty, err
		}
	} else {
		ceiling, err = cursorID(keys[0])
		if err != nil {
			return empty, err
		}
		beforeID, err = cursorID(keys[1])
		if err != nil || beforeID > ceiling {
			return empty, ErrInvalidCursor
		}
	}
	conditions := []string{"id<=?"}
	args := []any{ceiling}
	if beforeID > 0 {
		conditions, args = append(conditions, "id<?"), append(args, beforeID)
	}
	for _, item := range []struct{ column, value string }{{"category", filter.Category}, {"action", filter.Action}, {"outcome", filter.Outcome}, {"resource_type", filter.ResourceType}, {"resource_id", filter.ResourceID}} {
		if item.value != "" {
			conditions, args = append(conditions, item.column+"=?"), append(args, item.value)
		}
	}
	if filter.AfterMS > 0 {
		conditions, args = append(conditions, "at_ms>=?"), append(args, filter.AfterMS)
	}
	if filter.BeforeMS > 0 {
		conditions, args = append(conditions, "at_ms<=?"), append(args, filter.BeforeMS)
	}
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(ctx, `SELECT `+auditEventColumns+` FROM audit_event WHERE `+strings.Join(conditions, " AND ")+` ORDER BY id DESC LIMIT ?`, args...)
	if err != nil {
		return empty, err
	}
	defer rows.Close()
	page := model.Page[*model.AuditEvent]{Items: []*model.AuditEvent{}}
	for rows.Next() {
		event := &model.AuditEvent{}
		if err := rows.Scan(&event.ID, &event.OperationID, &event.AtMS, &event.FinishedAtMS, &event.Category, &event.Action, &event.ResourceType, &event.ResourceID, &event.ActorHash, &event.Outcome, &event.ReasonCode); err != nil {
			return empty, err
		}
		page.Items = append(page.Items, event)
	}
	if err := rows.Err(); err != nil {
		return empty, err
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		page.NextCursor, err = encodePageCursor("audit_events", cursorFilter, strconv.FormatInt(ceiling, 10), strconv.FormatInt(page.Items[len(page.Items)-1].ID, 10))
	}
	return page, err
}
