package store

// CalibrationRun 持久化（§4.10、§P0-11）。
//
// CalibrationService 不直接串联多个 CRUD：候选发送前只调 PrepareCalibrationCandidate；
// 成功只调 CommitCalibrationSuccess；非成功调 AdvanceCalibrationAfterExecution。

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probetemplate"
)

// materializedCandidatePayload 把物化身份与预分配 ExecutionID 一起持久化。
//
// execution_id 列有 FK → probe_execution，prepare 时 execution 尚未存在，
// 因此预分配 ID 只能放在 JSON 里；execution 插入后再回填 execution_id 列。
type materializedCandidatePayload struct {
	Identity             model.RecipeIdentity `json:"identity"`
	RecipeID             int64                `json:"recipe_id"`
	PlannedExecutionID   string               `json:"planned_execution_id"`
	EstimatedInputTokens int64                `json:"estimated_input_tokens,omitempty"`
	SourceTemplateID     string               `json:"source_template_id,omitempty"`
	SourceRevision       int64                `json:"source_revision,omitempty"`
}

// PrepareCalibrationMaterial 是 PrepareCalibrationCandidate 的内容输入。
//
// 由 CalibrationService 根据 SourceRecipe（通常是 embedded compact）给出
// 要物化进 draft DB version 的精确 header/query/body。
type PrepareCalibrationMaterial struct {
	Origin               model.RecipeSource
	Method               string
	FixedRawQuery        string
	Headers              []model.HeaderTemplate
	Body                 []byte
	BodyIsText           bool
	StreamExpected       bool
	TimeoutProfile       model.ProbeTimeoutProfile
	EstimatedInputTokens int64
	SourceTemplateID     string
	SourceRevision       int64
}

func (store *Store) CreateCalibrationRun(ctx context.Context, run *model.CalibrationRun) error {
	if run == nil || run.RouteID < 1 || !run.Endpoint.Valid() {
		return model.WrapValidation("calibration run 参数无效")
	}
	if len(run.Candidates) == 0 || len(run.Candidates) > 3 {
		return model.WrapValidation("calibration 候选数必须在 1..3")
	}
	if run.ID == "" {
		run.ID = newCalibrationID()
	}
	now := nowMS()
	if run.CreatedAt == 0 {
		run.CreatedAt = now
	}
	run.State = model.CalibrationPlanned
	run.Current = 0
	run.Revision = 1
	run.StartedAt = 0
	run.FinishedAt = 0
	run.Selected = nil

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	var routeExists int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM route WHERE id=?`, run.RouteID).Scan(&routeExists); err != nil {
		return err
	}
	if routeExists == 0 {
		return model.WrapValidation("route %d 不存在", run.RouteID)
	}

	if _, err = tx.ExecContext(ctx, `INSERT INTO calibration_run
		(id,route_id,endpoint,state,current_ordinal,selected_ordinal,created_at,started_at,finished_at,revision)
		VALUES (?,?,?,?,?,?,?,0,0,1)`,
		run.ID, run.RouteID, run.Endpoint, run.State, run.Current, nil, run.CreatedAt); err != nil {
		return wrapConstraint(err, "calibration_run")
	}
	for i := range run.Candidates {
		candidate := &run.Candidates[i]
		candidate.Ordinal = i
		candidate.State = model.CalibrationCandidatePlanned
		candidate.Disposition = ""
		candidate.ExecutionID = ""
		candidate.FinishedAt = 0
		candidate.SendStartedAt = 0
		if candidate.AuthMode == "" {
			return model.WrapValidation("candidate %d 缺少 auth_mode", i)
		}
		sourceJSON, marshalErr := json.Marshal(candidate.SourceRecipe)
		if marshalErr != nil {
			return marshalErr
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO calibration_candidate
			(run_id,ordinal,auth_mode,source_recipe_json,materialized_recipe_json,state,execution_id,
			 disposition,send_started_at,finished_at,estimated_input_tokens)
			VALUES (?,?,?,?,?,'planned',NULL,'',0,0,?)`,
			run.ID, i, candidate.AuthMode, string(sourceJSON), "",
			candidate.EstimatedInputTokens); err != nil {
			return wrapConstraint(err, "calibration_candidate")
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (store *Store) GetCalibrationRun(ctx context.Context, id string) (*model.CalibrationRun, error) {
	if id == "" {
		return nil, model.WrapValidation("calibration run id 为空")
	}
	run, err := scanCalibrationRun(store.db.QueryRowContext(ctx, `SELECT id,route_id,endpoint,state,
		current_ordinal,selected_ordinal,created_at,started_at,finished_at,revision
		FROM calibration_run WHERE id=?`, id))
	if err != nil {
		return nil, err
	}
	candidates, err := store.loadCalibrationCandidates(ctx, store.db, id)
	if err != nil {
		return nil, err
	}
	run.Candidates = candidates
	if run.Selected != nil {
		for i := range candidates {
			if candidates[i].Ordinal == run.Selected.Ordinal {
				selected := candidates[i]
				run.Selected = &selected
				break
			}
		}
	}
	return run, nil
}

func (store *Store) ListCalibrationRunsPage(ctx context.Context, filter model.CalibrationFilter) (model.Page[*model.CalibrationRun], error) {
	limit, err := normalizePageLimit(filter.Limit)
	if err != nil {
		return model.Page[*model.CalibrationRun]{}, err
	}
	cursorFilter := filter
	cursorFilter.PageRequest = model.PageRequest{}
	keys, err := decodePageCursor(filter.Cursor, "calibrations", cursorFilter, 2)
	if err != nil {
		return model.Page[*model.CalibrationRun]{}, err
	}
	conditions := []string{"1=1"}
	args := make([]any, 0, 8)
	if filter.RouteID > 0 {
		conditions = append(conditions, "route_id=?")
		args = append(args, filter.RouteID)
	}
	if filter.Endpoint != "" {
		if !filter.Endpoint.Valid() {
			return model.Page[*model.CalibrationRun]{}, model.WrapValidation("endpoint filter 无效")
		}
		conditions = append(conditions, "endpoint=?")
		args = append(args, filter.Endpoint)
	}
	if filter.State != "" {
		conditions = append(conditions, "state=?")
		args = append(args, filter.State)
	}
	if len(keys) == 2 {
		createdAt, parseErr := strconv.ParseInt(keys[0], 10, 64)
		if parseErr != nil {
			return model.Page[*model.CalibrationRun]{}, ErrInvalidCursor
		}
		id := keys[1]
		conditions = append(conditions, "(created_at<? OR (created_at=? AND id<?))")
		args = append(args, createdAt, createdAt, id)
	}
	args = append(args, limit+1)
	rows, err := store.db.QueryContext(ctx, `SELECT id,route_id,endpoint,state,current_ordinal,selected_ordinal,
		created_at,started_at,finished_at,revision FROM calibration_run WHERE `+
		strings.Join(conditions, " AND ")+` ORDER BY created_at DESC, id DESC LIMIT ?`, args...)
	if err != nil {
		return model.Page[*model.CalibrationRun]{}, err
	}
	defer rows.Close()
	items := make([]*model.CalibrationRun, 0, limit+1)
	for rows.Next() {
		item, scanErr := scanCalibrationRun(rows)
		if scanErr != nil {
			return model.Page[*model.CalibrationRun]{}, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return model.Page[*model.CalibrationRun]{}, err
	}
	page := model.Page[*model.CalibrationRun]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor, err = encodePageCursor("calibrations", cursorFilter,
			strconv.FormatInt(last.CreatedAt, 10), last.ID)
		if err != nil {
			return model.Page[*model.CalibrationRun]{}, err
		}
	}
	for _, item := range page.Items {
		candidates, loadErr := store.loadCalibrationCandidates(ctx, store.db, item.ID)
		if loadErr != nil {
			return model.Page[*model.CalibrationRun]{}, loadErr
		}
		item.Candidates = candidates
	}
	return page, nil
}

func (store *Store) StartCalibrationRun(ctx context.Context, id string, expectedRevision int64) error {
	if id == "" || expectedRevision < 1 {
		return model.WrapValidation("start calibration 参数无效")
	}
	now := nowMS()
	result, err := store.db.ExecContext(ctx, `UPDATE calibration_run SET state='running',started_at=?,
		revision=revision+1 WHERE id=? AND revision=? AND state IN ('planned','running')`,
		now, id, expectedRevision)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 1 {
		return nil
	}
	run, getErr := store.GetCalibrationRun(ctx, id)
	if getErr != nil {
		return getErr
	}
	if run.State == model.CalibrationRunning && run.Revision == expectedRevision+1 {
		return nil // 幂等：已 start
	}
	if run.Revision != expectedRevision {
		return ErrRevisionConflict
	}
	return model.WrapValidation("calibration run 状态为 %s，不能 start", run.State)
}

// PrepareCalibrationCandidate 物化 draft DB version、预分配 ExecutionID，candidate→prepared。
//
// 任一步失败全部回滚且不发网。未发送的候选不会物化。
func (store *Store) PrepareCalibrationCandidate(ctx context.Context, runID string, ordinal int,
	expectedRunRevision int64, material PrepareCalibrationMaterial) (version *model.ProbeRecipeVersion, err error) {

	if runID == "" || ordinal < 0 || expectedRunRevision < 1 {
		return nil, model.WrapValidation("prepare calibration 参数无效")
	}
	if !material.Origin.Valid() || material.Method == "" || !material.TimeoutProfile.Valid() {
		return nil, model.WrapValidation("prepare material 无效")
	}

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	run, err := scanCalibrationRun(tx.QueryRowContext(ctx, `SELECT id,route_id,endpoint,state,
		current_ordinal,selected_ordinal,created_at,started_at,finished_at,revision
		FROM calibration_run WHERE id=?`, runID))
	if err != nil {
		return nil, err
	}
	if run.State != model.CalibrationRunning {
		return nil, model.WrapValidation("calibration run 状态为 %s，不能 prepare", run.State)
	}
	if run.Revision != expectedRunRevision {
		return nil, ErrRevisionConflict
	}
	if run.Current != ordinal {
		return nil, model.WrapValidation("current ordinal=%d，不能 prepare %d", run.Current, ordinal)
	}

	candidate, err := loadCalibrationCandidateTx(ctx, tx, runID, ordinal)
	if err != nil {
		return nil, err
	}
	switch candidate.State {
	case model.CalibrationCandidatePrepared, model.CalibrationCandidateSendStarted,
		model.CalibrationCandidateFinished, model.CalibrationCandidateIndeterminate:
		// 幂等：已 prepared 及以上则返回已有 version，不新建。
		if candidate.MaterializedRecipe.Storage == model.RecipeStorageDB && candidate.MaterializedRecipe.DBVersionID > 0 {
			version, err = scanRecipeVersion(tx.QueryRowContext(ctx, `SELECT `+recipeVersionCols+
				` FROM probe_recipe_version WHERE id=?`, candidate.MaterializedRecipe.DBVersionID))
			if err != nil {
				return nil, err
			}
			return version, tx.Commit()
		}
		return nil, model.WrapValidation("candidate %d 状态为 %s 但缺少 materialized version", ordinal, candidate.State)
	case model.CalibrationCandidatePlanned:
		// continue
	default:
		return nil, model.WrapValidation("candidate %d 状态为 %s，不能 prepare", ordinal, candidate.State)
	}

	recipeID, err := ensureCalibrationRecipeTx(ctx, tx, run.RouteID, run.Endpoint)
	if err != nil {
		return nil, err
	}
	recipe, err := scanProbeRecipe(tx.QueryRowContext(ctx, `SELECT `+recipeCols+
		` FROM probe_recipe WHERE id=?`, recipeID))
	if err != nil {
		return nil, err
	}

	version = &model.ProbeRecipeVersion{
		RecipeID:       recipeID,
		Origin:         material.Origin,
		Method:         material.Method,
		FixedRawQuery:  material.FixedRawQuery,
		Headers:        material.Headers,
		Body:           material.Body,
		BodyIsText:     material.BodyIsText,
		StreamExpected: material.StreamExpected,
		TimeoutProfile: material.TimeoutProfile,
	}
	if err = addRecipeVersionTx(ctx, tx, version, recipe.Revision); err != nil {
		return nil, err
	}

	plannedID := newCalibrationID()
	payload := materializedCandidatePayload{
		Identity: model.RecipeIdentity{
			Storage: model.RecipeStorageDB, Origin: material.Origin, DBVersionID: version.ID,
		},
		RecipeID:             recipeID,
		PlannedExecutionID:   plannedID,
		EstimatedInputTokens: material.EstimatedInputTokens,
		SourceTemplateID:     material.SourceTemplateID,
		SourceRevision:       material.SourceRevision,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	est := material.EstimatedInputTokens
	if est == 0 {
		est = candidate.EstimatedInputTokens
	}
	result, err := tx.ExecContext(ctx, `UPDATE calibration_candidate SET state='prepared',
		materialized_recipe_json=?,estimated_input_tokens=? WHERE run_id=? AND ordinal=? AND state='planned'`,
		string(payloadJSON), est, runID, ordinal)
	if err != nil {
		return nil, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, ErrRevisionConflict
	}
	// bump run revision so CAS callers see prepare happened
	bump, err := tx.ExecContext(ctx, `UPDATE calibration_run SET revision=revision+1 WHERE id=? AND revision=?`,
		runID, expectedRunRevision)
	if err != nil {
		return nil, err
	}
	if affected, _ := bump.RowsAffected(); affected != 1 {
		return nil, ErrRevisionConflict
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return version, nil
}

func (store *Store) MarkCalibrationSendStarted(ctx context.Context, runID string, ordinal int,
	executionID string, expectedRunRevision int64) error {

	if runID == "" || ordinal < 0 || executionID == "" || expectedRunRevision < 1 {
		return model.WrapValidation("mark send_started 参数无效")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	run, err := scanCalibrationRun(tx.QueryRowContext(ctx, `SELECT id,route_id,endpoint,state,
		current_ordinal,selected_ordinal,created_at,started_at,finished_at,revision
		FROM calibration_run WHERE id=?`, runID))
	if err != nil {
		return err
	}
	if run.Revision != expectedRunRevision {
		return ErrRevisionConflict
	}
	if run.State != model.CalibrationRunning {
		return model.WrapValidation("calibration run 状态为 %s", run.State)
	}
	candidate, err := loadCalibrationCandidateTx(ctx, tx, runID, ordinal)
	if err != nil {
		return err
	}
	if candidate.State == model.CalibrationCandidateSendStarted {
		planned, _ := plannedExecutionID(candidate)
		if planned == executionID || candidate.ExecutionID == executionID {
			return tx.Commit() // 幂等
		}
		return model.WrapValidation("candidate 已 send_started，execution_id 不匹配")
	}
	if candidate.State != model.CalibrationCandidatePrepared {
		return model.WrapValidation("candidate 状态为 %s，不能 mark send_started", candidate.State)
	}
	planned, err := plannedExecutionID(candidate)
	if err != nil {
		return err
	}
	if planned != executionID {
		return model.WrapValidation("execution_id 与 prepare 预分配的不一致")
	}
	now := nowMS()
	result, err := tx.ExecContext(ctx, `UPDATE calibration_candidate SET state='send_started',send_started_at=?
		WHERE run_id=? AND ordinal=? AND state='prepared'`, now, runID, ordinal)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrRevisionConflict
	}
	bump, err := tx.ExecContext(ctx, `UPDATE calibration_run SET revision=revision+1 WHERE id=? AND revision=?`,
		runID, expectedRunRevision)
	if err != nil {
		return err
	}
	if affected, _ := bump.RowsAffected(); affected != 1 {
		return ErrRevisionConflict
	}
	return tx.Commit()
}

// InterruptCalibrationCandidate 把 send_started 且无 execution 的候选标为 indeterminate，run→interrupted。
func (store *Store) InterruptCalibrationCandidate(ctx context.Context, runID string, ordinal int,
	expectedRunRevision int64) error {

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	run, err := scanCalibrationRun(tx.QueryRowContext(ctx, `SELECT id,route_id,endpoint,state,
		current_ordinal,selected_ordinal,created_at,started_at,finished_at,revision
		FROM calibration_run WHERE id=?`, runID))
	if err != nil {
		return err
	}
	if run.Revision != expectedRunRevision {
		return ErrRevisionConflict
	}
	candidate, err := loadCalibrationCandidateTx(ctx, tx, runID, ordinal)
	if err != nil {
		return err
	}
	if candidate.State == model.CalibrationCandidateIndeterminate && run.State == model.CalibrationInterrupted {
		return tx.Commit() // 幂等
	}
	if run.State != model.CalibrationRunning {
		return model.WrapValidation("calibration run 状态为 %s，不能 interrupt", run.State)
	}
	if candidate.State != model.CalibrationCandidateSendStarted {
		return model.WrapValidation("candidate 状态为 %s，不能 interrupt", candidate.State)
	}
	now := nowMS()
	candResult, err := tx.ExecContext(ctx, `UPDATE calibration_candidate SET state='indeterminate',finished_at=?,
		disposition='stop' WHERE run_id=? AND ordinal=? AND state='send_started'`,
		now, runID, ordinal)
	if err != nil {
		return err
	}
	if affected, _ := candResult.RowsAffected(); affected != 1 {
		return ErrRevisionConflict
	}
	result, err := tx.ExecContext(ctx, `UPDATE calibration_run SET state='interrupted',finished_at=?,
		revision=revision+1 WHERE id=? AND revision=? AND state='running'`,
		now, runID, expectedRunRevision)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrRevisionConflict
	}
	return tx.Commit()
}

func (store *Store) AdvanceCalibrationAfterExecution(ctx context.Context, runID string, ordinal int,
	executionID string, expectedRunRevision int64) (*model.CalibrationRun, error) {

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	run, err := scanCalibrationRun(tx.QueryRowContext(ctx, `SELECT id,route_id,endpoint,state,
		current_ordinal,selected_ordinal,created_at,started_at,finished_at,revision
		FROM calibration_run WHERE id=?`, runID))
	if err != nil {
		return nil, err
	}
	if run.Revision != expectedRunRevision {
		return nil, ErrRevisionConflict
	}
	if run.State != model.CalibrationRunning {
		// 幂等：已终态则直接返回
		_ = tx.Rollback()
		return store.GetCalibrationRun(ctx, runID)
	}

	candidate, err := loadCalibrationCandidateTx(ctx, tx, runID, ordinal)
	if err != nil {
		return nil, err
	}
	if candidate.State == model.CalibrationCandidateFinished {
		_ = tx.Rollback()
		return store.GetCalibrationRun(ctx, runID)
	}

	execution, err := scanProbeExecution(tx.QueryRowContext(ctx, `SELECT `+probeExecutionCols+
		` FROM probe_execution WHERE id=?`, executionID))
	if err != nil {
		return nil, err
	}
	if execution.CalibrationRunID != runID || execution.CandidateOrdinal != ordinal {
		return nil, model.WrapValidation("execution 与 calibration candidate 身份不一致")
	}
	planned, planErr := plannedExecutionID(candidate)
	if planErr != nil {
		return nil, planErr
	}
	if planned != "" && planned != executionID {
		return nil, model.WrapValidation("execution_id 与预分配不一致")
	}
	if candidate.MaterializedRecipe.Storage == model.RecipeStorageDB &&
		candidate.MaterializedRecipe.DBVersionID > 0 &&
		execution.RecipeVersionID != candidate.MaterializedRecipe.DBVersionID {
		return nil, model.WrapValidation("execution 的 DBVersionID 与 materialized recipe 不一致")
	}

	now := nowMS()
	disposition := execution.CandidateDisposition
	if disposition == "" {
		disposition = model.CandidateStop
	}
	result, err := tx.ExecContext(ctx, `UPDATE calibration_candidate SET state='finished',finished_at=?,
		disposition=?,execution_id=? WHERE run_id=? AND ordinal=? AND state IN ('send_started','prepared')`,
		now, disposition, executionID, runID, ordinal)
	if err != nil {
		return nil, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, ErrRevisionConflict
	}

	tryNext := disposition == model.CandidateTryNextAuth || disposition == model.CandidateTryNextShape
	var nextOrdinal sql.NullInt64
	if tryNext {
		nextErr := tx.QueryRowContext(ctx, `SELECT ordinal FROM calibration_candidate
			WHERE run_id=? AND ordinal>? AND state='planned' ORDER BY ordinal LIMIT 1`,
			runID, ordinal).Scan(&nextOrdinal.Int64)
		if nextErr == nil {
			nextOrdinal.Valid = true
		} else if !errors.Is(nextErr, sql.ErrNoRows) {
			return nil, nextErr
		}
	}

	if tryNext && nextOrdinal.Valid {
		if _, err = tx.ExecContext(ctx, `UPDATE calibration_run SET current_ordinal=?,revision=revision+1
			WHERE id=? AND revision=?`, nextOrdinal.Int64, runID, expectedRunRevision); err != nil {
			return nil, err
		}
	} else {
		finalState := model.CalibrationFailed
		// 只有「全部候选都是 try_next_auth 且已穷尽」才写 Endpoint config_error。
		// 单个 401/403 仍 unknown；429/5xx/timeout 的 stop 不升 config_error。
		if disposition == model.CandidateTryNextAuth && !nextOrdinal.Valid {
			if err = writeAuthExhaustedConfigErrorTx(ctx, tx, run); err != nil {
				return nil, err
			}
		}
		if _, err = tx.ExecContext(ctx, `UPDATE calibration_run SET state=?,finished_at=?,revision=revision+1
			WHERE id=? AND revision=?`, finalState, now, runID, expectedRunRevision); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return store.GetCalibrationRun(ctx, runID)
}

func (store *Store) CommitCalibrationSuccess(ctx context.Context, commit model.CalibrationCommit) (*model.ProbeRecipeVersion, error) {
	if commit.RunID == "" || commit.ExecutionID == "" || commit.ExpectedRunRevision < 1 ||
		commit.SelectedVersionID < 1 || commit.RecipeID < 1 {
		return nil, model.WrapValidation("commit calibration 参数无效")
	}

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	run, err := scanCalibrationRun(tx.QueryRowContext(ctx, `SELECT id,route_id,endpoint,state,
		current_ordinal,selected_ordinal,created_at,started_at,finished_at,revision
		FROM calibration_run WHERE id=?`, commit.RunID))
	if err != nil {
		return nil, err
	}
	if run.Revision != commit.ExpectedRunRevision {
		return nil, ErrRevisionConflict
	}
	if run.State == model.CalibrationSucceeded {
		version, getErr := scanRecipeVersion(tx.QueryRowContext(ctx, `SELECT `+recipeVersionCols+
			` FROM probe_recipe_version WHERE id=?`, commit.SelectedVersionID))
		if getErr != nil {
			return nil, getErr
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return version, nil
	}
	if run.State != model.CalibrationRunning {
		return nil, model.WrapValidation("calibration run 状态为 %s", run.State)
	}

	candidate, err := loadCalibrationCandidateTx(ctx, tx, commit.RunID, commit.CandidateOrdinal)
	if err != nil {
		return nil, err
	}
	if candidate.MaterializedRecipe.DBVersionID != commit.SelectedVersionID {
		return nil, model.WrapValidation("SelectedVersionID 与 candidate.MaterializedRecipe 不一致")
	}

	execution, err := scanProbeExecution(tx.QueryRowContext(ctx, `SELECT `+probeExecutionCols+
		` FROM probe_execution WHERE id=?`, commit.ExecutionID))
	if err != nil {
		return nil, err
	}
	if !execution.Success {
		return nil, model.WrapValidation("execution 未成功，不能 commit calibration success")
	}
	if execution.RecipeVersionID != commit.SelectedVersionID {
		return nil, model.WrapValidation("execution DBVersionID 与 selected version 不一致")
	}
	if execution.CalibrationRunID != commit.RunID || execution.CandidateOrdinal != commit.CandidateOrdinal {
		return nil, model.WrapValidation("execution 与 candidate 身份不一致")
	}

	endpoint := commit.Endpoint
	if endpoint.ID == 0 {
		return nil, model.WrapValidation("commit 缺少 Endpoint")
	}
	currentEndpoint, err := scanEndpoint(tx.QueryRowContext(ctx, `SELECT `+endpointColumns+
		` FROM upstream_endpoint WHERE id=?`, endpoint.ID))
	if err != nil {
		return nil, err
	}
	if currentEndpoint.Revision != commit.ExpectedEndpointRevision {
		return nil, ErrRevisionConflict
	}

	recipe, err := scanProbeRecipe(tx.QueryRowContext(ctx, `SELECT `+recipeCols+
		` FROM probe_recipe WHERE id=?`, commit.RecipeID))
	if err != nil {
		return nil, err
	}
	if recipe.Revision != commit.ExpectedRecipeRevision {
		return nil, ErrRevisionConflict
	}
	if err = requireRecipeTestExecution(ctx, tx, recipe, commit.SelectedVersionID, commit.ExecutionID, false); err != nil {
		return nil, err
	}

	// 更新 Auth Profile → auto_calibrated + selected mode
	selectedMode := candidate.AuthMode
	endpoint.AuthProfile.Mode = model.AuthModeAutoCalibrated
	endpoint.AuthProfile.CalibratedMode = selectedMode
	endpoint.AuthProfile.SecretRef = currentEndpoint.AuthProfile.SecretRef
	if endpoint.AuthProfile.SecretRef == "" {
		endpoint.AuthProfile.SecretRef = "upstream_api_key"
	}
	endpoint.LegacyCompatRealOnly = false
	endpoint.Revision = currentEndpoint.Revision + 1
	endpoint.AuthProfile.Revision = currentEndpoint.AuthProfile.Revision + 1
	endpoint.UpdatedAt = nowMS()
	manualJSON, err := json.Marshal(endpoint.AuthProfile.ManualHeaders)
	if err != nil {
		return nil, err
	}
	authResult, err := tx.ExecContext(ctx, `UPDATE upstream_endpoint SET
		auth_mode=?,calibrated_mode=?,auth_header_name=?,auth_query_name=?,auth_secret_ref=?,
		auth_manual_headers_json=?,auth_profile_revision=?,revision=?,legacy_compat_real_only=0,updated_at=?
		WHERE id=? AND revision=?`,
		endpoint.AuthProfile.Mode, endpoint.AuthProfile.CalibratedMode, endpoint.AuthProfile.HeaderName,
		endpoint.AuthProfile.QueryName, endpoint.AuthProfile.SecretRef, string(manualJSON),
		endpoint.AuthProfile.Revision, endpoint.Revision, endpoint.UpdatedAt,
		endpoint.ID, commit.ExpectedEndpointRevision)
	if err != nil {
		return nil, wrapConstraint(err, "upstream_endpoint")
	}
	if affected, _ := authResult.RowsAffected(); affected != 1 {
		return nil, ErrRevisionConflict
	}

	// publish 同一 tested version
	now := endpoint.UpdatedAt
	pubResult, err := tx.ExecContext(ctx, `UPDATE probe_recipe SET status='published',
		published_version_id=?,last_test_execution_id=?,last_publish_forced=0,published_at=?,
		revision=revision+1,active_binding_revision=active_binding_revision+1,updated_at=?
		WHERE id=? AND revision=?`, commit.SelectedVersionID, commit.ExecutionID, now, now,
		commit.RecipeID, commit.ExpectedRecipeRevision)
	if err != nil {
		return nil, wrapConstraint(err, "probe_recipe")
	}
	if affected, _ := pubResult.RowsAffected(); affected != 1 {
		return nil, ErrRevisionConflict
	}
	if err = replaceRecipeSecretRefs(ctx, tx, commit.RecipeID, commit.SelectedVersionID); err != nil {
		return nil, err
	}

	// Capability invalidation：删掉旧行（effective unknown）
	if _, err = tx.ExecContext(ctx, `DELETE FROM endpoint_capability
		WHERE ((scope_route_id=? AND scope_route_id IS NOT NULL) OR (scope_upstream_id=? AND scope_upstream_id IS NOT NULL))
		AND endpoint=?`, run.RouteID, currentEndpoint.UpstreamID, run.Endpoint); err != nil {
		return nil, err
	}

	if _, err = tx.ExecContext(ctx, `UPDATE calibration_candidate SET state='finished',finished_at=?,
		disposition='stop',execution_id=? WHERE run_id=? AND ordinal=?`,
		now, commit.ExecutionID, commit.RunID, commit.CandidateOrdinal); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE calibration_run SET state='succeeded',selected_ordinal=?,
		finished_at=?,revision=revision+1 WHERE id=? AND revision=?`,
		commit.CandidateOrdinal, now, commit.RunID, commit.ExpectedRunRevision); err != nil {
		return nil, err
	}

	version, err := scanRecipeVersion(tx.QueryRowContext(ctx, `SELECT `+recipeVersionCols+
		` FROM probe_recipe_version WHERE id=?`, commit.SelectedVersionID))
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return version, nil
}

func (store *Store) FinishCalibrationRun(ctx context.Context, id string, state model.CalibrationState,
	expectedRevision int64) error {

	switch state {
	case model.CalibrationFailed, model.CalibrationCanceled, model.CalibrationInterrupted:
		// ok
	default:
		return model.WrapValidation("finish 只能落到 failed/canceled/interrupted")
	}
	now := nowMS()
	result, err := store.db.ExecContext(ctx, `UPDATE calibration_run SET state=?,finished_at=?,
		revision=revision+1 WHERE id=? AND revision=? AND state IN ('planned','running')`,
		state, now, id, expectedRevision)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 1 {
		return nil
	}
	run, getErr := store.GetCalibrationRun(ctx, id)
	if getErr != nil {
		return getErr
	}
	if run.State == state {
		return nil
	}
	if run.Revision != expectedRevision {
		return ErrRevisionConflict
	}
	return model.WrapValidation("calibration run 状态为 %s，不能 finish 为 %s", run.State, state)
}

// PlannedExecutionID 取出 prepare 时预分配的 execution id。
func (store *Store) PlannedExecutionID(candidate model.CalibrationCandidate) (string, error) {
	return plannedExecutionID(candidate)
}

// MaterializedRecipeID 取出 prepare 时绑定的 calibration-owned recipe id。
func (store *Store) MaterializedRecipeID(ctx context.Context, runID string, ordinal int) (int64, error) {
	payload, err := loadMaterializedPayload(ctx, store.db, runID, ordinal)
	if err != nil {
		return 0, err
	}
	if payload.RecipeID < 1 {
		return 0, model.WrapValidation("candidate 缺少 recipe id")
	}
	return payload.RecipeID, nil
}

func plannedExecutionID(candidate model.CalibrationCandidate) (string, error) {
	if candidate.ExecutionID != "" {
		return candidate.ExecutionID, nil
	}
	return "", model.WrapValidation("candidate 没有预分配 execution id")
}

func writeAuthExhaustedConfigErrorTx(ctx context.Context, tx *sql.Tx, run *model.CalibrationRun) error {
	var upstreamID int64
	if err := tx.QueryRowContext(ctx, `SELECT upstream_id FROM route WHERE id=?`, run.RouteID).Scan(&upstreamID); err != nil {
		return err
	}
	endpoint, err := scanEndpoint(tx.QueryRowContext(ctx, `SELECT `+endpointColumns+
		` FROM upstream_endpoint WHERE upstream_id=? AND endpoint=?`, upstreamID, run.Endpoint))
	if err != nil {
		return err
	}
	var networkRev, credentialRev int64
	if err := tx.QueryRowContext(ctx, `SELECT network_revision,credential_revision FROM upstream WHERE id=?`,
		upstreamID).Scan(&networkRev, &credentialRev); err != nil {
		return err
	}
	now := nowMS()
	selector := model.EvidencePolicySelector{
		Kind: model.EvidenceL2, Endpoint: run.Endpoint, TimeoutProfile: model.TimeoutL2Standard,
	}
	if err := selector.Validate(); err != nil {
		return err
	}
	cap := &model.EndpointCapability{
		ScopeType:                  model.RecipeScopeRoute,
		ScopeID:                    run.RouteID,
		Endpoint:                   run.Endpoint,
		EndpointID:                 endpoint.ID,
		State:                      model.CapabilityConfigError,
		PolicySelector:             selector,
		ObservationToken:           "calibration-auth-exhausted",
		UpstreamNetworkRevision:    networkRev,
		UpstreamCredentialRevision: credentialRev,
		EndpointRevision:           endpoint.Revision,
		AuthProfileRevision:        endpoint.AuthProfile.Revision,
		ObservedAt:                 now,
		ErrorClass:                 model.ErrorAuthRejected,
		RedactedDetail:             "auth_calibration_exhausted",
	}
	return saveCapability(ctx, tx, cap)
}

func ensureCalibrationRecipeTx(ctx context.Context, tx *sql.Tx, routeID int64,
	endpoint model.EndpointKind) (int64, error) {

	var recipeID int64
	err := tx.QueryRowContext(ctx, `SELECT id FROM probe_recipe
		WHERE route_id=? AND endpoint=? AND status='draft' ORDER BY id DESC LIMIT 1`,
		routeID, endpoint).Scan(&recipeID)
	if err == nil {
		return recipeID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	now := nowMS()
	result, err := tx.ExecContext(ctx, `INSERT INTO probe_recipe
		(upstream_id,route_id,endpoint,status,pinned,revision,active_binding_revision,created_at,updated_at)
		VALUES (NULL,?,?,'draft',0,1,1,?,?)`, routeID, endpoint, now, now)
	if err != nil {
		return 0, wrapConstraint(err, "probe_recipe")
	}
	return result.LastInsertId()
}

func scanCalibrationRun(scanner interface{ Scan(...any) error }) (*model.CalibrationRun, error) {
	var run model.CalibrationRun
	var selected sql.NullInt64
	if err := scanner.Scan(&run.ID, &run.RouteID, &run.Endpoint, &run.State, &run.Current, &selected,
		&run.CreatedAt, &run.StartedAt, &run.FinishedAt, &run.Revision); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	if selected.Valid {
		run.Selected = &model.CalibrationCandidate{Ordinal: int(selected.Int64)}
	}
	return &run, nil
}

func (store *Store) loadCalibrationCandidates(ctx context.Context, db interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, runID string) ([]model.CalibrationCandidate, error) {
	rows, err := db.QueryContext(ctx, `SELECT ordinal,auth_mode,source_recipe_json,materialized_recipe_json,
		state,COALESCE(execution_id,''),disposition,send_started_at,finished_at,estimated_input_tokens
		FROM calibration_candidate WHERE run_id=? ORDER BY ordinal`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.CalibrationCandidate, 0, 3)
	for rows.Next() {
		var candidate model.CalibrationCandidate
		var sourceJSON, materialJSON string
		if err := rows.Scan(&candidate.Ordinal, &candidate.AuthMode, &sourceJSON, &materialJSON,
			&candidate.State, &candidate.ExecutionID, &candidate.Disposition,
			&candidate.SendStartedAt, &candidate.FinishedAt, &candidate.EstimatedInputTokens); err != nil {
			return nil, err
		}
		if sourceJSON != "" {
			if err := json.Unmarshal([]byte(sourceJSON), &candidate.SourceRecipe); err != nil {
				return nil, fmt.Errorf("calibration candidate source_recipe: %w", err)
			}
		}
		if materialJSON != "" {
			var payload materializedCandidatePayload
			if err := json.Unmarshal([]byte(materialJSON), &payload); err != nil {
				return nil, fmt.Errorf("calibration candidate materialized_recipe: %w", err)
			}
			candidate.MaterializedRecipe = payload.Identity
			if candidate.ExecutionID == "" {
				candidate.ExecutionID = payload.PlannedExecutionID
			}
			if candidate.EstimatedInputTokens == 0 {
				candidate.EstimatedInputTokens = payload.EstimatedInputTokens
			}
		}
		out = append(out, candidate)
	}
	return out, rows.Err()
}

func loadCalibrationCandidateTx(ctx context.Context, tx *sql.Tx, runID string, ordinal int) (model.CalibrationCandidate, error) {
	var candidate model.CalibrationCandidate
	var sourceJSON, materialJSON string
	err := tx.QueryRowContext(ctx, `SELECT ordinal,auth_mode,source_recipe_json,materialized_recipe_json,
		state,COALESCE(execution_id,''),disposition,send_started_at,finished_at,estimated_input_tokens
		FROM calibration_candidate WHERE run_id=? AND ordinal=?`, runID, ordinal).Scan(
		&candidate.Ordinal, &candidate.AuthMode, &sourceJSON, &materialJSON,
		&candidate.State, &candidate.ExecutionID, &candidate.Disposition,
		&candidate.SendStartedAt, &candidate.FinishedAt, &candidate.EstimatedInputTokens)
	if errors.Is(err, sql.ErrNoRows) {
		return candidate, ErrNotFound
	}
	if err != nil {
		return candidate, err
	}
	if sourceJSON != "" {
		if err := json.Unmarshal([]byte(sourceJSON), &candidate.SourceRecipe); err != nil {
			return candidate, err
		}
	}
	if materialJSON != "" {
		var payload materializedCandidatePayload
		if err := json.Unmarshal([]byte(materialJSON), &payload); err != nil {
			return candidate, err
		}
		candidate.MaterializedRecipe = payload.Identity
		if candidate.ExecutionID == "" {
			candidate.ExecutionID = payload.PlannedExecutionID
		}
		if candidate.EstimatedInputTokens == 0 {
			candidate.EstimatedInputTokens = payload.EstimatedInputTokens
		}
		// stash recipe id into SourceRevision-unused path via TemplateID empty;
		// callers use decodeMaterializedRecipeID from the JSON again when needed.
		_ = payload.RecipeID
	}
	return candidate, nil
}

func loadMaterializedPayload(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, runID string, ordinal int) (materializedCandidatePayload, error) {
	var materialJSON string
	err := q.QueryRowContext(ctx, `SELECT materialized_recipe_json FROM calibration_candidate
		WHERE run_id=? AND ordinal=?`, runID, ordinal).Scan(&materialJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return materializedCandidatePayload{}, ErrNotFound
	}
	if err != nil {
		return materializedCandidatePayload{}, err
	}
	if materialJSON == "" {
		return materializedCandidatePayload{}, model.WrapValidation("candidate 尚未物化")
	}
	var payload materializedCandidatePayload
	if err := json.Unmarshal([]byte(materialJSON), &payload); err != nil {
		return materializedCandidatePayload{}, err
	}
	return payload, nil
}

func loadMaterializedPayloadTx(ctx context.Context, tx *sql.Tx, runID string, ordinal int) (materializedCandidatePayload, error) {
	return loadMaterializedPayload(ctx, tx, runID, ordinal)
}

// addRecipeVersionTx 在已有事务中插入不可变 version（供 PrepareCalibrationCandidate）。
func addRecipeVersionTx(ctx context.Context, tx *sql.Tx, version *model.ProbeRecipeVersion,
	expectedRecipeRevision int64) error {

	recipe, err := scanProbeRecipe(tx.QueryRowContext(ctx, `SELECT `+recipeCols+
		` FROM probe_recipe WHERE id=?`, version.RecipeID))
	if err != nil {
		return err
	}
	if recipe.Revision != expectedRecipeRevision || recipe.Status == model.RecipeArchived {
		return ErrRevisionConflict
	}
	if err := version.ValidateForEndpoint(recipe.Endpoint); err != nil {
		return err
	}
	if !version.Origin.Valid() {
		return model.WrapValidation("recipe origin 无效")
	}
	required, err := probetemplate.ScanRequiredSecrets(recipe.Endpoint, probetemplate.TemplateContent{
		Method: version.Method, RawQuery: version.FixedRawQuery, Headers: version.Headers, Body: version.Body,
	})
	if err != nil {
		return err
	}
	var nextVersion int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0)+1 FROM probe_recipe_version WHERE recipe_id=?`,
		recipe.ID).Scan(&nextVersion); err != nil {
		return err
	}
	headersJSON, err := json.Marshal(version.Headers)
	if err != nil {
		return err
	}
	version.Version = nextVersion
	version.CreatedAt = nowMS()
	result, err := tx.ExecContext(ctx, `INSERT INTO probe_recipe_version
		(recipe_id,version,origin,method,fixed_raw_query,headers_json,body,body_is_text,
		 stream_expected,timeout_profile,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		version.RecipeID, version.Version, version.Origin, version.Method, version.FixedRawQuery,
		string(headersJSON), version.Body, version.BodyIsText, version.StreamExpected,
		version.TimeoutProfile, version.CreatedAt)
	if err != nil {
		return err
	}
	version.ID, err = result.LastInsertId()
	if err != nil {
		return err
	}
	for _, name := range required {
		var id, revision int64
		var fingerprint string
		if err := tx.QueryRowContext(ctx, `SELECT id,revision,fingerprint FROM probe_secret WHERE name=?`, name).
			Scan(&id, &revision, &fingerprint); errors.Is(err, sql.ErrNoRows) {
			return model.WrapValidation("Recipe 引用的 Secret %q 不存在", name)
		} else if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO recipe_version_required_secret
			(recipe_version_id,name,resolved_secret_id,bound_secret_id_snapshot,bound_revision_snapshot,
			 bound_fingerprint_snapshot,bound_name_snapshot) VALUES (?,?,?,?,?,?,?)`,
			version.ID, name, id, id, revision, fingerprint, name); err != nil {
			return err
		}
	}
	update, err := tx.ExecContext(ctx, `UPDATE probe_recipe SET draft_version_id=?,revision=revision+1,updated_at=?
		WHERE id=? AND revision=?`, version.ID, version.CreatedAt, recipe.ID, expectedRecipeRevision)
	if err != nil {
		return err
	}
	if affected, _ := update.RowsAffected(); affected != 1 {
		return ErrRevisionConflict
	}
	return nil
}

var calibrationIDEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func newCalibrationID() string {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("cal-%d", nowMS())
	}
	return strings.ToLower(calibrationIDEncoding.EncodeToString(b[:]))
}
