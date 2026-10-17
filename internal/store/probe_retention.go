package store

import (
	"context"
	"database/sql"
	"sort"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

const probeRetentionBatch = 500

func retentionBudget(now time.Time, limit int) (int, error) {
	if now.IsZero() || now.UTC().Year() < 1970 || now.UTC().Year() > 9999 || limit <= 0 {
		return 0, model.WrapValidation("retention 需要有效 UTC 时间与正批次上限")
	}
	if limit > probeRetentionBatch {
		limit = probeRetentionBatch
	}
	return limit, nil
}

// These are diagnostic links, not SQL FKs. Keep them even when a Recipe or
// Profile is disabled/archived. Calibration's actual FK is also protected.
const unreferencedExecution = `NOT EXISTS (SELECT 1 FROM probe_recipe r WHERE r.last_test_execution_id=e.id)
	AND NOT EXISTS (SELECT 1 FROM client_probe_profile p WHERE p.tested_execution_id=e.id)
	AND NOT EXISTS (SELECT 1 FROM calibration_candidate c WHERE c.execution_id=e.id)`

type retainedExecution struct {
	id      string
	created int64
}

// PruneProbeExecutions enforces independent real/automatic/manual policies.
// created_at is completion time (DoneAtMS), or insertion time for an unsent
// local failure. Calibration is removed by its own topology-aware transaction.
func (s *Store) PruneProbeExecutions(ctx context.Context, nowUTC time.Time, limit int) (int, error) {
	limit, err := retentionBudget(nowUTC, limit)
	if err != nil {
		return 0, err
	}
	nowUTC = nowUTC.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var candidates []retainedExecution
	for _, policy := range []struct {
		triggers  string
		days, cap int
	}{
		{`'real_traffic'`, 7, 50000}, {`'scheduled','recovery'`, 90, 200000}, {`'manual'`, 90, 50000},
	} {
		rows, err := tx.QueryContext(ctx, `WITH eligible AS MATERIALIZED (
			SELECT id,created_at FROM probe_execution e WHERE trigger IN (`+policy.triggers+`) AND `+unreferencedExecution+`)
			SELECT id,created_at FROM eligible WHERE created_at<? OR id IN
			(SELECT id FROM eligible ORDER BY created_at DESC,id DESC LIMIT -1 OFFSET ?)
			ORDER BY created_at,id LIMIT ?`, nowUTC.AddDate(0, 0, -policy.days).UnixMilli(), policy.cap, limit)
		if err != nil {
			return 0, err
		}
		for rows.Next() {
			var candidate retainedExecution
			if err := rows.Scan(&candidate.id, &candidate.created); err != nil {
				rows.Close()
				return 0, err
			}
			candidates = append(candidates, candidate)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return 0, err
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].created == candidates[j].created {
			return candidates[i].id < candidates[j].id
		}
		return candidates[i].created < candidates[j].created
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	for _, candidate := range candidates {
		execution, err := scanProbeExecution(tx.QueryRowContext(ctx, `SELECT `+probeExecutionCols+` FROM probe_execution WHERE id=?`, candidate.id))
		if err != nil {
			return 0, err
		}
		if err := retainExecutionCost(ctx, tx, execution); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM probe_execution WHERE id=?`, candidate.id); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(candidates), nil
}

// Never lose a sent synthetic execution whose earlier cost write failed. The
// same cost codec/event gate repairs or verifies it before deleting the detail.
func retainExecutionCost(ctx context.Context, tx *sql.Tx, e *model.ProbeExecution) error {
	if e.Trigger == model.TriggerRealTraffic || (e.SentAtMS <= 0 && e.DoneAtMS <= 0) {
		return nil
	}
	_, err := recordExecutionCostTx(ctx, tx, *e)
	return err
}

// PruneProbeCostHistory seals old complete UTC days durably before removing
// any data. Keep the preceding 730 full days plus today; day N-731 is closed.
// A failed data batch deliberately does not undo the already committed seal.
func (s *Store) PruneProbeCostHistory(ctx context.Context, nowUTC time.Time, limit int) (int, error) {
	limit, err := retentionBudget(nowUTC, limit)
	if err != nil {
		return 0, err
	}
	now := nowUTC.UTC()
	closed := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -731).Format("2006-01-02")
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var previous string
	if err := tx.QueryRowContext(ctx, `SELECT closed_through_day_utc FROM probe_cost_retention_watermark WHERE singleton=1`).Scan(&previous); err != nil {
		return 0, err
	}
	if previous != "" {
		parsed, err := time.Parse("2006-01-02", previous)
		if err != nil || parsed.Format("2006-01-02") != previous || closed < previous {
			return 0, model.WrapValidation("retention 水位非法或 UTC 时间回拨")
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE probe_cost_retention_watermark SET closed_through_day_utc=? WHERE singleton=1`, closed); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	tx, err = s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `DELETE FROM probe_cost_daily WHERE rowid IN
		(SELECT rowid FROM probe_cost_daily WHERE day_utc<=? ORDER BY day_utc,rowid LIMIT ?)`, closed, limit)
	if err != nil {
		return 0, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	result, err = tx.ExecContext(ctx, `DELETE FROM probe_cost_event WHERE event_id IN
		(SELECT event_id FROM probe_cost_event WHERE day_utc<=? ORDER BY day_utc,event_id LIMIT ?)`, closed, limit-int(n))
	if err != nil {
		return 0, err
	}
	m, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int(n + m), nil
}

// PruneCalibrationHistory removes a complete terminal topology in one batch.
// The latest successful run is the endpoint Auth provenance (there is no run
// ID on AuthProfile); only a subsequent success can supersede it. Immutable
// RecipeVersions and all current Recipe/Profile evidence remain untouched.
func (s *Store) PruneCalibrationHistory(ctx context.Context, nowUTC time.Time, limit int) (int, error) {
	limit, err := retentionBudget(nowUTC, limit)
	if err != nil {
		return 0, err
	}
	nowUTC = nowUTC.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT cr.id FROM calibration_run cr
		WHERE cr.finished_at>0 AND cr.finished_at<? AND (
		(cr.state IN ('failed','canceled','interrupted') AND cr.selected_ordinal IS NULL)
		OR (cr.state='succeeded' AND EXISTS(SELECT 1 FROM calibration_run newer
		WHERE newer.route_id=cr.route_id AND newer.endpoint=cr.endpoint AND newer.state='succeeded'
		AND (newer.finished_at,newer.created_at,newer.id)>(cr.finished_at,cr.created_at,cr.id))))
		AND NOT EXISTS(SELECT 1 FROM probe_execution e WHERE
		(e.calibration_run_id=cr.id OR e.id IN(SELECT execution_id FROM calibration_candidate WHERE run_id=cr.id))
		AND (EXISTS(SELECT 1 FROM probe_recipe r WHERE r.last_test_execution_id=e.id)
		OR EXISTS(SELECT 1 FROM client_probe_profile p WHERE p.tested_execution_id=e.id)
		OR EXISTS(SELECT 1 FROM calibration_candidate c WHERE c.execution_id=e.id AND c.run_id!=cr.id)
		OR EXISTS(SELECT 1 FROM probe_recipe r WHERE r.published_version_id=e.recipe_version_id)))
		ORDER BY cr.finished_at,cr.id LIMIT ?`, nowUTC.AddDate(0, 0, -90).UnixMilli(), limit)
	if err != nil {
		return 0, err
	}
	var runIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		runIDs = append(runIDs, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	total := 0
	for _, id := range runIDs {
		var candidateCount int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM calibration_candidate WHERE run_id=?`, id).Scan(&candidateCount); err != nil {
			return 0, err
		}
		executionRows, err := tx.QueryContext(ctx, `SELECT id FROM probe_execution WHERE calibration_run_id=?
			OR id IN(SELECT execution_id FROM calibration_candidate WHERE run_id=?) LIMIT ?`, id, id, limit+1)
		if err != nil {
			return 0, err
		}
		var executionIDs []string
		for executionRows.Next() {
			var eid string
			if err := executionRows.Scan(&eid); err != nil {
				executionRows.Close()
				return 0, err
			}
			executionIDs = append(executionIDs, eid)
		}
		err = executionRows.Err()
		executionRows.Close()
		if err != nil {
			return 0, err
		}
		rowCount := 1 + candidateCount + len(executionIDs)
		if total+rowCount > limit {
			continue
		}
		for _, eid := range executionIDs {
			e, err := scanProbeExecution(tx.QueryRowContext(ctx, `SELECT `+probeExecutionCols+` FROM probe_execution WHERE id=?`, eid))
			if err != nil {
				return 0, err
			}
			if err := retainExecutionCost(ctx, tx, e); err != nil {
				return 0, err
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM calibration_candidate WHERE run_id=?`, id); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM calibration_run WHERE id=?`, id); err != nil {
			return 0, err
		}
		for _, eid := range executionIDs {
			if _, err := tx.ExecContext(ctx, `DELETE FROM probe_execution WHERE id=?`, eid); err != nil {
				return 0, err
			}
		}
		total += rowCount
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return total, nil
}
