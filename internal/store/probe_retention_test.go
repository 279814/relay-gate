package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

var retentionNow = time.Date(2026, 10, 18, 15, 40, 0, 0, time.UTC)

func retentionExecution(t *testing.T, st *Store, up *model.Upstream, id string, trigger model.ProbeTrigger, age time.Duration) model.ProbeExecution {
	t.Helper()
	stamp := retentionNow.Add(-age).UnixMilli()
	e := model.ProbeExecution{ID: id, Trigger: trigger, UpstreamID: up.ID,
		UpstreamNetworkRevision: up.NetworkRevision, UpstreamCredentialRevision: up.CredentialRevision,
		Endpoint: model.EndpointModels, RecipeBindingUse: model.BindingResolved,
		RecipeStorage: model.RecipeStorageEmbedded, RecipeOrigin: model.RecipeBasic,
		TemplateID: "builtin:models", RecipeIdentityRevision: 1, EvidenceHash: "evidence:" + id,
		ErrorClass: model.ErrorNone, Capability: model.CapabilityUnknown, Scope: model.ScopeUpstreamReachability,
		Final: true, Success: true, ObservationOrder: 1, SentAtMS: stamp, DoneAtMS: stamp + 1,
		ReachabilityDisposition: model.ApplyNotApplicable, CapabilityDisposition: model.ApplyNotApplicable}
	if trigger == model.TriggerRealTraffic {
		e.RecipeBindingUse = model.BindingRealTrafficContext
		e.RealRequestShapeUnavailableReason = model.ShapeUnsupported
	}
	if err := st.InsertProbeExecution(context.Background(), &e); err != nil {
		t.Fatal(err)
	}
	return e
}

func retentionCount(t *testing.T, st *Store, table string) int {
	t.Helper()
	var n int
	if err := st.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func retentionRecordCost(ctx context.Context, st *Store, e model.ProbeExecution) (bool, error) {
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	charged, err := recordExecutionCostTx(ctx, tx, e)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return charged, nil
}

func TestPruneProbeExecutionsUsesIndependentWindowsAndProtectsReferences(t *testing.T) {
	st := testStore(t)
	_, revision, err := st.GetRunStateWithRevision()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetRunStateWithRevision(model.RunStatePaused, revision); err != nil {
		t.Fatal(err)
	}
	up := mkUpstream(t, st, "retention")
	for _, tc := range []struct {
		id      string
		trigger model.ProbeTrigger
		days    int
	}{
		{"real-old", model.TriggerRealTraffic, 8}, {"real-new", model.TriggerRealTraffic, 6},
		{"auto-old", model.TriggerScheduled, 91}, {"recovery-old", model.TriggerRecovery, 91},
		{"auto-new", model.TriggerScheduled, 89}, {"manual-old", model.TriggerManual, 91},
		{"manual-new", model.TriggerManual, 89}, {"recipe-evidence", model.TriggerManual, 100},
		{"profile-evidence", model.TriggerManual, 100}, {"cal-evidence", model.TriggerCalibration, 100},
	} {
		retentionExecution(t, st, up, tc.id, tc.trigger, time.Duration(tc.days)*24*time.Hour)
	}
	if _, err := st.db.Exec(`INSERT INTO probe_recipe(upstream_id,endpoint,status,last_test_execution_id,created_at,updated_at)
		VALUES (?,'models','draft','recipe-evidence',1,1)`, up.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO client_probe_profile(upstream_id,endpoint,status,client_family,shape_hash,
		last_seen_at,tested_execution_id,created_at,updated_at) VALUES (?,'models','disabled','test','hash',1,'profile-evidence',1,1)`, up.ID); err != nil {
		t.Fatal(err)
	}
	beforeEvents := retentionCount(t, st, "probe_cost_event")
	n, err := st.PruneProbeExecutions(context.Background(), retentionNow, 500)
	if err != nil || n != 4 {
		t.Fatalf("pruned=%d err=%v, want four expired independent records", n, err)
	}
	for _, id := range []string{"real-new", "auto-new", "manual-new", "recipe-evidence", "profile-evidence", "cal-evidence"} {
		if _, err := st.GetProbeExecution(context.Background(), id); err != nil {
			t.Fatalf("protected %s: %v", id, err)
		}
	}
	if got := retentionCount(t, st, "probe_cost_event"); got != beforeEvents {
		t.Fatalf("execution cleanup changed retained cost events: %d != %d", got, beforeEvents)
	}
	if state, _, err := st.GetRunStateWithRevision(); err != nil || state != model.RunStatePaused {
		t.Fatalf("cleanup changed paused state: %s %v", state, err)
	}
}

// Insert a large, recent class in one SQLite statement: the real public method
// must enforce the production limits, not a reduced test-only policy.
func TestPruneProbeExecutionsEnforcesEachProductionRowCap(t *testing.T) {
	for _, tc := range []struct {
		trigger model.ProbeTrigger
		cap     int
	}{
		{model.TriggerRealTraffic, 50000}, {model.TriggerScheduled, 200000}, {model.TriggerManual, 50000},
	} {
		t.Run(string(tc.trigger), func(t *testing.T) {
			st := testStore(t)
			up := mkUpstream(t, st, "row-cap")
			binding, reason := "resolved", ""
			if tc.trigger == model.TriggerRealTraffic {
				binding, reason = "real_traffic_context", "unsupported_shape"
			}
			_, err := st.db.Exec(`WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?)
				INSERT INTO probe_execution(id,trigger,upstream_id,upstream_network_revision,upstream_credential_revision,
				endpoint,recipe_binding_use,recipe_storage,recipe_origin,template_id,recipe_identity_revision,evidence_hash,
				error_class,capability_state,observation_scope,observation_order,reachability_disposition,capability_disposition,
				real_request_shape_unavailable_reason,created_at,done_at_ms)
				SELECT printf('cap-%07d',x),?,?,1,1,'models',?,'embedded','basic_protocol','builtin:models',1,'hash',
				'none','unknown','upstream_reachability',x,'not_applicable','not_applicable',?,?+x,?+x FROM n`,
				tc.cap+3, tc.trigger, up.ID, binding, reason, retentionNow.Add(-time.Hour).UnixMilli(), retentionNow.Add(-time.Hour).UnixMilli())
			if err != nil {
				t.Fatal(err)
			}
			n, err := st.PruneProbeExecutions(context.Background(), retentionNow, 2)
			if err != nil || n != 2 {
				t.Fatalf("pruned=%d err=%v", n, err)
			}
			n, err = st.PruneProbeExecutions(context.Background(), retentionNow, 500)
			if err != nil || n != 1 {
				t.Fatalf("remaining excess=%d err=%v", n, err)
			}
			if got := retentionCount(t, st, "probe_execution"); got != tc.cap {
				t.Fatalf("kept=%d cap=%d", got, tc.cap)
			}
			if _, err := st.GetProbeExecution(context.Background(), "cap-0000001"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("oldest survived: %v", err)
			}
			if _, err := st.GetProbeExecution(context.Background(), fmt.Sprintf("cap-%07d", tc.cap+3)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPruneProbeCostHistorySealsBeforeDeletionAndSurvivesFailureAndRestart(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "cost-retention")
	// Derive the boundary independently: keep the 730 complete days before
	// today, plus today. A day older than those complete days is closed.
	start := time.Date(retentionNow.Year(), retentionNow.Month(), retentionNow.Day(), 0, 0, 0, 0, time.UTC)
	day := start.AddDate(0, 0, -731)
	value := model.ProbeCostDaily{DayUTC: day.Format("2006-01-02"), Trigger: model.TriggerScheduled, Origin: model.RecipeBasic, Endpoint: model.EndpointModels, UpstreamID: up.ID}
	for i := 0; i < 503; i++ {
		if err := st.RecordProbePiggybackSaving(context.Background(), fmt.Sprintf("saving-%d", i), value); err != nil {
			t.Fatal(err)
		}
		e := model.ProbeExecution{ID: fmt.Sprintf("cost-execution-%d", i), Trigger: model.TriggerScheduled,
			RecipeOrigin: model.RecipeBasic, Endpoint: model.EndpointMessages, UpstreamID: up.ID,
			SentAtMS: day.UnixMilli(), DoneAtMS: day.UnixMilli() + 1, Success: true, EstimatedInputTokens: 12}
		if _, err := retentionRecordCost(context.Background(), st, e); err != nil {
			t.Fatal(err)
		}
	}
	open := value
	open.DayUTC = day.AddDate(0, 0, 1).Format("2006-01-02")
	if err := st.RecordProbePiggybackSaving(context.Background(), "open-day", open); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`CREATE TRIGGER fail_cost_prune BEFORE DELETE ON probe_cost_daily BEGIN SELECT RAISE(ABORT,'injected'); END`); err != nil {
		t.Fatal(err)
	}
	if n, err := st.PruneProbeCostHistory(context.Background(), retentionNow, 500); err == nil || n != 0 {
		t.Fatalf("injected prune=%d err=%v", n, err)
	}
	var closed string
	if err := st.db.QueryRow(`SELECT closed_through_day_utc FROM probe_cost_retention_watermark`).Scan(&closed); err != nil {
		t.Fatal(err)
	}
	if closed != value.DayUTC {
		t.Fatalf("watermark must survive delete rollback: %s", closed)
	}
	page, err := st.ListProbeCostDaily(context.Background(), model.ProbeCostFilter{})
	if err != nil || len(page.Items) != 1 || page.Items[0].DayUTC != open.DayUTC {
		t.Fatalf("closed rows visible: %+v err=%v", page, err)
	}
	if _, err := st.db.Exec(`DROP TRIGGER fail_cost_prune`); err != nil {
		t.Fatal(err)
	}
	n, err := st.PruneProbeCostHistory(context.Background(), retentionNow, 5000)
	if err != nil || n != 500 {
		t.Fatalf("batch=%d err=%v", n, err)
	}
	path := st.DatabasePath()
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	cipher, _ := NewCipher("test-passphrase-at-least-16-chars")
	reopened, err := Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	n, err = reopened.PruneProbeCostHistory(context.Background(), retentionNow, 500)
	if err != nil || n != 500 {
		t.Fatalf("resume batch=%d err=%v", n, err)
	}
	n, err = reopened.PruneProbeCostHistory(context.Background(), retentionNow, 500)
	if err != nil || n != 8 {
		t.Fatalf("final batch=%d %v", n, err)
	}
	if err := reopened.RecordProbePiggybackSaving(context.Background(), "saving-0", value); err != nil {
		t.Fatal(err)
	}
	if err := reopened.RecordProbePiggybackSaving(context.Background(), "new-old-event", value); err != nil {
		t.Fatal(err)
	}
	if got := retentionCount(t, reopened, "probe_cost_event"); got != 1 {
		t.Fatalf("sealed day rebuilt events: %d", got)
	}
	if _, err := reopened.PruneProbeCostHistory(context.Background(), retentionNow.Add(-24*time.Hour), 500); err == nil {
		t.Fatal("clock rollback must not reduce watermark")
	}
	page, err = reopened.ListProbeCostDaily(context.Background(), model.ProbeCostFilter{})
	if err != nil || len(page.Items) != 1 || page.Items[0].PiggybackL2Saved != 1 {
		t.Fatalf("open daily changed: %+v err=%v", page, err)
	}
}

func TestPruneCostSealingSerializesConcurrentOldEvidenceReplay(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "seal-race")
	oldDay := retentionNow.AddDate(0, 0, -800)
	e := model.ProbeExecution{ID: "concurrent-old", Trigger: model.TriggerScheduled, RecipeOrigin: model.RecipeBasic,
		Endpoint: model.EndpointModels, UpstreamID: up.ID, SentAtMS: oldDay.UnixMilli(), DoneAtMS: oldDay.UnixMilli() + 1, Success: true}
	if _, err := retentionRecordCost(context.Background(), st, e); err != nil {
		t.Fatal(err)
	}
	value := model.ProbeCostDaily{DayUTC: oldDay.Format("2006-01-02"), Trigger: model.TriggerScheduled, Origin: model.RecipeBasic, Endpoint: model.EndpointModels, UpstreamID: up.ID}
	start := make(chan struct{})
	errs := make(chan error, 12)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := retentionRecordCost(context.Background(), st, e); err != nil {
				errs <- err
				return
			}
			errs <- st.RecordProbePiggybackSaving(context.Background(), "one-saving", value)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		_, err := st.PruneProbeCostHistory(context.Background(), retentionNow, 500)
		errs <- err
	}()
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.PruneProbeCostHistory(context.Background(), retentionNow, 500); err != nil {
		t.Fatal(err)
	}
	if retentionCount(t, st, "probe_cost_event") != 0 || retentionCount(t, st, "probe_cost_daily") != 0 {
		t.Fatal("concurrent old replay recreated sealed history")
	}
}

func TestPruneProbeExecutionsHasOneGlobal500RowBudgetAndCountsNoSendFailures(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "combined-budget")
	for i := 0; i < 510; i++ {
		trigger := model.TriggerManual
		if i%2 == 0 {
			trigger = model.TriggerRealTraffic
		}
		retentionExecution(t, st, up, fmt.Sprintf("batch-%03d", i), trigger, 100*24*time.Hour)
	}
	if _, err := st.db.Exec(`UPDATE probe_execution SET sent_at_ms=0 WHERE trigger='manual'`); err != nil {
		t.Fatal(err)
	}
	// No-send cost changes need their old, synthetic fixture events removed;
	// the janitor rebuilds zero-request evidence from the actual current detail.
	if _, err := st.db.Exec(`DELETE FROM probe_cost_event; DELETE FROM probe_cost_daily`); err != nil {
		t.Fatal(err)
	}
	if n, err := st.PruneProbeExecutions(context.Background(), retentionNow, 9999); err != nil || n != 500 {
		t.Fatalf("combined batch=%d %v", n, err)
	}
	if got := retentionCount(t, st, "probe_execution"); got != 10 {
		t.Fatalf("remaining=%d", got)
	}
	if n, err := st.PruneProbeExecutions(context.Background(), retentionNow, 500); err != nil || n != 10 {
		t.Fatalf("last batch=%d %v", n, err)
	}
	page, err := st.ListProbeCostDaily(context.Background(), model.ProbeCostFilter{})
	if err != nil || len(page.Items) != 1 || page.Items[0].Requests != 0 {
		t.Fatalf("no-send was charged requests: %+v %v", page, err)
	}
}

func TestPruneProbeExecutionsPreservesCostReplayAndRollsBackFailedCostRepair(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "cost-replay")
	e := retentionExecution(t, st, up, "old-synthetic", model.TriggerScheduled, 100*24*time.Hour)
	if _, err := st.db.Exec(`DELETE FROM probe_cost_event; DELETE FROM probe_cost_daily;
		CREATE TRIGGER fail_cost_repair BEFORE INSERT ON probe_cost_event BEGIN SELECT RAISE(ABORT,'injected'); END`); err != nil {
		t.Fatal(err)
	}
	if n, err := st.PruneProbeExecutions(context.Background(), retentionNow, 500); err == nil || n != 0 {
		t.Fatalf("prune without durable cost=%d err=%v", n, err)
	}
	if _, err := st.GetProbeExecution(context.Background(), e.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`DROP TRIGGER fail_cost_repair`); err != nil {
		t.Fatal(err)
	}
	if n, err := st.PruneProbeExecutions(context.Background(), retentionNow, 500); err != nil || n != 1 {
		t.Fatalf("cost repair prune=%d err=%v", n, err)
	}
	if _, err := retentionRecordCost(context.Background(), st, e); err != nil {
		t.Fatal(err)
	}
	conflict := e
	conflict.EstimatedInputTokens++
	if _, err := retentionRecordCost(context.Background(), st, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("replay mismatch=%v", err)
	}
	page, err := st.ListProbeCostDaily(context.Background(), model.ProbeCostFilter{})
	if err != nil || len(page.Items) != 1 || page.Items[0].Requests != 1 {
		t.Fatalf("cost replay changed daily: %+v %v", page, err)
	}
}

func TestPruneRejectsInvalidInputAndCanceledContextWithoutWrites(t *testing.T) {
	st := testStore(t)
	methods := []func(context.Context, time.Time, int) (int, error){st.PruneProbeExecutions, st.PruneProbeCostHistory, st.PruneCalibrationHistory}
	for _, prune := range methods {
		if _, err := prune(context.Background(), time.Time{}, 500); err == nil {
			t.Fatal("zero now accepted")
		}
		if _, err := prune(context.Background(), retentionNow, -1); err == nil {
			t.Fatal("negative budget accepted")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := prune(ctx, retentionNow, 500); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled=%v", err)
		}
	}
}

func retentionRun(t *testing.T, st *Store, up *model.Upstream, routeID int64, id string, state model.CalibrationState, days int) string {
	t.Helper()
	execID := id + "-execution"
	e := retentionExecution(t, st, up, execID, model.TriggerCalibration, time.Duration(days)*24*time.Hour)
	stamp := e.DoneAtMS
	if _, err := st.db.Exec(`INSERT INTO calibration_run(id,route_id,endpoint,state,selected_ordinal,created_at,finished_at)
		VALUES (?,?,'models',?,CASE WHEN ?='succeeded' THEN 0 ELSE NULL END,?,?)`, id, routeID, state, state, stamp-1, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO calibration_candidate(run_id,ordinal,auth_mode,source_recipe_json,state,execution_id,finished_at)
		VALUES (?,0,'bearer','{}','finished',?,?)`, id, execID, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE probe_execution SET calibration_run_id=? WHERE id=?`, id, execID); err != nil {
		t.Fatal(err)
	}
	return execID
}

func TestPruneCalibrationHistoryHonorsTopologyAndCurrentEvidence(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "cal-retention")
	mn := mkModelName(t, st, "cal-retention-model", model.ProtoAnthropic)
	route := &model.Route{ModelNameID: mn.ID, UpstreamID: up.ID, Enabled: true, Priority: 1, Weight: 1}
	if err := st.CreateRoute(route); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id    string
		state model.CalibrationState
		days  int
	}{
		{"expired-failed", model.CalibrationFailed, 100}, {"expired-canceled", model.CalibrationCanceled, 100},
		{"expired-interrupted", model.CalibrationInterrupted, 100}, {"old-success", model.CalibrationSucceeded, 100},
		{"current-success", model.CalibrationSucceeded, 95}, {"running", model.CalibrationRunning, 100},
		{"recent-failed", model.CalibrationFailed, 89}, {"recipe-pinned", model.CalibrationFailed, 100},
		{"profile-pinned", model.CalibrationFailed, 100},
	} {
		retentionRun(t, st, up, route.ID, tc.id, tc.state, tc.days)
	}
	if _, err := st.db.Exec(`INSERT INTO probe_recipe(upstream_id,endpoint,status,last_test_execution_id,created_at,updated_at)
		VALUES (?,'models','published','recipe-pinned-execution',1,1)`, up.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO client_probe_profile(upstream_id,endpoint,status,client_family,shape_hash,last_seen_at,
		tested_execution_id,created_at,updated_at) VALUES (?,'models','tested','test','calhash',1,'profile-pinned-execution',1,1)`, up.ID); err != nil {
		t.Fatal(err)
	}
	// A run+candidate+execution is indivisible. Budget two cannot partially
	// remove the candidate and leave a run whose evidence disappeared.
	if n, err := st.PruneCalibrationHistory(context.Background(), retentionNow, 2); err != nil || n != 0 {
		t.Fatalf("too-small batch=%d %v", n, err)
	}
	if n, err := st.PruneCalibrationHistory(context.Background(), retentionNow, 7); err != nil || n != 6 {
		t.Fatalf("first batch=%d %v", n, err)
	}
	if n, err := st.PruneCalibrationHistory(context.Background(), retentionNow, 500); err != nil || n != 6 {
		t.Fatalf("second batch=%d %v", n, err)
	}
	for _, id := range []string{"expired-failed", "expired-canceled", "expired-interrupted", "old-success"} {
		if _, err := st.GetCalibrationRun(context.Background(), id); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expired %s: %v", id, err)
		}
		if _, err := st.GetProbeExecution(context.Background(), id+"-execution"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expired execution %s: %v", id, err)
		}
	}
	for _, id := range []string{"current-success", "running", "recent-failed", "recipe-pinned", "profile-pinned"} {
		run, err := st.GetCalibrationRun(context.Background(), id)
		if err != nil || len(run.Candidates) != 1 {
			t.Fatalf("protected %s: %+v %v", id, run, err)
		}
		if _, err := st.GetProbeExecution(context.Background(), id+"-execution"); err != nil {
			t.Fatal(err)
		}
	}
	if got := retentionCount(t, st, "probe_recipe"); got != 1 {
		t.Fatalf("recipes changed: %d", got)
	}
	rows, err := st.db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		t.Fatal("retention broke FK")
	}
}

func TestPruneCalibrationHistoryRollsBackWholeTopology(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "cal-rollback")
	mn := mkModelName(t, st, "cal-rollback-model", model.ProtoAnthropic)
	route := &model.Route{ModelNameID: mn.ID, UpstreamID: up.ID, Enabled: true, Priority: 1, Weight: 1}
	if err := st.CreateRoute(route); err != nil {
		t.Fatal(err)
	}
	retentionRun(t, st, up, route.ID, "rollback-run", model.CalibrationFailed, 100)
	if _, err := st.db.Exec(`CREATE TRIGGER fail_run_prune BEFORE DELETE ON calibration_run BEGIN SELECT RAISE(ABORT,'injected'); END`); err != nil {
		t.Fatal(err)
	}
	if n, err := st.PruneCalibrationHistory(context.Background(), retentionNow, 500); err == nil || n != 0 {
		t.Fatalf("injected batch=%d %v", n, err)
	}
	run, err := st.GetCalibrationRun(context.Background(), "rollback-run")
	if err != nil || len(run.Candidates) != 1 {
		t.Fatalf("topology changed: %+v %v", run, err)
	}
	if _, err := st.GetProbeExecution(context.Background(), "rollback-run-execution"); err != nil {
		t.Fatal(err)
	}
}

func TestPruneCalibrationWithUnrelatedExecutionVolumeFitsJanitorDeadline(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "cal-volume")
	mn := mkModelName(t, st, "cal-volume-model", model.ProtoAnthropic)
	route := &model.Route{ModelNameID: mn.ID, UpstreamID: up.ID, Enabled: true, Priority: 1, Weight: 1}
	if err := st.CreateRoute(route); err != nil {
		t.Fatal(err)
	}
	_, err := st.db.Exec(`WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<200000)
		INSERT INTO probe_execution(id,trigger,upstream_id,upstream_network_revision,upstream_credential_revision,
		endpoint,recipe_binding_use,recipe_storage,recipe_origin,template_id,recipe_identity_revision,evidence_hash,
		error_class,capability_state,observation_scope,observation_order,reachability_disposition,capability_disposition,created_at)
		SELECT printf('volume-%07d',x),'scheduled',?,1,1,'models','resolved','embedded','basic_protocol','builtin:models',1,
		'hash','none','unknown','upstream_reachability',x,'not_applicable','not_applicable',? FROM n`, up.ID, retentionNow.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if _, err := st.db.Exec(`INSERT INTO calibration_run(id,route_id,endpoint,state,created_at,finished_at)
			VALUES (?,?,'models','failed',1,1)`, fmt.Sprintf("empty-failed-%03d", i), route.ID); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	n, err := st.PruneCalibrationHistory(ctx, retentionNow, 500)
	t.Logf("200000 unrelated executions + 100 terminal runs: cleanup=%s", time.Since(started))
	if err != nil || n != 100 {
		t.Fatalf("unrelated high-volume execution must not starve calibration cleanup: n=%d err=%v", n, err)
	}
}

func TestPruneCalibration500RowBudgetPreservesImmutableVersions(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "cal-500")
	mn := mkModelName(t, st, "cal-500-model", model.ProtoAnthropic)
	route := &model.Route{ModelNameID: mn.ID, UpstreamID: up.ID, Enabled: true, Priority: 1, Weight: 1}
	if err := st.CreateRoute(route); err != nil {
		t.Fatal(err)
	}
	recipeID, version := mkDraftRecipe(t, st, up)
	for i := 0; i < 170; i++ {
		retentionRun(t, st, up, route.ID, fmt.Sprintf("topology-%03d", i), model.CalibrationFailed, 100)
	}
	if _, err := st.db.Exec(`UPDATE probe_execution SET recipe_storage='db',recipe_id=?,recipe_version_id=?,
		template_id='',recipe_identity_revision=0 WHERE id='topology-000-execution'`, recipeID, version.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := st.PruneCalibrationHistory(context.Background(), retentionNow, 9999); err != nil || n != 498 {
		t.Fatalf("calibration combined batch=%d %v", n, err)
	}
	if n, err := st.PruneCalibrationHistory(context.Background(), retentionNow, 500); err != nil || n != 12 {
		t.Fatalf("calibration remaining batch=%d %v", n, err)
	}
	if _, err := st.GetRecipeVersion(context.Background(), version.ID); err != nil {
		t.Fatalf("immutable version deleted: %v", err)
	}
	if retentionCount(t, st, "calibration_run") != 0 || retentionCount(t, st, "calibration_candidate") != 0 || retentionCount(t, st, "probe_execution") != 0 {
		t.Fatal("terminal topology was not fully pruned")
	}
}

func TestPruneCalibrationPreservesCurrentPublishedVersionEvidence(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "cal-version-pin")
	mn := mkModelName(t, st, "cal-version-pin-model", model.ProtoAnthropic)
	route := &model.Route{ModelNameID: mn.ID, UpstreamID: up.ID, Enabled: true, Priority: 1, Weight: 1}
	if err := st.CreateRoute(route); err != nil {
		t.Fatal(err)
	}
	eid := retentionRun(t, st, up, route.ID, "published-version-run", model.CalibrationFailed, 100)
	recipeID, version := mkDraftRecipe(t, st, up)
	if _, err := st.db.Exec(`UPDATE probe_execution SET recipe_storage='db',recipe_id=?,recipe_version_id=?,
		template_id='',recipe_identity_revision=0 WHERE id=?`, recipeID, version.ID, eid); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE probe_recipe SET status='published',published_version_id=? WHERE id=?`, version.ID, recipeID); err != nil {
		t.Fatal(err)
	}
	if n, err := st.PruneCalibrationHistory(context.Background(), retentionNow, 500); err != nil || n != 0 {
		t.Fatalf("published version's evidence removed=%d %v", n, err)
	}
	if _, err := st.GetCalibrationRun(context.Background(), "published-version-run"); err != nil {
		t.Fatal(err)
	}
}
