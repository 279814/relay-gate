package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

func TestRetentionCountAndOldestQueriesUseIndexesWithoutMaterializingClass(t *testing.T) {
	st := testStore(t)
	for _, tc := range []struct {
		query     string
		args      []any
		selection bool
	}{
		{countRetainedExecutionsSQL, []any{model.TriggerScheduled, model.TriggerScheduled, model.TriggerScheduled, model.TriggerScheduled}, false},
		{oldestRetainedExecutionsSQL + ` ORDER BY created_at,id LIMIT ?`, []any{model.TriggerRecovery, 500}, true},
		{oldestRetainedExecutionsSQL + ` AND created_at<? ORDER BY created_at,id LIMIT ?`, []any{model.TriggerManual, retentionNow.UnixMilli(), 500}, true},
	} {
		rows, err := st.db.Query("EXPLAIN QUERY PLAN "+tc.query, tc.args...)
		if err != nil {
			t.Fatal(err)
		}
		var plans []string
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			plans = append(plans, detail)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			t.Fatal(err)
		}
		plan := strings.Join(plans, "\n")
		if strings.Contains(plan, "MATERIALIZE") || strings.Contains(plan, "SCAN e") || (tc.selection && strings.Contains(plan, "TEMP B-TREE")) {
			t.Fatalf("unbounded class work: %s", plan)
		}
		if tc.selection && !strings.Contains(plan, "idx_probe_execution_trigger_created") {
			t.Fatalf("oldest query lost ordered compound index: %s", plan)
		}
	}
}

func TestRetentionIndexedCountMatchesEligibilityWithDuplicateAndDanglingReferences(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "count-reference")
	for i, trigger := range []model.ProbeTrigger{model.TriggerRealTraffic, model.TriggerScheduled, model.TriggerRecovery, model.TriggerManual} {
		retentionExecution(t, st, up, []string{"protected-count", "scheduled-count", "recovery-count", "manual-count"}[i], trigger, 100*24*time.Hour)
	}
	for _, id := range []string{"protected-count", "missing-execution-history"} {
		if _, err := st.db.Exec(`INSERT INTO probe_recipe(upstream_id,endpoint,status,last_test_execution_id,created_at,updated_at)
			VALUES (?,'models','archived',?,1,1)`, up.ID, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.db.Exec(`INSERT INTO client_probe_profile(upstream_id,endpoint,status,client_family,shape_hash,last_seen_at,
		tested_execution_id,created_at,updated_at) VALUES (?,'models','disabled','fixture','count-shape',1,'protected-count',1,1)`, up.ID); err != nil {
		t.Fatal(err)
	}
	mn := mkModelName(t, st, "count-model", model.ProtoAnthropic)
	route := &model.Route{ModelNameID: mn.ID, UpstreamID: up.ID, Enabled: true, Priority: 1, Weight: 1}
	if err := st.CreateRoute(route); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO calibration_run(id,route_id,endpoint,state,created_at)VALUES ('count-run',?,'models','running',1);
		INSERT INTO calibration_candidate(run_id,ordinal,auth_mode,source_recipe_json,state,execution_id)
		VALUES ('count-run',0,'bearer','{}','finished','protected-count')`, route.ID); err != nil {
		t.Fatal(err)
	}
	for _, trigger := range []model.ProbeTrigger{model.TriggerRealTraffic, model.TriggerScheduled, model.TriggerRecovery, model.TriggerManual} {
		var got, want int
		if err := st.db.QueryRow(countRetainedExecutionsSQL, trigger, trigger, trigger, trigger).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if err := st.db.QueryRow(`SELECT COUNT(*) FROM probe_execution e WHERE trigger=? AND `+unreferencedExecution, trigger).Scan(&want); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("count differs from selection predicate: trigger=%s got=%d want=%d", trigger, got, want)
		}
	}
}

func TestRetentionConcurrentNewCalibrationReferenceIsAtomic(t *testing.T) {
	for attempt := 0; attempt < 10; attempt++ {
		st := testStore(t)
		up := mkUpstream(t, st, "ref-race")
		mn := mkModelName(t, st, "ref-race-model", model.ProtoAnthropic)
		route := &model.Route{ModelNameID: mn.ID, UpstreamID: up.ID, Enabled: true, Priority: 1, Weight: 1}
		if err := st.CreateRoute(route); err != nil {
			t.Fatal(err)
		}
		run := &model.CalibrationRun{RouteID: route.ID, Endpoint: model.EndpointModels, Candidates: []model.CalibrationCandidate{{
			AuthMode: model.AuthModeBearer, SourceRecipe: model.RecipeIdentity{Storage: model.RecipeStorageEmbedded, Origin: model.RecipeBasic, TemplateID: "builtin:models", Revision: 1},
		}}}
		if err := st.CreateCalibrationRun(context.Background(), run); err != nil {
			t.Fatal(err)
		}
		e := retentionExecution(t, st, up, "reference-target", model.TriggerManual, 100*24*time.Hour)
		start := make(chan struct{})
		pruned := make(chan struct {
			n   int
			err error
		}, 1)
		referenced := make(chan error, 1)
		go func() {
			<-start
			n, err := st.PruneProbeExecutions(context.Background(), retentionNow, 500)
			pruned <- struct {
				n   int
				err error
			}{n, err}
		}()
		go func() {
			<-start
			_, err := st.db.Exec(`UPDATE calibration_candidate SET execution_id=? WHERE run_id=? AND ordinal=0`, e.ID, run.ID)
			referenced <- err
		}()
		close(start)
		p, refErr := <-pruned, <-referenced
		if p.err != nil {
			t.Fatal(p.err)
		}
		_, getErr := st.GetProbeExecution(context.Background(), e.ID)
		if refErr == nil {
			if p.n != 0 || getErr != nil {
				t.Fatalf("committed FK reference lost execution: prune=%d get=%v", p.n, getErr)
			}
		} else if p.n != 1 || !errors.Is(getErr, ErrNotFound) || !strings.Contains(strings.ToLower(refErr.Error()), "foreign key") {
			t.Fatalf("delete/reference had no valid serial outcome: prune=%d ref=%v get=%v", p.n, refErr, getErr)
		}
	}
}
