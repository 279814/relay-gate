package store

import (
	"context"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

func TestCanaryFactsEventAndDailyShareObservationTransaction(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(map[bool]string{false: "execution_only", true: "result_recorder"}[commit], func(t *testing.T) {
			st := testStore(t)
			e := canaryCostFixture(t, st, mkRoute(t, st), "typed-canary", true, true)
			if _, err := st.db.Exec(`DELETE FROM probe_execution WHERE id=?`, e.ID); err != nil {
				t.Fatal(err)
			}
			yes := true
			e.SemanticSeen, e.NormalEndSeen = true, true
			e.Canary = &model.CanaryExecution{ExecutionID: e.ID, Source: model.CanaryManual, ExpectationVersion: 1, NonceSHA256: strings.Repeat("a", 64), ExpectedTool: model.CanaryTool, Verdict: "passed", NonceMatched: &yes, ToolMatched: &yes, OutputUsagePresent: true}
			hash, err := revisioncodec.NewCanaryEvidenceHash(*e.Canary)
			if err != nil {
				t.Fatal(err)
			}
			e.Canary.EvidenceHash = hash
			record := func() error {
				if !commit {
					return st.InsertProbeExecution(context.Background(), &e)
				}
				_, err := st.CommitProbeObservation(context.Background(), &model.ProbeObservation{Execution: e}, &fakeStateReducer{})
				return err
			}
			if _, err := st.db.Exec(`CREATE TRIGGER synthetic_canary_cost_fail BEFORE INSERT ON canary_cost_daily BEGIN SELECT RAISE(FAIL,'synthetic cost failure'); END`); err != nil {
				t.Fatal(err)
			}
			if err := record(); err == nil {
				t.Fatal("Canary observation hid failed durable cost")
			}
			for _, table := range []string{"probe_execution", "canary_execution", "probe_cost_event", "canary_cost_daily"} {
				if n := retentionCount(t, st, table); n != 0 {
					t.Fatalf("%s partially committed: %d", table, n)
				}
			}
			if _, err := st.db.Exec(`DROP TRIGGER synthetic_canary_cost_fail`); err != nil {
				t.Fatal(err)
			}
			if err := record(); err != nil {
				t.Fatal(err)
			}
			if err := record(); err != nil {
				t.Fatal(err)
			}
			var requests int
			if err := st.db.QueryRow(`SELECT requests FROM canary_cost_daily`).Scan(&requests); err != nil || requests != 1 {
				t.Fatalf("Canary replay duplicated cost: %d %v", requests, err)
			}
			loaded, err := st.GetProbeExecution(context.Background(), e.ID)
			if err != nil || loaded.Canary == nil || loaded.Canary.EvidenceHash != hash {
				t.Fatalf("lost typed immutable Canary result: %+v %v", loaded, err)
			}
			e.Canary.Source = model.CanaryPeriodic
			e.Canary.PolicyRevision = 1
			e.Canary.EvidenceHash, _ = revisioncodec.NewCanaryEvidenceHash(*e.Canary)
			if err := record(); err != ErrIdempotencyConflict {
				t.Fatalf("same execution accepted different Canary facts: %v", err)
			}
		})
	}
}
