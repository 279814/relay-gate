package store

import (
	"context"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func canaryCostFixture(t *testing.T, st *Store, route *model.Route, id string, sent bool, outputPresent bool) model.ProbeExecution {
	t.Helper()
	e := model.ProbeExecution{ID: id, Trigger: model.TriggerManual, UpstreamID: route.UpstreamID, RouteID: route.ID,
		Endpoint: model.EndpointMessages, RecipeBindingUse: model.BindingResolved, RecipeStorage: model.RecipeStorageEmbedded, RecipeOrigin: model.RecipeBasic,
		TemplateID: "builtin:canary-v1", RecipeIdentityRevision: 1, EvidenceHash: "synthetic-" + id, ErrorClass: model.ErrorNone, Capability: model.CapabilityUnknown,
		Scope: model.ScopeRouteEndpoint, Final: true, Success: true, ObservationOrder: 1, DoneAtMS: 1792368001000, EstimatedInputTokens: 12,
		ReachabilityDisposition: model.ApplyNotApplicable, CapabilityDisposition: model.ApplyNotApplicable}
	if sent {
		e.SentAtMS = 1792368000000
	}
	tx, err := st.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := insertProbeExecutionTx(context.Background(), tx, &e); err != nil {
		t.Fatal(err)
	}
	verdict := "passed"
	if !sent {
		verdict = "not_sent"
	}
	if _, err := tx.Exec(`INSERT INTO canary_execution(execution_id,source,policy_revision,expectation_version,nonce_sha256,expected_tool,verdict,nonce_matched,tool_matched,output_usage_present,evidence_hash) VALUES(?,'manual',0,1,?,'relay_canary_noop',?,1,1,?,?)`, id, strings.Repeat("a", 64), verdict, outputPresent, strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestCanaryCostUsesExistingEventGateAndSeparateDaily(t *testing.T) {
	st := testStore(t)
	e := canaryCostFixture(t, st, mkRoute(t, st), "canary-cost", true, true)
	for range 2 {
		tx, err := st.db.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := recordExecutionCostTx(context.Background(), tx, e); err != nil || !ok {
			tx.Rollback()
			t.Fatalf("charge=%v %v", ok, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	var requests, input, output, unknown int
	if err := st.db.QueryRow(`SELECT requests,estimated_input_tokens,observed_output_tokens,unknown_output_rows FROM canary_cost_daily`).Scan(&requests, &input, &output, &unknown); err != nil || requests != 1 || input != 12 || output != 0 || unknown != 0 {
		t.Fatalf("Canary daily=%d/%d/%d unknown=%d err=%v", requests, input, output, unknown, err)
	}
	if n := retentionCount(t, st, "probe_cost_daily"); n != 0 {
		t.Fatalf("Canary cost mixed into Recipe ledger: %d", n)
	}
	var source string
	if err := st.db.QueryRow(`SELECT canary_source FROM probe_cost_event WHERE event_id=?`, "execution:"+e.ID).Scan(&source); err != nil || source != "manual" {
		t.Fatalf("missing authoritative event source: %q %v", source, err)
	}
	if _, err := st.db.Exec(`UPDATE canary_execution SET source='periodic',policy_revision=1 WHERE execution_id=?`, e.ID); err != nil {
		t.Fatal(err)
	}
	tx, err := st.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := recordExecutionCostTx(context.Background(), tx, e); err != ErrIdempotencyConflict {
		t.Fatalf("changed Canary source silently replayed: %v", err)
	}
}

func TestCanaryCostUnknownZeroAndUnsentStayDistinct(t *testing.T) {
	st := testStore(t)
	route := mkRoute(t, st)
	for _, test := range []struct {
		id            string
		sent, present bool
	}{{"known-zero", true, true}, {"unknown-zero", true, false}, {"not-sent", false, false}} {
		e := canaryCostFixture(t, st, route, test.id, test.sent, test.present)
		tx, err := st.db.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = recordExecutionCostTx(context.Background(), tx, e)
		if err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	var requests, unknown int
	if err := st.db.QueryRow(`SELECT SUM(requests),SUM(unknown_output_rows) FROM canary_cost_daily`).Scan(&requests, &unknown); err != nil || requests != 2 || unknown != 1 {
		t.Fatalf("unknown/unsent cost=%d/%d %v", requests, unknown, err)
	}
	if n := retentionCount(t, st, "probe_cost_event"); n != 2 {
		t.Fatalf("unsent Canary charged: %d", n)
	}
}

func TestCanaryCostRetentionSharesSealAndGlobalBatch(t *testing.T) {
	st := testStore(t)
	e := canaryCostFixture(t, st, mkRoute(t, st), "canary-closed-day", true, false)
	e.SentAtMS = retentionNow.AddDate(0, 0, -800).UnixMilli()
	e.DoneAtMS = e.SentAtMS + 1
	tx, err := st.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recordExecutionCostTx(context.Background(), tx, e); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if n, err := st.PruneProbeCostHistory(context.Background(), retentionNow, 1); err != nil || n != 1 {
			t.Fatalf("Canary retention batch=%d err=%v", n, err)
		}
	}
	if n := retentionCount(t, st, "canary_cost_daily") + retentionCount(t, st, "probe_cost_event"); n != 0 {
		t.Fatalf("Canary history escaped shared retention: %d", n)
	}
	tx, err = st.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if charged, err := recordExecutionCostTx(context.Background(), tx, e); err != nil || charged {
		t.Fatalf("closed Canary day resurrected: %v %v", charged, err)
	}
}
