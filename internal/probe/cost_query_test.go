package probe

import (
	"context"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

func TestDurableCostViewUsesDailyRowsAcrossRestartAndPages(t *testing.T) {
	st := calibrationTestStore(t)
	now := time.Date(2026, 10, 18, 1, 2, 3, 0, time.UTC)
	if err := st.SaveProbeCostRaw(`{"day":"2026-10-18","l1_count":9999}`); err != nil {
		t.Fatal(err)
	}
	for index := int64(1); index <= 205; index++ {
		_, err := st.DB().Exec(`INSERT INTO probe_cost_daily(day_utc,trigger,origin,endpoint,route_id,upstream_id,requests,succeeded,failed,estimated_input_tokens,observed_output_tokens,piggyback_l2_saved) VALUES(?,?,?,?,?,?,3,1,2,10,2,1)`, "2026-10-18", model.TriggerScheduled, model.RecipeCompact, model.EndpointMessages, index, 9)
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err := st.DB().Exec(`INSERT INTO probe_cost_daily(day_utc,trigger,origin,endpoint,upstream_id,requests,succeeded,failed) VALUES(?,?,?,?,9,2,1,1)`, "2026-10-18", model.TriggerScheduled, model.RecipeCompact, model.EndpointModels)
	if err != nil {
		t.Fatal(err)
	}
	for restarted := 0; restarted < 2; restarted++ {
		view := NewDurableCostView(st)
		view.now = func() time.Time { return now }
		snapshot, err := view.Snapshot(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.L1Count != 2 || snapshot.L1Failed != 1 || snapshot.L2Count != 615 || snapshot.L2Failed != 410 || snapshot.EstTokens != 2460 || len(snapshot.Routes) != 205 || snapshot.Routes[0].RouteID != 1 || snapshot.Routes[204].RouteID != 205 {
			t.Fatalf("wrong durable summary: %+v", snapshot)
		}
	}
	raw, err := st.GetProbeCostRaw()
	if err != nil || raw != `{"day":"2026-10-18","l1_count":9999}` {
		t.Fatal("durable query read/wrote the obsolete JSON snapshot")
	}
	view := NewDurableCostView(st)
	view.now = func() time.Time { return now.Add(24 * time.Hour) }
	snapshot, err := view.Snapshot(context.Background())
	if err != nil || snapshot.L1Count+snapshot.L2Count != 0 {
		t.Fatalf("UTC rollover mixed days: %+v %v", snapshot, err)
	}
}

func TestDurableCostViewPropagatesReadFailureInsteadOfZeroOrOldJSON(t *testing.T) {
	st := calibrationTestStore(t)
	view := NewDurableCostView(st)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := view.Snapshot(ctx); err == nil {
		t.Fatal("cancelled durable read returned a fabricated successful snapshot")
	}
}
