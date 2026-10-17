package api

import (
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/probe"
)

func TestProbeCostReadsCommittedDailyTotalsWithoutJSONRestore(t *testing.T) {
	s, _ := newTestServer(t)
	if err := s.st.SaveProbeCostRaw(`{"l1_count":9999}`); err != nil {
		t.Fatal(err)
	}
	_, err := s.st.DB().Exec(`INSERT INTO probe_cost_daily(day_utc,trigger,origin,endpoint,upstream_id,requests,succeeded,failed) VALUES(?,'scheduled','compact_native','models',1,3,2,1)`, time.Now().UTC().Format("2006-01-02"))
	if err != nil {
		t.Fatal(err)
	}
	h := s.WithCost(probe.NewDurableCostView(s.st)).Routes(testAdminPW)
	rec := do(t, h, "GET", "/admin/api/probe-cost", "", true)
	var result struct {
		Cost probe.CostSnapshot `json:"cost"`
	}
	result = decodeBody[struct {
		Cost probe.CostSnapshot `json:"cost"`
	}](t, rec)
	if rec.Code != 200 || result.Cost.L1Count != 3 || result.Cost.L1Failed != 1 {
		t.Fatalf("API did not read the committed ledger: %d %s", rec.Code, rec.Body.String())
	}
}
