package probe

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
	"github.com/279814/relay-gate/internal/store"
)

func TestDurableCostRecordsSentAttemptsOnceAcrossColdRestart(t *testing.T) {
	st := calibrationTestStore(t)
	up, _, route := seedCalibrationRoute(t, st)
	now := time.Date(2026, 10, 18, 1, 0, 0, 0, time.UTC)
	recorder := NewExecutionOnlyRecorder(st)
	for index, testCase := range []struct {
		endpoint      model.EndpointKind
		sent, success bool
		input, output int64
	}{
		{model.EndpointModels, true, false, 0, 0},
		{model.EndpointMessages, true, true, 13, 2},
		{model.EndpointMessages, true, false, 7, 0},
		{model.EndpointMessages, false, false, 999, 999},
		{model.EndpointCountTokens, true, false, 0, 0},
	} {
		execution := model.ProbeExecution{
			ID: fmt.Sprintf("cost-recorder-%d", index), Trigger: model.TriggerScheduled,
			UpstreamID: up.ID, RouteID: route.ID, Endpoint: testCase.endpoint,
			RecipeStorage: model.RecipeStorageEmbedded, RecipeOrigin: model.RecipeBasic,
			TemplateID: "builtin:cost-fixture", RecipeIdentityRevision: 1,
			RecipeBindingUse: model.BindingResolved, RecipeBindingFacts: model.RecipeBindingFacts{
				Use: model.BindingResolved, ResolvedLayer: model.ResolvedEmbedded,
			},
			DoneAtMS: now.UnixMilli() + 1, ObservationOrder: int64(index + 1),
			ErrorClass: model.ErrorTransient, Scope: model.ScopeNone, Capability: model.CapabilityUnknown,
			Final: true, Success: testCase.success,
			EstimatedInputTokens: testCase.input, ObservedOutputTokens: testCase.output,
		}
		if testCase.endpoint == model.EndpointModels {
			execution.RouteID = 0
		}
		if testCase.sent {
			execution.SentAtMS, execution.StatusCode = now.UnixMilli(), 500
		} else {
			execution.ErrorClass = model.ErrorConfig
		}
		if testCase.success {
			execution.ErrorClass, execution.StatusCode = model.ErrorNone, 200
		}
		observation := &model.ProbeObservation{Execution: execution}
		hash, err := revisioncodec.NewProbeEvidenceHash(*observation)
		if err != nil {
			t.Fatal(err)
		}
		observation.Execution.EvidenceHash = hash
		for repeated := 0; repeated < 2; repeated++ {
			if _, err := recorder.Record(context.Background(), observation); err != nil {
				t.Fatal(err)
			}
		}
	}
	check := func(st *store.Store) {
		t.Helper()
		view := NewDurableCostView(st)
		view.now = func() time.Time { return now }
		snapshot, err := view.Snapshot(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.L1Count != 1 || snapshot.L1Failed != 1 || snapshot.L2Count != 2 || snapshot.L2Failed != 1 || snapshot.EstTokens != 22 || len(snapshot.Routes) != 1 || len(snapshot.Upstreams) != 1 {
			t.Fatalf("sent, unsent or repeated observations changed durable totals: %+v", snapshot)
		}
	}
	check(st)
	path := st.DatabasePath()
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	cipher, err := store.NewCipher("calibration-test-passphrase-16")
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := store.Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	check(restarted)
}
