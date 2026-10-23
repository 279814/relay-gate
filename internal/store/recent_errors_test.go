package store

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestRecentErrorsContextAndFilterCursor(t *testing.T) {
	st := testStore(t)
	for i := 0; i < 3; i++ {
		if err := st.InsertRequestLog(&model.RequestLog{ReqID: "metadata-only", Endpoint: "/v1/messages", RouteID: 7, UpstreamID: 8, Outcome: model.OutcomeTimeout, TSRecv: 100}); err != nil {
			t.Fatal(err)
		}
	}
	f := RecentErrorFilter{PageRequest: model.PageRequest{Limit: 1}, RouteID: 7}
	first, err := st.ListRecentErrors(context.Background(), f)
	if err != nil || len(first.Logs) != 1 || first.FailedCount != 3 || first.NextCursor == "" {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := st.ListRecentErrors(ctx, f); !errors.Is(err, context.Canceled) {
		t.Fatalf("context ignored: %v", err)
	}
	for _, change := range []func(*RecentErrorFilter){
		func(f *RecentErrorFilter) { f.RouteID = 8 }, func(f *RecentErrorFilter) { f.UpstreamID = 8 },
		func(f *RecentErrorFilter) { f.Protocol = model.ProtoAnthropic }, func(f *RecentErrorFilter) { f.Outcome = model.OutcomeTimeout },
		func(f *RecentErrorFilter) { f.FromMS = 10 }, func(f *RecentErrorFilter) { f.ToMS = 1000 },
	} {
		changed := f
		changed.Cursor = first.NextCursor
		change(&changed)
		if _, err := st.ListRecentErrors(context.Background(), changed); !errors.Is(err, ErrInvalidCursor) {
			t.Fatalf("changed filter accepted cursor: %v", err)
		}
	}
	f.Cursor = first.NextCursor
	f.Limit = 2
	second, err := st.ListRecentErrors(context.Background(), f)
	if err != nil || len(second.Logs) != 2 || second.NextCursor != "" {
		t.Fatalf("changing page size must preserve filter identity: %+v %v", second, err)
	}
}

func recentCanonicalExecution(upstreamID int64, id string, class model.ErrorClass) model.ProbeExecution {
	return model.ProbeExecution{ID: id, Trigger: model.TriggerRealTraffic, UpstreamID: upstreamID, Endpoint: model.EndpointMessages,
		RecipeBindingUse: model.BindingRealTrafficContext, RecipeStorage: model.RecipeStorageEmbedded, RecipeOrigin: model.RecipeBasic,
		TemplateID: "builtin:messages", RecipeIdentityRevision: 1, ObservationOrder: 1, RealRequestShapeUnavailableReason: model.ShapeUnsupported,
		Final: true, StatusCode: 200, ErrorClass: class, CapabilityDisposition: model.ApplyConfigStale}
}

func TestRecentErrorsCanonicalFactsPairBothWriterOrdersAndSurviveRetention(t *testing.T) {
	for _, observationFirst := range []bool{false, true} {
		t.Run(fmt.Sprint("observation-first=", observationFirst), func(t *testing.T) {
			st := testStore(t)
			up := mkUpstream(t, st, "recent-canonical")
			ctx := context.Background()
			classes := []model.ErrorClass{model.ErrorUnreachable, model.ErrorAuthRejected, model.ErrorShapeRejected, model.ErrorConfig,
				model.ErrorUnsupported, model.ErrorModelNotFound, model.ErrorRateLimited, model.ErrorTransient, model.ErrorFakeAlive, model.ErrorPartial}
			for i, class := range classes {
				id := fmt.Sprintf("canonical-%d", i)
				execution := recentCanonicalExecution(up.ID, id, class)
				row := &model.RequestLog{ReqID: id, Outcome: model.OutcomeOK, RespStatus: 200,
					Metadata: model.AttemptMetadata{Version: 1, ExecutionID: id, CapabilityEffect: "pending"}}
				if observationFirst {
					if err := st.InsertProbeExecution(ctx, &execution); err != nil {
						t.Fatal(err)
					}
				}
				if err := st.InsertRequestLog(row); err != nil {
					t.Fatal(err)
				}
				if !observationFirst {
					page, err := st.ListRecentErrors(ctx, RecentErrorFilter{ErrorClass: class})
					if err != nil || page.FailedCount != 0 || len(page.Logs) != 0 {
						t.Fatalf("uncommitted metadata became a failure: %+v %v", page, err)
					}
					if err := st.InsertProbeExecution(ctx, &execution); err != nil {
						t.Fatal(err)
					}
				}
				page, err := st.ListRecentErrors(ctx, RecentErrorFilter{ErrorClass: class})
				if err != nil || page.FailedCount != 1 || len(page.Logs) != 1 || page.Logs[0].ID != row.ID || page.Logs[0].Outcome != model.OutcomeOK {
					t.Fatalf("class %s did not join its exact committed attempt: %+v %v", class, page, err)
				}
			}
			if err := st.InsertRequestLog(&model.RequestLog{Outcome: model.OutcomeTimeout}); err != nil {
				t.Fatal(err)
			}
			f := RecentErrorFilter{PageRequest: model.PageRequest{Limit: 4}}
			seen := map[int64]bool{}
			for {
				page, err := st.ListRecentErrors(ctx, f)
				if err != nil || page.FailedCount != 11 {
					t.Fatalf("count/page sets diverged: %+v %v", page, err)
				}
				for _, row := range page.Logs {
					if seen[row.ID] {
						t.Fatal("duplicate canonical failure across pages")
					}
					seen[row.ID] = true
				}
				if page.NextCursor == "" {
					break
				}
				f.Cursor = page.NextCursor
			}
			if len(seen) != 11 {
				t.Fatalf("page omitted failures: %d", len(seen))
			}
			if _, err := st.db.Exec(`DELETE FROM probe_execution`); err != nil {
				t.Fatal(err)
			}
			page, err := st.ListRecentErrors(ctx, RecentErrorFilter{ErrorClass: model.ErrorPartial})
			if err != nil || page.FailedCount != 1 || len(page.Logs) != 1 || page.Logs[0].Metadata.ExecutionStored {
				t.Fatalf("retention lost committed failure or invented detail link: %+v %v", page, err)
			}
		})
	}
}

func TestRecentErrorsDoNotInferUncommittedUnknownOrSuccessfulFailures(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "recent-boundaries")
	ctx := context.Background()
	if err := st.InsertRequestLog(&model.RequestLog{ReqID: "legacy-200", Outcome: model.OutcomeOK, RespStatus: 200}); err != nil {
		t.Fatal(err)
	}
	for _, effect := range []string{"unknown", "pending", "unavailable", "dropped", "ignored"} {
		if err := st.InsertRequestLog(&model.RequestLog{ReqID: effect, Outcome: model.OutcomeOK,
			Metadata: model.AttemptMetadata{Version: 1, ExecutionID: "missing-" + effect, CapabilityEffect: effect, ErrorClass: model.ErrorPartial}}); err != nil {
			t.Fatal(err)
		}
	}
	for i, tc := range []struct {
		class   model.ErrorClass
		trigger model.ProbeTrigger
		success bool
	}{
		{model.ErrorNone, model.TriggerRealTraffic, true}, // includes successful ExpectedCancel
		{model.ErrorIgnored, model.TriggerRealTraffic, false},
		{model.ErrorPartial, model.TriggerScheduled, false},  // unrelated synthetic evidence cannot add a real attempt
		{model.ErrorPartial, model.TriggerRealTraffic, true}, // never override explicit success
	} {
		id := fmt.Sprintf("non-failure-%d", i)
		execution := recentCanonicalExecution(up.ID, id, tc.class)
		execution.Trigger, execution.Success = tc.trigger, tc.success
		if tc.trigger != model.TriggerRealTraffic {
			execution.RecipeBindingUse = model.BindingExplicitTest
			execution.RealRequestShapeUnavailableReason = ""
			execution.DoneAtMS = 1700000000000
		}
		execution.ExpectedCancel = tc.success
		if err := st.InsertProbeExecution(ctx, &execution); err != nil {
			t.Fatal(err)
		}
		if err := st.InsertRequestLog(&model.RequestLog{Outcome: model.OutcomeOK, Metadata: model.AttemptMetadata{Version: 1, ExecutionID: id}}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := st.ListRecentErrors(ctx, RecentErrorFilter{})
	if err != nil || page.FailedCount != 0 || len(page.Logs) != 0 {
		t.Fatalf("unknown, dropped or successful canonical observation became a failure: %+v %v", page, err)
	}
	// Coarse failures keep their original meaning even without canonical evidence.
	for _, class := range []model.ErrorClass{"unknown", model.ErrorNone, model.ErrorIgnored} {
		if err := st.InsertRequestLog(&model.RequestLog{Outcome: model.OutcomeClientAbort, Metadata: model.AttemptMetadata{Version: 1, ErrorClass: class}}); err != nil {
			t.Fatal(err)
		}
		filtered, err := st.ListRecentErrors(ctx, RecentErrorFilter{ErrorClass: class, Outcome: model.OutcomeClientAbort})
		if err != nil || filtered.FailedCount != 1 || len(filtered.Logs) != 1 {
			t.Fatalf("coarse failure lost for %s: %+v %v", class, filtered, err)
		}
	}
}

func TestRecentErrorsNeverAssociateEmptyRequestIDs(t *testing.T) {
	st := testStore(t)
	if err := st.InsertSample(&model.Sample{ReqID: "", Outcome: model.OutcomeOK}); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertRequestLog(&model.RequestLog{ReqID: "", Outcome: model.OutcomeTimeout}); err != nil {
		t.Fatal(err)
	}
	page, err := st.ListRecentErrors(context.Background(), RecentErrorFilter{})
	if err != nil || len(page.Logs) != 1 {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	if page.Logs[0].SampleID != 0 {
		t.Fatal("empty legacy ReqID was treated as an exact sample association")
	}
}
