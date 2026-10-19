package store

import (
	"context"
	"errors"
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
