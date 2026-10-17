package api

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

func TestRouteIDTargetsAreCompleteAndReEnableDoesNotScheduleSynthetic(t *testing.T) {
	for _, resource := range []string{"upstreams", "model-names"} {
		t.Run(resource, func(t *testing.T) {
			s, _ := newTestServer(t)
			if resource == "upstreams" {
				seedConfig(t, s, 1, 205)
			} else {
				seedConfig(t, s, 205, 1)
			}
			up := metadataUpstream(t, s, "id-target-sibling", "id-target-sibling-credential")
			mn, err := s.configAdmin.CreateModelName(context.Background(), model.ModelName{Name: "id-target-sibling-model", Protocol: model.ProtoAnthropic, Enabled: true})
			if err != nil {
				t.Fatal(err)
			}
			sibling, err := s.configAdmin.CreateRoute(context.Background(), model.Route{UpstreamID: up.ID, ModelNameID: mn.ID, Enabled: true, Weight: 100, Priority: 1})
			if err != nil {
				t.Fatal(err)
			}
			want := make([]int64, 205)
			for i := range want {
				want[i] = int64(i + 1)
			}
			// Invalidation needs identities only: an unrelated decoded configuration
			// column must not erase the entire command target set.
			if _, err := s.st.DB().Exec(`UPDATE route SET max_concurrency='not-an-integer' WHERE id=1`); err != nil {
				t.Fatal(err)
			}
			var ids []int64
			if resource == "upstreams" {
				ids = s.routeIDsOfUpstream(1)
			} else {
				ids = s.routeIDsOfModelName(1)
			}
			if !reflect.DeepEqual(ids, want) {
				t.Fatalf("complete FK target IDs: got %d want %d", len(ids), len(want))
			}

			settings := &fakeSettingsForInvalidate{s: model.DefaultSettings()}
			settings.s.FailThreshold = 1
			tracker := health.NewTracker(settings)
			inner := &recordingInvalidator{}
			h := s.WithInvalidator(&SemanticConfigInvalidator{
				Semantic: health.NewSemanticInvalidator(tracker, nil, nil, nil, nil), Inner: inner,
				RoutesOfUpstream: s.routeIDsOfUpstream, RoutesOfModelName: s.routeIDsOfModelName,
			}).Routes(testAdminPW)
			for _, id := range append(want, sibling.ID) {
				tracker.Report(health.Report{RouteID: id, Source: health.SourceL2, Verdict: health.VerdictUnavailable})
			}
			for i, enabled := range []bool{false, true} {
				response := do(t, h, "PUT", "/admin/api/"+resource+"/1", fmt.Sprintf(`{"expected_revision":%d,"enabled":%t}`, i+1, enabled), true)
				if response.Code != 200 {
					t.Fatalf("reenable status=%d %s", response.Code, response.Body.String())
				}
			}
			for _, id := range want {
				if tracker.State(id) != model.StateUnknown {
					t.Fatalf("child %d stayed %s", id, tracker.State(id))
				}
			}
			if tracker.State(sibling.ID) != model.StateDead {
				t.Fatal("sibling health changed")
			}
			if routes, ups, names := inner.counts(); routes+ups+names != 0 || len(inner.scheduled) != 0 {
				t.Fatal("pure reenable scheduled synthetic work")
			}
		})
	}
}
