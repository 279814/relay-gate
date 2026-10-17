package probe

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

func TestLearnerDefensivelyRejectsUnsafeTypedShapeAndStoredProfile(t *testing.T) {
	const private = "PRIVATE_OPAQUE_CONTEXT_92d7b6da"
	for _, shape := range []model.ClientRequestShape{
		{FixedRawQuery: "opaque_context=" + private},
		{BodyShapeJSON: []byte(`{"model":"string","private_metadata":"` + private + `"}`)},
		{BodyShapeJSON: []byte(`{"model":"string","metadata":{"user_id":"` + private + `"}}`)},
		{BodyShapeJSON: []byte(`{"model":"string","thinking":{"type":"` + private + `"}}`)},
		{BodyShapeJSON: []byte(`{"model":"string","thinking":{"type":"enabled","budget_tokens":8000}}`)},
	} {
		t.Run(string(shape.BodyShapeJSON)+shape.FixedRawQuery, func(t *testing.T) {
			captured := &captureLearnerStore{}
			if err := NewLearner(captured).ObserveSuccessful(context.Background(), 7, model.EndpointMessages, shape); err == nil || captured.profile != nil {
				t.Fatal("unsafe typed shape was accepted")
			}
			profile := &model.ClientProbeProfile{ID: 9, Revision: 1, Status: model.ProfileTested,
				FixedRawQuery: shape.FixedRawQuery, BodyShapeJSON: shape.BodyShapeJSON}
			if _, err := testResolver(&fakeRecipeSource{profile: profile}).Resolve(context.Background(), RecipeQuery{UpstreamID: 7, Endpoint: model.EndpointMessages}); err == nil {
				t.Fatal("unsafe stored profile was executed")
			}
		})
	}
}

func TestLearnerRebuildsUntrustedHeaderQueryMetadataAndFamily(t *testing.T) {
	captured := &captureLearnerStore{}
	shape := model.ClientRequestShape{ClientFamily: "PRIVATE_FAMILY", FixedRawQuery: "beta=true",
		SafeHeaders:    []model.HeaderTemplate{{Name: "X-Opaque", Values: []string{"PRIVATE_HEADER"}}},
		QueryShapeJSON: []byte(`{"PRIVATE_QUERY":"PRIVATE_METADATA"}`),
		BodyTemplate:   []byte(`{"model":"PRIVATE_BODY"}`), BodyShapeJSON: []byte(`{"model":"string","stream":false}`)}
	if err := NewLearner(captured).ObserveSuccessful(context.Background(), 7, model.EndpointMessages, shape); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(captured.profile)
	if err != nil || strings.Contains(string(raw), "PRIVATE_") || captured.profile.ClientFamily != "generic" || string(captured.profile.QueryShapeJSON) != `{"beta":"bool"}` {
		t.Fatalf("untrusted metadata survived: %s %v", raw, err)
	}
}

func TestLearnerPersistsRepeatedShapeAcrossInstancesAndSites(t *testing.T) {
	st := calibrationTestStore(t)
	up, _, _ := seedCalibrationRoute(t, st)
	shape, reason := SanitizeRequestShape(model.EndpointMessages, health.AttemptRequestView{Body: []byte(`{"model":"private","stream":true,"messages":[]}`)})
	if reason != "" {
		t.Fatal(reason)
	}
	for i := 0; i < 2; i++ {
		if err := NewLearner(st).ObserveSuccessful(context.Background(), up.ID, model.EndpointMessages, shape); err != nil {
			t.Fatal(err)
		}
	}
	page, err := st.ListClientProfilesPage(context.Background(), model.ClientProfileFilter{UpstreamID: up.ID})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("profile page=%+v err=%v", page, err)
	}
	profile := page.Items[0]
	if profile.SeenCount != 2 || profile.Revision != 1 || profile.ClientFamily != "generic" || profile.Status != model.ProfileCandidate {
		t.Fatalf("observation telemetry/identity=%+v", profile)
	}
	other := &model.Upstream{Name: "learn-other", BaseURL: "https://example.test", APIKey: "test-upstream-credential", Enabled: true}
	if err := st.CreateUpstream(other); err != nil {
		t.Fatal(err)
	}
	learner := NewLearner(st)
	for _, id := range []int64{up.ID, other.ID} {
		if err := learner.ObserveSuccessful(context.Background(), id, model.EndpointMessages, shape); err != nil {
			t.Fatal(err)
		}
	}
	page, err = st.ListClientProfilesPage(context.Background(), model.ClientProfileFilter{UpstreamID: other.ID})
	if err != nil || len(page.Items) != 1 || page.Items[0].SeenCount != 1 {
		t.Fatalf("same shape lost across sites: %+v %v", page, err)
	}
}

func TestLearnerRetriesAfterStoreFailure(t *testing.T) {
	st := calibrationTestStore(t)
	up, _, _ := seedCalibrationRoute(t, st)
	shape, _ := SanitizeRequestShape(model.EndpointMessages, health.AttemptRequestView{Body: []byte(`{"model":"private","messages":[]}`)})
	learner := NewLearner(st)
	if _, err := st.DB().Exec(`CREATE TRIGGER reject_profile BEFORE INSERT ON client_probe_profile BEGIN SELECT RAISE(ABORT,'fixture write failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := learner.ObserveSuccessful(context.Background(), up.ID, model.EndpointMessages, shape); err == nil {
		t.Fatal("write failure was hidden")
	}
	if _, err := st.DB().Exec(`DROP TRIGGER reject_profile`); err != nil {
		t.Fatal(err)
	}
	if err := learner.ObserveSuccessful(context.Background(), up.ID, model.EndpointMessages, shape); err != nil {
		t.Fatal(err)
	}
	page, err := st.ListClientProfilesPage(context.Background(), model.ClientProfileFilter{UpstreamID: up.ID})
	if err != nil || len(page.Items) != 1 || page.Items[0].SeenCount != 1 {
		t.Fatalf("failed write poisoned the learner: %+v %v", page, err)
	}
}
