package probe

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"

	"github.com/279814/relay-gate/internal/configadmin"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/store"
)

func canonicalEndpointAdminFixture(t *testing.T) (*Service, *model.Upstream, model.UpstreamEndpoint) {
	t.Helper()
	st := calibrationTestStore(t)
	var endpoints []configadmin.EndpointMutation
	for _, kind := range []model.EndpointKind{model.EndpointModels, model.EndpointMessages, model.EndpointCountTokens, model.EndpointResponses, model.EndpointChatCompletions} {
		endpoints = append(endpoints, configadmin.EndpointMutation{Endpoint: kind, AuthProfile: model.EndpointAuthProfile{Mode: model.AuthModeBearer, SecretRef: "upstream_api_key"}})
	}
	up, err := configadmin.New(st, nil).CreateUpstream(context.Background(), model.Upstream{Name: "endpoint-admin", BaseURL: "https://endpoint.test", APIKey: "synthetic-endpoint-key", Enabled: false}, endpoints)
	if err != nil {
		t.Fatal(err)
	}
	ep, err := st.Endpoint(context.Background(), up.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	return NewService(st, nil, nil, nil, nil, nil), &up, *ep
}

func TestEndpointServiceCannotCreateMigrationAuth(t *testing.T) {
	s, _, ep := canonicalEndpointAdminFixture(t)
	if err := s.store.DeleteEndpoint(ep.ID, ep.Revision); err != nil {
		t.Fatal(err)
	}
	ep.ID = 0
	ep.AuthProfile.Mode = model.AuthModeLegacyAutoRealOnly
	ep.LegacyCompatRealOnly = true
	if _, err := s.CreateEndpoint(context.Background(), EndpointMutationFrom(ep)); err == nil {
		t.Fatal("Service created migration-only auth without HTTP")
	}
}

func TestEndpointServiceCannotConvertCanonicalToLegacyAuth(t *testing.T) {
	s, _, ep := canonicalEndpointAdminFixture(t)
	ep.AuthProfile.Mode = model.AuthModeLegacyAutoRealOnly
	ep.LegacyCompatRealOnly = true
	if _, err := s.UpdateEndpoint(context.Background(), ep.ID, ep.Revision, EndpointMutationFrom(ep)); err == nil {
		t.Fatal("Service converted ordinary Endpoint to migration-only auth without HTTP")
	}
}

func TestEndpointServiceExistingMigrationRowCannotBeNormallyEdited(t *testing.T) {
	s, _, ep := canonicalEndpointAdminFixture(t)
	ep.AuthProfile.Mode = model.AuthModeLegacyAutoRealOnly
	ep.LegacyCompatRealOnly = true
	if err := s.store.UpdateEndpoint(&ep, ep.Revision); err != nil {
		t.Fatal(err)
	}
	read, err := s.GetEndpoint(context.Background(), ep.ID)
	if err != nil || !read.LegacyCompatRealOnly || read.AuthProfile.Mode != model.AuthModeLegacyAutoRealOnly {
		t.Fatalf("migration row cannot be read: %+v %v", read, err)
	}
	read.URLOverride = "https://endpoint.test/v2/messages"
	mutation := EndpointMutationFrom(read)
	mutation.AuthProfile.Mode = model.AuthModeBearer
	if _, err := s.UpdateEndpoint(context.Background(), ep.ID, ep.Revision, mutation); err == nil {
		t.Fatal("ordinary Service Update mutated existing migration row")
	}
	after, err := s.GetEndpoint(context.Background(), ep.ID)
	if err != nil || !reflect.DeepEqual(after, ep) {
		t.Fatalf("readonly legacy row changed: %+v %v", after, err)
	}
	header := http.Header{}
	if err := outbound.ApplyAuth(context.Background(), header, outbound.AuthInput{Profile: after.AuthProfile, Values: outbound.Values{UpstreamAPIKey: []byte("synthetic-legacy-key")}, Use: outbound.ResolveRealForward}); err != nil || header.Get("Authorization") == "" || header.Get("X-Api-Key") == "" {
		t.Fatalf("historical real forwarding compatibility lost: header names=%v err=%v", reflect.ValueOf(header).MapKeys(), err)
	}
}

func TestEndpointServiceCanonicalEditsKeepCASAndCalibrationResult(t *testing.T) {
	s, _, ep := canonicalEndpointAdminFixture(t)
	invalidator := &recordingRouteInvalidator{}
	s.invalidator = invalidator
	ep.AuthProfile.Mode = model.AuthModeAutoCalibrated
	ep.AuthProfile.CalibratedMode = model.AuthModeXAPIKey
	if err := s.store.UpdateEndpoint(&ep, ep.Revision); err != nil {
		t.Fatal(err)
	}
	input := EndpointMutationFrom(ep)
	input.AuthProfile.ManualHeaders = []model.HeaderTemplate{} // The browser's empty JSON editor.
	unchanged, err := s.UpdateEndpoint(context.Background(), ep.ID, ep.Revision, input)
	if err != nil || unchanged.Revision != ep.Revision || len(invalidator.upstreams) != 0 {
		t.Fatalf("service no-op invalidated: endpoint=%+v err=%v invalidations=%v", unchanged, err, invalidator.upstreams)
	}
	input.URLOverride = "https://endpoint.test/v2/messages"
	updated, err := s.UpdateEndpoint(context.Background(), ep.ID, ep.Revision, input)
	if err != nil {
		t.Fatal(err)
	}
	if updated.AuthProfile.CalibratedMode != model.AuthModeXAPIKey || updated.AuthProfile.Revision != ep.AuthProfile.Revision {
		t.Fatalf("URL-only edit erased calibration: %+v", updated.AuthProfile)
	}
	if _, err := s.UpdateEndpoint(context.Background(), ep.ID, ep.Revision, input); !errors.Is(err, store.ErrRevisionConflict) {
		t.Fatalf("stale mutation=%v", err)
	}
	input = EndpointMutationFrom(updated)
	input.AuthProfile.Mode = model.AuthModeBearer
	changed, err := s.UpdateEndpoint(context.Background(), ep.ID, updated.Revision, input)
	if err != nil {
		t.Fatal(err)
	}
	if changed.AuthProfile.CalibratedMode != "" || changed.AuthProfile.Revision != updated.AuthProfile.Revision+1 {
		t.Fatalf("auth edit retained stale calibration: %+v", changed.AuthProfile)
	}
}

func TestEndpointServiceHistoricalAuthCanStillCalibrate(t *testing.T) {
	st := calibrationTestStore(t)
	up, _, route := seedCalibrationRoute(t, st)
	calibrator, _ := newCalibrationHarness(t, st, up, func(*http.Request) (*http.Response, error) {
		return respFrom(200, "text/event-stream", anthropicSemanticBody()), nil
	})
	service := NewService(st, nil, calibrator, nil, nil, nil)
	ep, err := st.Endpoint(context.Background(), up.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	if ep.AuthProfile.Mode != model.AuthModeLegacyAutoRealOnly {
		t.Fatal("fixture is not historical auth")
	}
	plan, err := service.PlanCalibration(context.Background(), route.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	run, err := service.StartCalibration(context.Background(), plan.ID, plan.Revision)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if err := calibrator.stepOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		current, err := service.GetCalibration(context.Background(), run.ID)
		if err != nil {
			t.Fatal(err)
		}
		if current.State != model.CalibrationRunning {
			break
		}
	}
	final, err := service.GetCalibration(context.Background(), run.ID)
	if err != nil || final.State != model.CalibrationSucceeded {
		t.Fatalf("calibration did not complete: %+v %v", final, err)
	}
	resolved, err := service.GetEndpoint(context.Background(), ep.ID)
	if err != nil || resolved.LegacyCompatRealOnly || resolved.AuthProfile.Mode != model.AuthModeAutoCalibrated || resolved.AuthProfile.CalibratedMode == "" {
		t.Fatalf("historical auth not canonically calibrated: %+v %v", resolved, err)
	}
}
