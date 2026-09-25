package api

import (
	"net/http"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probe"
)

// Partial PUT must change only fields present in the JSON body. Omitted fields
// keep their stored values; explicit false / empty string still apply; a
// rejected update must leave the previous row unchanged.

func TestPartialPUT_RouteOmitsKeepStoredFields(t *testing.T) {
	_, h := newTestServer(t)
	upID := mkUpstreamViaAPI(t, h, `{"name":"partial-rt-u","base_url":"https://partial-rt.example.com","api_key":"sk-aaaaaaaaaaaa"}`)
	rec := do(t, h, "POST", "/admin/api/model-names",
		`{"name":"partial-rt-m","protocol":"anthropic"}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create model_name: %d %s", rec.Code, rec.Body.String())
	}
	mnID := int64(decodeBody[map[string]any](t, rec)["id"].(float64))
	rec = do(t, h, "POST", "/admin/api/routes",
		`{"model_name_id":`+itoa(mnID)+`,"upstream_id":`+itoa(upID)+
			`,"priority":7,"weight":40,"upstream_model":"mapped","enabled":true}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create route: %d %s", rec.Code, rec.Body.String())
	}
	rtID := int64(decodeBody[map[string]any](t, rec)["id"].(float64))

	rec = do(t, h, "PUT", "/admin/api/routes/"+itoa(rtID), `{"priority":3}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("partial PUT: %d %s", rec.Code, rec.Body.String())
	}
	got := decodeBody[model.Route](t, rec)
	if got.Priority != 3 || got.Weight != 40 || !got.Enabled ||
		got.UpstreamID != upID || got.ModelNameID != mnID || got.UpstreamModel != "mapped" {
		t.Fatalf("omitted fields changed: %+v", got)
	}

	rec = do(t, h, "PUT", "/admin/api/routes/"+itoa(rtID), `{"enabled":false}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("explicit enabled:false: %d %s", rec.Code, rec.Body.String())
	}
	got = decodeBody[model.Route](t, rec)
	if got.Enabled || got.Priority != 3 || got.Weight != 40 {
		t.Fatalf("explicit false must apply without wiping others: %+v", got)
	}

	before := got
	rec = do(t, h, "PUT", "/admin/api/routes/"+itoa(rtID), `{"upstream_id":0}`, true)
	if rec.Code == http.StatusOK {
		t.Fatal("upstream_id 0 must be rejected")
	}
	rec = do(t, h, "GET", "/admin/api/routes/"+itoa(rtID), "", true)
	after := decodeBody[model.Route](t, rec)
	if after.Priority != before.Priority || after.Weight != before.Weight ||
		after.Enabled != before.Enabled || after.UpstreamModel != before.UpstreamModel ||
		after.UpstreamID != before.UpstreamID {
		t.Fatalf("rejected update changed row: before=%+v after=%+v", before, after)
	}
}

func TestPartialPUT_ModelNameOmitsKeepStoredFields(t *testing.T) {
	_, h := newTestServer(t)
	rec := do(t, h, "POST", "/admin/api/model-names",
		`{"name":"partial-mn","protocol":"anthropic","match_mode":"prefix","probe_prompt":"hi","probe_max_tokens":8,"enabled":true}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	id := int64(decodeBody[map[string]any](t, rec)["id"].(float64))

	rec = do(t, h, "PUT", "/admin/api/model-names/"+itoa(id), `{"name":"partial-mn-renamed"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("partial PUT: %d %s", rec.Code, rec.Body.String())
	}
	got := decodeBody[model.ModelName](t, rec)
	if got.Name != "partial-mn-renamed" || got.Protocol != model.ProtoAnthropic ||
		got.MatchMode != model.MatchPrefix || got.ProbePrompt != "hi" ||
		got.ProbeMaxTokens != 8 || !got.Enabled {
		t.Fatalf("omitted fields changed: %+v", got)
	}

	rec = do(t, h, "PUT", "/admin/api/model-names/"+itoa(id), `{"enabled":false}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("explicit enabled:false: %d %s", rec.Code, rec.Body.String())
	}
	got = decodeBody[model.ModelName](t, rec)
	if got.Enabled || got.Protocol != model.ProtoAnthropic || got.MatchMode != model.MatchPrefix {
		t.Fatalf("explicit false must apply without wiping others: %+v", got)
	}

	before := got
	rec = do(t, h, "PUT", "/admin/api/model-names/"+itoa(id), `{"protocol":"not-a-protocol"}`, true)
	if rec.Code == http.StatusOK {
		t.Fatal("invalid protocol must be rejected")
	}
	rec = do(t, h, "GET", "/admin/api/model-names/"+itoa(id), "", true)
	after := decodeBody[model.ModelName](t, rec)
	if after.Name != before.Name || after.Protocol != before.Protocol ||
		after.MatchMode != before.MatchMode || after.Enabled != before.Enabled {
		t.Fatalf("rejected update changed row: before=%+v after=%+v", before, after)
	}
}

func TestPartialPUT_EndpointOmitsKeepStoredFields(t *testing.T) {
	s, _ := newTestServer(t)
	h := s.WithProbeAdmin(probe.NewService(s.st, nil, nil, nil, nil, nil)).Routes(testAdminPW)

	upID := mkUpstreamViaAPI(t, h, `{"name":"partial-ep-u","base_url":"https://partial-ep.example.com","api_key":"sk-eeeeeeeeeeee"}`)
	rec := do(t, h, "GET", "/admin/api/upstream-endpoints?upstream_id="+itoa(upID), "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("list endpoints: %d %s", rec.Code, rec.Body.String())
	}
	page := decodeBody[model.Page[model.UpstreamEndpoint]](t, rec)
	if len(page.Items) == 0 {
		t.Fatal("expected auto-created endpoints")
	}
	ep := page.Items[0]
	beforeAuth := ep.AuthProfile
	beforeKind := ep.Kind
	beforeMode := ep.URLMode
	beforeUpstream := ep.UpstreamID

	override := "https://partial-ep.example.com/v1/custom"
	rec = do(t, h, "PUT", "/admin/api/upstream-endpoints/"+itoa(ep.ID),
		`{"url_override":`+mustJSON(t, override)+`,"expected_revision":`+itoa(ep.Revision)+`}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("partial PUT: %d %s", rec.Code, rec.Body.String())
	}
	got := decodeBody[model.UpstreamEndpoint](t, rec)
	if got.URLOverride != override {
		t.Fatalf("url_override=%q want %q", got.URLOverride, override)
	}
	if got.UpstreamID != beforeUpstream || got.Kind != beforeKind || got.URLMode != beforeMode {
		t.Fatalf("omitted binding/mode wiped: %+v", got)
	}
	if got.AuthProfile.Mode != beforeAuth.Mode || got.AuthProfile.SecretRef != beforeAuth.SecretRef ||
		got.AuthProfile.Revision != beforeAuth.Revision {
		t.Fatalf("omitted auth_profile wiped: got=%+v want=%+v", got.AuthProfile, beforeAuth)
	}

	// Explicit empty string must clear the override, not be treated as omitted.
	rec = do(t, h, "PUT", "/admin/api/upstream-endpoints/"+itoa(ep.ID),
		`{"url_override":"","expected_revision":`+itoa(got.Revision)+`}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("explicit empty url_override: %d %s", rec.Code, rec.Body.String())
	}
	cleared := decodeBody[model.UpstreamEndpoint](t, rec)
	if cleared.URLOverride != "" {
		t.Fatalf("explicit empty must clear url_override, got %q", cleared.URLOverride)
	}
	if cleared.AuthProfile.SecretRef != beforeAuth.SecretRef || cleared.Kind != beforeKind {
		t.Fatalf("clearing override wiped other fields: %+v", cleared)
	}

	before := cleared
	rec = do(t, h, "PUT", "/admin/api/upstream-endpoints/"+itoa(ep.ID),
		`{"url_mode":"not-a-mode","expected_revision":`+itoa(before.Revision)+`}`, true)
	if rec.Code == http.StatusOK {
		t.Fatal("invalid url_mode must be rejected")
	}
	rec = do(t, h, "GET", "/admin/api/upstream-endpoints/"+itoa(ep.ID), "", true)
	after := decodeBody[model.UpstreamEndpoint](t, rec)
	if after.URLOverride != before.URLOverride || after.URLMode != before.URLMode ||
		after.AuthProfile.SecretRef != before.AuthProfile.SecretRef || after.Revision != before.Revision {
		t.Fatalf("rejected update changed row: before=%+v after=%+v", before, after)
	}
}
