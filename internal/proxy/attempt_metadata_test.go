package proxy

import (
	"github.com/279814/relay-gate/internal/livecfg"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestCountTokensLogsOnlyActualSendsWithExactAttemptFacts(t *testing.T) {
	hs := newMultiHarness(t, respondStatus(503, `down`), respondOK(`{"input_tokens":5}`))
	hs.h.WithCountTokensCapability(&memoryCountCaps{states: map[int64]model.CapabilityState{100: model.CapabilitySupported, 200: model.CapabilitySupported}})
	sink := hs.withLogs()
	mux := http.NewServeMux()
	hs.h.Routes(mux)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages/count_tokens", strings.NewReader(hs.req()))
	req.Header.Set("X-Api-Key", hs.relayPW)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	rows := sink.all()
	if len(rows) != 2 {
		t.Fatalf("count actual sends not logged: %d", len(rows))
	}
	for i, row := range rows {
		if row.Endpoint != "/v1/messages/count_tokens" || row.Attempt != i+1 || row.Attempts != 2 || row.Metadata.ExecutionID == "" || row.Metadata.RequestWriteState != "written" || row.Metadata.RequestDiffReason != "sample_disabled" {
			t.Errorf("attempt %d=%+v", i, row)
		}
	}
	if rows[0].ReqID != rows[1].ReqID || !rows[0].Retried || rows[1].Retried || rows[0].Metadata.ExecutionID == rows[1].Metadata.ExecutionID {
		t.Fatalf("count group/attempt facts wrong: %+v", rows)
	}
	if len(hs.sink.all()) != 0 {
		t.Fatal("count_tokens unexpectedly retained a sample body")
	}
}

type attemptBundleConfig struct {
	*fakeConfig
	published *livecfg.PublishedConfig
}

func (c *attemptBundleConfig) Bundle() (*livecfg.PublishedConfig, error) { return c.published, nil }

func TestAttemptUsesOneCapturedRootForEndpointAndMetadata(t *testing.T) {
	hs := newHarness(t, nil)
	sink := &recordingLogSink{}
	hs.h.WithLogSink(sink)
	ep, _ := (testEndpoints{cfg: hs.cfg}).Endpoint(nil, 10, model.EndpointMessages)
	ep.URLOverride = hs.up.URL + "/captured"
	ep.Revision = 4
	ep.AuthProfile.Revision = 5
	pub := &livecfg.PublishedConfig{Generation: 42, Routing: hs.cfg.snap, Settings: hs.cfg.settings, Probe: &livecfg.ProbeSnapshot{Generation: 42, SettingsRowRevision: 8, Endpoints: map[int64]map[model.EndpointKind]*model.UpstreamEndpoint{10: {model.EndpointMessages: ep}}}}
	hs.h.cfg = &attemptBundleConfig{hs.cfg, pub}
	if rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`)); rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if hs.gotReq.path != "/captured" {
		t.Fatalf("endpoint used current source instead of captured root: %s", hs.gotReq.path)
	}
	logs := sink.all()
	if len(logs) != 1 {
		t.Fatalf("logs=%d", len(logs))
	}
	m := logs[0].Metadata
	if m.ConfigGeneration != 42 || m.SettingsRevision != 8 || m.EndpointRevision != 4 || m.AuthProfileRevision != 5 {
		t.Fatalf("mixed/invented snapshot facts: %+v", m)
	}
}

func TestRequestLogCapturesEachActualAttemptFacts(t *testing.T) {
	hs := newMultiHarness(t, respondStatus(502, `down`), respondOK(`{"content":[{"type":"text","text":"ok"}]}`))
	hs.cfg.settings.RealTotalSec = 30
	hs.cfg.settings.RetryPolicy = model.RetryPolicyBalanced
	for _, routes := range hs.cfg.snap.RoutesByModelName {
		for _, r := range routes {
			r.Revision = 3
			r.CapabilityRevision = 4
		}
	}
	for _, m := range hs.cfg.snap.ModelNames {
		m.Revision = 5
		m.CapabilityRevision = 6
	}
	sink := hs.withLogs()
	if rec := hs.serve(hs.req()); rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}
	logs := sink.all()
	if len(logs) != 2 {
		t.Fatalf("logs=%d", len(logs))
	}
	seen := map[string]bool{}
	for i, row := range logs {
		m := row.Metadata
		if m.Version != 1 || m.ExecutionID == "" || seen[m.ExecutionID] || m.RouteRevision != 3 || m.ModelRevision != 5 || m.RetryPolicy != model.RetryPolicyBalanced || m.RequestWriteState != "written" {
			t.Errorf("attempt %d facts=%+v", i+1, m)
		}
		seen[m.ExecutionID] = true
		if m.ResponseHeaderAtMS == 0 || (i == 1 && (m.FirstEventAtMS == 0 || m.FirstSemanticAtMS == 0)) {
			t.Errorf("phase facts=%+v", m)
		}
	}
	smp := hs.sink.one(t)
	for i, a := range smp.Attempts {
		if a.Metadata.ExecutionID != logs[i].Metadata.ExecutionID || a.Metadata.Retried != logs[i].Retried || a.Metadata.Attempts != 2 {
			t.Errorf("sample attempt %d metadata=%+v log=%+v", i, a.Metadata, logs[i].Metadata)
		}
	}
}
