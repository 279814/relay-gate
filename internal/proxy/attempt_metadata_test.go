package proxy

import (
	"github.com/279814/relay-gate/internal/livecfg"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

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
