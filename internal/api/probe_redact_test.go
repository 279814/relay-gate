package api

import (
	"context"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probe"
)

// legacyDetailAdmin 模拟写侧脱敏前落库的行：上游把 key 整段回显进
// error.code 时，redacted_detail / last_error 原样带着它。
type legacyDetailAdmin struct {
	*probe.Service
	detail string
}

func (a *legacyDetailAdmin) execution() model.ProbeExecution {
	return model.ProbeExecution{ID: "exec-legacy", RedactedDetail: a.detail}
}

func (a *legacyDetailAdmin) RunManual(context.Context, int64) (model.ProbeExecution, error) {
	return a.execution(), nil
}

func (a *legacyDetailAdmin) ListExecutions(context.Context, model.ProbeExecutionFilter) (model.Page[model.ProbeExecution], error) {
	return model.Page[model.ProbeExecution]{Items: []model.ProbeExecution{a.execution()}}, nil
}

func (a *legacyDetailAdmin) GetExecution(context.Context, string) (model.ProbeExecution, error) {
	return a.execution(), nil
}

func (a *legacyDetailAdmin) ListCapabilities(context.Context, model.CapabilityFilter) (model.Page[model.EndpointCapability], error) {
	return model.Page[model.EndpointCapability]{Items: []model.EndpointCapability{{RedactedDetail: a.detail}}}, nil
}

func (a *legacyDetailAdmin) ListReachability(context.Context, model.ReachabilityFilter) (model.Page[model.UpstreamReachability], error) {
	return model.Page[model.UpstreamReachability]{Items: []model.UpstreamReachability{{LastError: a.detail}}}, nil
}

func TestProbeAdminResponses_RedactLegacyEchoedUpstreamKey(t *testing.T) {
	s, _ := newTestServer(t)
	const key = "sk-legacy-echo-key-0123456789"
	admin := &legacyDetailAdmin{
		Service: probe.NewService(s.st, nil, nil, nil, nil, nil),
		detail:  "authentication_error:" + key,
	}
	h := s.WithProbeAdmin(admin).Routes(testAdminPW)
	mkUpstreamViaAPI(t, h, `{"name":"legacy-echo","base_url":"https://legacy-echo.example.com","api_key":"`+key+`"}`)

	for _, tc := range []struct{ method, path string }{
		{"GET", "/admin/api/probe-executions"},
		{"GET", "/admin/api/probe-executions/exec-legacy"},
		{"POST", "/admin/api/routes/1/probe"},
		{"GET", "/admin/api/capabilities"},
		{"GET", "/admin/api/reachability"},
	} {
		rec := do(t, h, tc.method, tc.path, "", true)
		if rec.Code != 200 {
			t.Fatalf("%s %s: status %d: %s", tc.method, tc.path, rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if strings.Contains(body, key) {
			t.Errorf("%s %s leaked upstream key: %s", tc.method, tc.path, body)
		}
		if !strings.Contains(body, "authentication_error") {
			t.Errorf("%s %s dropped the structured detail: %s", tc.method, tc.path, body)
		}
	}
}
