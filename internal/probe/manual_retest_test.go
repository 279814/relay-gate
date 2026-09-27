package probe

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/observationseq"
	"github.com/279814/relay-gate/internal/outbound"
)

// docs/01 §8.13：config_error 仅配置变更或人工重新测试后解除。管理面「测试」
// 走 Service.RunManual：同样的配置错误重测后仍是 config_error，成功重测必须
// 以新结论替换它（内存与落库一致）。
func TestRunManual_RetestReplacesConfigErrorOnlyOnNewResult(t *testing.T) {
	ctx := context.Background()
	st := calibrationTestStore(t)
	up := &model.Upstream{
		Name: "retest-up", BaseURL: "https://retest.example.test",
		APIKey: "sk-retest-upstream-key", AuthStyle: model.AuthXAPIKey, Enabled: true,
		ProbeMode: model.ProbeModeActive,
	}
	if err := st.CreateUpstream(up); err != nil {
		t.Fatal(err)
	}
	mn := &model.ModelName{
		Name: "claude-retest", Protocol: model.ProtoAnthropic,
		MatchMode: model.MatchExact, Enabled: true,
	}
	mn.Defaults()
	if err := st.CreateModelName(mn); err != nil {
		t.Fatal(err)
	}
	rt := &model.Route{ModelNameID: mn.ID, UpstreamID: up.ID, Priority: 1, Weight: 1, Enabled: true}
	if err := st.CreateRoute(rt); err != nil {
		t.Fatal(err)
	}
	endpoint := model.EndpointMessages

	// 让 sequencer 的号越过种子行的 order，模拟重启前已分配过的号段。
	if _, _, err := st.ReserveObservationOrders(ctx, observationseq.BlockSize); err != nil {
		t.Fatal(err)
	}
	commitRouteConfigError(t, st, up, rt, endpoint)
	caps := restartedRegistry(t, st)
	if got := caps.Effective(model.RecipeScopeRoute, rt.ID, endpoint, ""); got != model.CapabilityConfigError {
		t.Fatalf("seed state=%s, want config_error", got)
	}

	var succeed atomic.Bool
	transport := &countingRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		if succeed.Load() {
			return respFrom(200, "text/event-stream", anthropicSemanticBody()), nil
		}
		return respFrom(400, "application/json",
			`{"error":{"type":"invalid_request_error","code":"model_not_found","message":"no such model"}}`), nil
	}}
	cfg, recipes := restoreTestDeps(st)
	if _, err := cfg.Bundle(); err != nil {
		t.Fatal(err)
	}
	targets := outbound.NewProvider(storeEndpointSource{store: st}, nil, outbound.NewResolver(testHasher{}))
	recorder := NewResultRecorder(st, health.NewObservationReducer(nil),
		health.NewReachabilityTracker(nil), caps)
	executor := NewExecutor(targets, st, recipes, fakeTransports{rt: transport},
		recorder, AlwaysOpenAdmission(), WallClock(), nil)
	seq, err := observationseq.Open(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(seq.Close)
	sched := NewScheduler(cfg, nil, health.NewTracker(nil), nil, slog.New(slog.NewTextHandler(io.Discard, nil))).
		WithRecipes(recipes).WithExecutor(executor).WithSequencer(seq)
	svc := NewService(st, executor, nil, settingsSnap{}, nil, nil).WithManualPreparer(sched)

	storedConfigErrors := func() int {
		t.Helper()
		rows, err := st.ListEndpointCapabilitiesByState(ctx, model.CapabilityConfigError)
		if err != nil {
			t.Fatal(err)
		}
		return len(rows)
	}

	exec, err := svc.RunManual(ctx, rt.ID)
	if err != nil {
		t.Fatal(err)
	}
	if exec.Success || exec.CapabilityDisposition != model.ApplyCurrent {
		t.Fatalf("failed retest success=%v disposition=%s, want applied failure", exec.Success, exec.CapabilityDisposition)
	}
	if got := caps.Effective(model.RecipeScopeRoute, rt.ID, endpoint, ""); got != model.CapabilityConfigError {
		t.Fatalf("after same-way failed retest state=%s, want config_error", got)
	}
	if n := storedConfigErrors(); n != 1 {
		t.Fatalf("after failed retest stored config_error rows=%d, want 1", n)
	}

	succeed.Store(true)
	exec, err = svc.RunManual(ctx, rt.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !exec.Success || exec.CapabilityDisposition != model.ApplyCurrent {
		t.Fatalf("successful retest success=%v disposition=%s, want applied success", exec.Success, exec.CapabilityDisposition)
	}
	if got := caps.Effective(model.RecipeScopeRoute, rt.ID, endpoint, ""); got != model.CapabilitySupported {
		t.Fatalf("after successful retest state=%s, want supported", got)
	}
	if n := storedConfigErrors(); n != 0 {
		t.Fatalf("after successful retest stored config_error rows=%d, want 0", n)
	}
	if transport.count() != 2 {
		t.Fatalf("RoundTrip=%d, want 2", transport.count())
	}
}
