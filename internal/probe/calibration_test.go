package probe

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/store"
)

func calibrationTestStore(t *testing.T) *store.Store {
	t.Helper()
	cipher, err := store.NewCipher("calibration-test-passphrase-16")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "cal.db"), cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func seedCalibrationRoute(t *testing.T, st *store.Store) (*model.Upstream, *model.ModelName, *model.Route) {
	t.Helper()
	up := &model.Upstream{
		Name: "cal-up", BaseURL: "https://cal.example.test",
		APIKey: "sk-cal-upstream-key", AuthStyle: model.AuthAuto, Enabled: true,
		ProbeMode: model.ProbeModeActive,
	}
	if err := st.CreateUpstream(up); err != nil {
		t.Fatal(err)
	}
	mn := &model.ModelName{
		Name: "claude-cal", Protocol: model.ProtoAnthropic,
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
	return up, mn, rt
}

func newCalibrationHarness(t *testing.T, st *store.Store, up *model.Upstream,
	respond func(*http.Request) (*http.Response, error)) (*CalibrationService, *countingRoundTripper) {

	t.Helper()
	rt := &countingRoundTripper{fn: respond}
	targets := outbound.NewProvider(
		storeEndpointSource{store: st}, nil, outbound.NewResolver(testHasher{}))
	recipes := NewRecipeResolver(st).WithNotFound(func(err error) bool {
		return errors.Is(err, store.ErrNotFound)
	})
	executor := NewExecutor(targets, st, recipes, fakeTransports{rt: rt},
		NewExecutionOnlyRecorder(st), AlwaysOpenAdmission(), WallClock(), nil)
	svc := NewCalibrationService(st, executor, WallClock(), nil, func() (model.Settings, error) {
		return model.DefaultSettings(), nil
	}, NewCapabilityRegistry(nil))
	return svc, rt
}

type storeEndpointSource struct{ store *store.Store }

func (s storeEndpointSource) Endpoint(ctx context.Context, upstreamID int64, kind model.EndpointKind) (*model.UpstreamEndpoint, error) {
	return s.store.Endpoint(ctx, upstreamID, kind)
}

func TestCalibration_PlanPersistsAtMostThreeCandidates(t *testing.T) {
	st := calibrationTestStore(t)
	_, _, rt := seedCalibrationRoute(t, st)
	svc, _ := newCalibrationHarness(t, st, nil, func(*http.Request) (*http.Response, error) {
		t.Fatal("Plan 不应出网")
		return nil, nil
	})

	run, err := svc.Plan(context.Background(), rt.ID, model.EndpointMessages, CalibrationPlanOptions{Manual: true})
	if err != nil {
		t.Fatal(err)
	}
	if run.State != model.CalibrationPlanned {
		t.Fatalf("state=%s", run.State)
	}
	if len(run.Candidates) == 0 || len(run.Candidates) > MaxCalibrationCandidates {
		t.Fatalf("candidates=%d", len(run.Candidates))
	}
	for i, c := range run.Candidates {
		if c.Ordinal != i {
			t.Fatalf("ordinal=%d want %d", c.Ordinal, i)
		}
		if c.EstimatedInputTokens <= 0 {
			t.Fatalf("candidate %d 成本应在发送前持久化", i)
		}
		if c.State != model.CalibrationCandidatePlanned {
			t.Fatalf("candidate state=%s", c.State)
		}
	}
}

func TestCalibration_LazyRejectsAutomaticPlan(t *testing.T) {
	st := calibrationTestStore(t)
	up, _, rt := seedCalibrationRoute(t, st)
	up.ProbeMode = model.ProbeModeLazy
	if err := st.UpdateUpstream(up); err != nil {
		t.Fatal(err)
	}
	svc, _ := newCalibrationHarness(t, st, up, nil)
	_, err := svc.Plan(context.Background(), rt.ID, model.EndpointMessages, CalibrationPlanOptions{Manual: false})
	if err == nil {
		t.Fatal("Lazy 自动 Plan 必须拒绝")
	}
	if !strings.Contains(err.Error(), "手动") {
		t.Fatalf("错误应说明只能手动: %v", err)
	}
	_, err = svc.Plan(context.Background(), rt.ID, model.EndpointMessages, CalibrationPlanOptions{Manual: true})
	if err != nil {
		t.Fatalf("Lazy 手动 Plan 应允许: %v", err)
	}
}

func TestCalibration_EachCandidateOneRoundTrip_NoHiddenRetry(t *testing.T) {
	st := calibrationTestStore(t)
	up, _, rt := seedCalibrationRoute(t, st)
	var calls atomic.Int64
	svc, counter := newCalibrationHarness(t, st, up, func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		// 前两次 401（try_next_auth），第三次成功
		n := calls.Load()
		if n < 3 {
			return respFrom(401, "application/json", `{"error":{"type":"authentication_error"}}`), nil
		}
		return respFrom(200, "text/event-stream", anthropicSemanticBody()), nil
	})

	run, err := svc.Plan(context.Background(), rt.ID, model.EndpointMessages, CalibrationPlanOptions{Manual: true})
	if err != nil {
		t.Fatal(err)
	}
	started, err := svc.Start(context.Background(), run.ID, run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		_ = svc.stepOnce(context.Background())
		got, _ := st.GetCalibrationRun(context.Background(), started.ID)
		if got.State == model.CalibrationSucceeded || got.State == model.CalibrationFailed ||
			got.State == model.CalibrationInterrupted {
			break
		}
	}
	final, err := st.GetCalibrationRun(context.Background(), started.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.State != model.CalibrationSucceeded {
		t.Fatalf("state=%s candidates=%+v", final.State, final.Candidates)
	}
	if counter.count() != int(calls.Load()) {
		t.Fatalf("counting transport=%d calls=%d", counter.count(), calls.Load())
	}
	if counter.count() != 3 {
		t.Fatalf("应执行 3 个候选各一次，实际 RoundTrip=%d", counter.count())
	}
	// 成功后 Auth Profile 固化为单一模式
	ep, err := st.Endpoint(context.Background(), up.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	if ep.AuthProfile.Mode != model.AuthModeAutoCalibrated || ep.AuthProfile.CalibratedMode == "" {
		t.Fatalf("auth profile=%+v", ep.AuthProfile)
	}
}

func TestCalibration_StopOn429_DoesNotAdvance(t *testing.T) {
	st := calibrationTestStore(t)
	up, _, rt := seedCalibrationRoute(t, st)
	svc, counter := newCalibrationHarness(t, st, up, func(*http.Request) (*http.Response, error) {
		return respFrom(429, "application/json", `{"error":{"type":"rate_limit_error"}}`), nil
	})
	run, err := svc.Plan(context.Background(), rt.ID, model.EndpointMessages, CalibrationPlanOptions{Manual: true})
	if err != nil {
		t.Fatal(err)
	}
	started, err := svc.Start(context.Background(), run.ID, run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		_ = svc.stepOnce(context.Background())
	}
	final, _ := st.GetCalibrationRun(context.Background(), started.ID)
	if final.State != model.CalibrationFailed {
		t.Fatalf("429 应停止 run，state=%s", final.State)
	}
	if counter.count() != 1 {
		t.Fatalf("429 不应换候选，RoundTrip=%d", counter.count())
	}
	if final.Current != 0 {
		t.Fatalf("current 应停在 0，got %d", final.Current)
	}
}

func TestCalibration_StopOn5xx_DoesNotAdvance(t *testing.T) {
	st := calibrationTestStore(t)
	up, _, rt := seedCalibrationRoute(t, st)
	svc, counter := newCalibrationHarness(t, st, up, func(*http.Request) (*http.Response, error) {
		return respFrom(503, "application/json", `{"error":{"type":"api_error"}}`), nil
	})
	run, err := svc.Plan(context.Background(), rt.ID, model.EndpointMessages, CalibrationPlanOptions{Manual: true})
	if err != nil {
		t.Fatal(err)
	}
	started, err := svc.Start(context.Background(), run.ID, run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		_ = svc.stepOnce(context.Background())
	}
	final, _ := st.GetCalibrationRun(context.Background(), started.ID)
	if final.State != model.CalibrationFailed {
		t.Fatalf("5xx 应停止 run，state=%s", final.State)
	}
	if counter.count() != 1 {
		t.Fatalf("5xx 不应换候选，RoundTrip=%d", counter.count())
	}
}

func TestCalibration_ConnectFailure_DoesNotAdvance(t *testing.T) {
	st := calibrationTestStore(t)
	up, _, rt := seedCalibrationRoute(t, st)
	svc, counter := newCalibrationHarness(t, st, up, func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused")
	})
	run, err := svc.Plan(context.Background(), rt.ID, model.EndpointMessages, CalibrationPlanOptions{Manual: true})
	if err != nil {
		t.Fatal(err)
	}
	started, err := svc.Start(context.Background(), run.ID, run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		_ = svc.stepOnce(context.Background())
	}
	final, _ := st.GetCalibrationRun(context.Background(), started.ID)
	if final.State != model.CalibrationFailed {
		t.Fatalf("连接失败应停止 run，state=%s", final.State)
	}
	if counter.count() != 1 {
		t.Fatalf("连接失败不应换候选，RoundTrip=%d", counter.count())
	}
}

func TestCalibration_ProductionResultRecorder_DoesNotUpgradeSingle401(t *testing.T) {
	st := calibrationTestStore(t)
	up, _, rt := seedCalibrationRoute(t, st)
	settings := model.DefaultSettings()
	reach := health.NewReachabilityTracker(capSettings{settings})
	caps := NewCapabilityRegistry(capSettings{settings})
	recorder := NewResultRecorder(st, health.NewObservationReducer(nil), reach, caps)

	var calls atomic.Int64
	rtTrip := &countingRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		n := calls.Add(1)
		if n < 3 {
			return respFrom(401, "application/json", `{"error":{"type":"authentication_error"}}`), nil
		}
		return respFrom(200, "text/event-stream", anthropicSemanticBody()), nil
	}}
	targets := outbound.NewProvider(
		storeEndpointSource{store: st}, nil, outbound.NewResolver(testHasher{}))
	recipes := NewRecipeResolver(st).WithNotFound(func(err error) bool {
		return errors.Is(err, store.ErrNotFound)
	})
	executor := NewExecutor(targets, st, recipes, fakeTransports{rt: rtTrip},
		recorder, AlwaysOpenAdmission(), WallClock(), nil)
	svc := NewCalibrationService(st, executor, WallClock(), nil, func() (model.Settings, error) {
		return settings, nil
	}, caps)

	run, err := svc.Plan(context.Background(), rt.ID, model.EndpointMessages, CalibrationPlanOptions{Manual: true})
	if err != nil {
		t.Fatal(err)
	}
	started, err := svc.Start(context.Background(), run.ID, run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		_ = svc.stepOnce(context.Background())
		got, _ := st.GetCalibrationRun(context.Background(), started.ID)
		if got.State == model.CalibrationSucceeded || got.State == model.CalibrationFailed {
			break
		}
	}
	final, err := st.GetCalibrationRun(context.Background(), started.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.State != model.CalibrationSucceeded {
		t.Fatalf("ResultRecorder 路径应成功，state=%s", final.State)
	}
	if rtTrip.count() != 3 {
		t.Fatalf("RoundTrip=%d want 3", rtTrip.count())
	}
	if snap := reach.Snapshot(up.ID); snap != nil {
		t.Fatalf("校准不得改 Reachability: %+v", snap)
	}
}

func TestCalibration_ExhaustedAuthCapabilityHasValidSelector(t *testing.T) {
	st := calibrationTestStore(t)
	up, _, rt := seedCalibrationRoute(t, st)
	svc, _ := newCalibrationHarness(t, st, up, func(*http.Request) (*http.Response, error) {
		return respFrom(401, "application/json", `{"error":{"type":"authentication_error"}}`), nil
	})
	run, err := svc.Plan(context.Background(), rt.ID, model.EndpointMessages, CalibrationPlanOptions{Manual: true})
	if err != nil {
		t.Fatal(err)
	}
	started, err := svc.Start(context.Background(), run.ID, run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		_ = svc.stepOnce(context.Background())
		got, _ := st.GetCalibrationRun(context.Background(), started.ID)
		if got.State == model.CalibrationFailed {
			break
		}
	}
	caps, err := st.ListCapabilities(context.Background(), model.CapabilityFilter{
		PageRequest: model.PageRequest{Limit: 20},
		Endpoint:    model.EndpointMessages,
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range caps.Items {
		if row.ScopeID == rt.ID && row.State == model.CapabilityConfigError {
			found = true
			if err := row.PolicySelector.Validate(); err != nil {
				t.Fatalf("穷尽鉴权写入的 capability selector 无效: %v (%+v)", err, row.PolicySelector)
			}
			if row.PolicySelector.TimeoutProfile != model.TimeoutL2Standard {
				t.Fatalf("timeout_profile=%q", row.PolicySelector.TimeoutProfile)
			}
		}
	}
	if !found {
		t.Fatal("应写入 config_error capability")
	}
}

func TestCalibration_CancelDoesNotStartNext(t *testing.T) {
	st := calibrationTestStore(t)
	up, _, rt := seedCalibrationRoute(t, st)
	block := make(chan struct{})
	svc, counter := newCalibrationHarness(t, st, up, func(*http.Request) (*http.Response, error) {
		<-block
		return respFrom(401, "application/json", `{}`), nil
	})
	run, err := svc.Plan(context.Background(), rt.ID, model.EndpointMessages, CalibrationPlanOptions{Manual: true})
	if err != nil {
		t.Fatal(err)
	}
	started, err := svc.Start(context.Background(), run.ID, run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Cancel(context.Background(), started.ID, started.Revision); err != nil {
		t.Fatal(err)
	}
	close(block)
	_ = svc.stepOnce(context.Background())
	final, _ := st.GetCalibrationRun(context.Background(), started.ID)
	if final.State != model.CalibrationCanceled {
		t.Fatalf("state=%s", final.State)
	}
	if counter.count() != 0 {
		t.Fatalf("cancel 后不应发送，RoundTrip=%d", counter.count())
	}
}

func TestCalibration_AllAuthRejectedWritesConfigError_NotReachability(t *testing.T) {
	st := calibrationTestStore(t)
	up, _, rt := seedCalibrationRoute(t, st)
	svc, counter := newCalibrationHarness(t, st, up, func(*http.Request) (*http.Response, error) {
		return respFrom(401, "application/json", `{"error":{"type":"authentication_error"}}`), nil
	})
	run, err := svc.Plan(context.Background(), rt.ID, model.EndpointMessages, CalibrationPlanOptions{Manual: true})
	if err != nil {
		t.Fatal(err)
	}
	started, err := svc.Start(context.Background(), run.ID, run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		_ = svc.stepOnce(context.Background())
		got, _ := st.GetCalibrationRun(context.Background(), started.ID)
		if got.State == model.CalibrationFailed {
			break
		}
	}
	final, _ := st.GetCalibrationRun(context.Background(), started.ID)
	if final.State != model.CalibrationFailed {
		t.Fatalf("state=%s", final.State)
	}
	if counter.count() != len(final.Candidates) {
		t.Fatalf("RoundTrip=%d candidates=%d", counter.count(), len(final.Candidates))
	}
	caps, err := st.ListCapabilities(context.Background(), model.CapabilityFilter{
		PageRequest: model.PageRequest{Limit: 20},
		Endpoint:    model.EndpointMessages,
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range caps.Items {
		if row.ScopeID == rt.ID && row.State == model.CapabilityConfigError {
			found = true
			if row.RedactedDetail != "" && strings.Contains(row.RedactedDetail, "sk-") {
				t.Fatal("capability 明细不能含 secret 明文")
			}
		}
	}
	if !found {
		t.Fatal("全部 auth_rejected 后应写 Endpoint config_error")
	}
	// Upstream Reachability 不应被写
	reach, listErr := st.ListReachability(context.Background(), model.ReachabilityFilter{
		PageRequest: model.PageRequest{Limit: 20},
	})
	if listErr != nil {
		t.Fatal(listErr)
	}
	for _, row := range reach.Items {
		if row.UpstreamID == up.ID {
			t.Fatalf("校准穷尽鉴权不得改 Upstream Reachability: %+v", row)
		}
	}
}

func TestCalibration_SendStartedWithoutExecution_Interrupts(t *testing.T) {
	st := calibrationTestStore(t)
	up, _, rt := seedCalibrationRoute(t, st)
	svc, counter := newCalibrationHarness(t, st, up, func(*http.Request) (*http.Response, error) {
		t.Fatal("interrupted 路径不得重发")
		return nil, errors.New("no")
	})
	run, err := svc.Plan(context.Background(), rt.ID, model.EndpointMessages, CalibrationPlanOptions{Manual: true})
	if err != nil {
		t.Fatal(err)
	}
	started, err := svc.Start(context.Background(), run.ID, run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	// 手动 prepare + mark send_started，不 Execute
	builtin, err := LoadBuiltinTemplates()
	if err != nil {
		t.Fatal(err)
	}
	compact, err := builtin.Compact(model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	material := store.PrepareCalibrationMaterial{
		Origin: compact.Family, Method: compact.Method, FixedRawQuery: compact.RawQuery,
		Headers: compact.Headers, Body: compact.Body, BodyIsText: true,
		StreamExpected: compact.StreamExpected, TimeoutProfile: compact.TimeoutProfile,
		EstimatedInputTokens: compact.EstimatedInputTokens, SourceTemplateID: compact.ID,
		SourceRevision: compact.Revision,
	}
	fresh, _ := st.GetCalibrationRun(context.Background(), started.ID)
	if _, err := st.PrepareCalibrationCandidate(context.Background(), fresh.ID, 0, fresh.Revision, material); err != nil {
		t.Fatal(err)
	}
	fresh, _ = st.GetCalibrationRun(context.Background(), started.ID)
	execID := fresh.Candidates[0].ExecutionID
	if execID == "" {
		t.Fatal("prepare 应预分配 execution id")
	}
	if err := st.MarkCalibrationSendStarted(context.Background(), fresh.ID, 0, execID, fresh.Revision); err != nil {
		t.Fatal(err)
	}
	fresh, _ = st.GetCalibrationRun(context.Background(), started.ID)
	if err := svc.advanceRun(context.Background(), fresh); err != nil {
		t.Fatal(err)
	}
	final, _ := st.GetCalibrationRun(context.Background(), started.ID)
	if final.State != model.CalibrationInterrupted {
		t.Fatalf("state=%s want interrupted", final.State)
	}
	if final.Candidates[0].State != model.CalibrationCandidateIndeterminate {
		t.Fatalf("candidate state=%s", final.Candidates[0].State)
	}
	if counter.count() != 0 {
		t.Fatalf("零发送，got %d", counter.count())
	}
}

func TestCalibration_PreparedCrashResumesOnce(t *testing.T) {
	st := calibrationTestStore(t)
	up, _, rt := seedCalibrationRoute(t, st)
	svc, counter := newCalibrationHarness(t, st, up, func(*http.Request) (*http.Response, error) {
		return respFrom(200, "text/event-stream", anthropicSemanticBody()), nil
	})
	crashed := false
	svc.WithCrashAt(CrashAfterPrepared, func(CalibrationCrashPoint) {
		if !crashed {
			crashed = true
			panic("injected crash after prepared")
		}
	})
	run, err := svc.Plan(context.Background(), rt.ID, model.EndpointMessages, CalibrationPlanOptions{Manual: true})
	if err != nil {
		t.Fatal(err)
	}
	started, err := svc.Start(context.Background(), run.ID, run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() { _ = recover() }()
		_ = svc.advanceRun(context.Background(), &started)
	}()
	fresh, _ := st.GetCalibrationRun(context.Background(), started.ID)
	if fresh.Candidates[0].State != model.CalibrationCandidatePrepared {
		t.Fatalf("crash 后应停留 prepared，got %s", fresh.Candidates[0].State)
	}
	// 清 crash hook 后继续
	svc.crashAt = ""
	svc.crashFn = nil
	_ = svc.advanceRun(context.Background(), fresh)
	for i := 0; i < 4; i++ {
		got, _ := st.GetCalibrationRun(context.Background(), started.ID)
		if got.State == model.CalibrationSucceeded {
			break
		}
		_ = svc.stepOnce(context.Background())
	}
	final, _ := st.GetCalibrationRun(context.Background(), started.ID)
	if final.State != model.CalibrationSucceeded {
		t.Fatalf("resume 后应成功，state=%s", final.State)
	}
	if counter.count() != 1 {
		t.Fatalf("prepared 恢复后总发送一次，got %d", counter.count())
	}
}

func TestExecutor_ExplicitRecipeUsesAuthOverride(t *testing.T) {
	st := calibrationTestStore(t)
	up, mn, rt := seedCalibrationRoute(t, st)
	var sawAuth string
	rtTrip := &countingRoundTripper{fn: func(req *http.Request) (*http.Response, error) {
		sawAuth = req.Header.Get("Authorization")
		if req.Header.Get("X-Api-Key") != "" {
			t.Error("不得同时写 x-api-key")
		}
		return respFrom(200, "text/event-stream", anthropicSemanticBody()), nil
	}}
	targets := outbound.NewProvider(storeEndpointSource{store: st}, nil, outbound.NewResolver(testHasher{}))
	recipes := NewRecipeResolver(st).WithNotFound(func(err error) bool {
		return errors.Is(err, store.ErrNotFound)
	})
	exec := NewExecutor(targets, st, recipes, fakeTransports{rt: rtTrip},
		&captureRecorder{}, AlwaysOpenAdmission(), WallClock(), nil)

	builtin, _ := LoadBuiltinTemplates()
	compact, _ := builtin.Compact(model.EndpointMessages)
	compiled := compact.Compiled()
	auth, err := SingleAuthProfile(model.AuthModeBearer, "upstream_api_key")
	if err != nil {
		t.Fatal(err)
	}
	result, err := exec.Execute(context.Background(), ExecutionRequest{
		ExecutionID: "explicit-1", Trigger: model.TriggerCalibration,
		Upstream: up, ModelName: mn, Route: rt, Endpoint: model.EndpointMessages,
		Budget: outbound.L2Budget(model.DefaultSettings()),
		ExplicitRecipe: &ResolvedRecipe{
			Layer: model.ResolvedRoute,
			Identity: model.RecipeIdentity{
				Storage: model.RecipeStorageDB, Origin: model.RecipeCompact, DBVersionID: 1,
			},
			Facts:    model.RecipeBindingFacts{Use: model.BindingExplicitTest, ResolvedLayer: model.ResolvedRoute},
			Compiled: compiled, StreamExpected: compact.StreamExpected, TimeoutProfile: compact.TimeoutProfile,
		},
		AuthOverride: &auth,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rtTrip.count() != 1 {
		t.Fatalf("RoundTrip=%d", rtTrip.count())
	}
	if !strings.HasPrefix(sawAuth, "Bearer ") {
		t.Fatalf("Authorization=%q", sawAuth)
	}
	if result.Execution.RecipeBindingUse != model.BindingExplicitTest {
		t.Fatalf("binding use=%s", result.Execution.RecipeBindingUse)
	}
}
