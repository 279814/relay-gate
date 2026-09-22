package probe

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
)

// ── 测试替身 ──────────────────────────────────────────────

// countingRoundTripper 统计 RoundTrip 次数，用来断言「至多一次 HTTP 请求」。
type countingRoundTripper struct {
	mu    sync.Mutex
	calls int
	fn    func(*http.Request) (*http.Response, error)
}

func (rt *countingRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	rt.mu.Lock()
	rt.calls++
	rt.mu.Unlock()
	return rt.fn(request)
}

func (rt *countingRoundTripper) count() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.calls
}

// fakeTransports 把一个固定 RoundTripper 交给 Executor，不碰真实连接池。
type fakeTransports struct{ rt http.RoundTripper }

func (f fakeTransports) RoundTripper(_ outbound.NetworkConfig) (http.RoundTripper, error) {
	return f.rt, nil
}

// captureRecorder 记录最后一次 observation，可注入写库失败。
type captureRecorder struct {
	calls int
	obs   *model.ProbeObservation
	err   error
}

func (r *captureRecorder) Record(_ context.Context, v *model.ProbeObservation) (model.ProbeApplyResult, error) {
	r.calls++
	clone := *v
	r.obs = &clone
	if r.err != nil {
		return model.ProbeApplyResult{}, r.err
	}
	return model.ProbeApplyResult{
		ExecutionStored: true,
		Reachability:    model.ApplyNotApplicable,
		Capability:      model.ApplyNotApplicable,
	}, nil
}

// spyAdmission 记录 AcquireSynthetic 与 release 的次数。
type spyAdmission struct {
	acquires int
	releases int
	err      error
}

func (s *spyAdmission) AcquireSynthetic(ctx context.Context, _ model.ProbeTrigger) (context.Context, func(), error) {
	s.acquires++
	if s.err != nil {
		return ctx, nil, s.err
	}
	return ctx, func() { s.releases++ }, nil
}

// ── 构造工具 ──────────────────────────────────────────────

func anthropicSemanticBody() string {
	return "event: message_start\ndata: {\"type\":\"message_start\"}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"2\"}}\n\n"
}

func respFrom(status int, contentType, body string) *http.Response {
	header := http.Header{}
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// newTestExecutorFor 装配一个 Executor，其出站解析面跟随该 Upstream 的
// auth_style（这样 legacy_auto_real_only 的 fail-closed 才能被触发）。
func newTestExecutorFor(up *model.Upstream, rt http.RoundTripper, recorder ExecutionRecorder,
	admission SyntheticAdmission, clock Clock) *Executor {

	targets := outbound.NewProvider(testEndpoints{upstream: up}, nil, outbound.NewResolver(testHasher{}))
	return NewExecutor(targets, nil, nil, fakeTransports{rt: rt}, recorder, admission, clock, nil)
}

func l2RequestFor(up *model.Upstream) ExecutionRequest {
	mn := modelNameFor(model.ProtoAnthropic)
	kind, _ := mn.Protocol.Endpoint()
	return ExecutionRequest{
		ExecutionID:      "exec-test",
		Trigger:          model.TriggerScheduled,
		Upstream:         up,
		ModelName:        mn,
		Route:            &model.Route{ID: 1},
		Endpoint:         kind,
		Mode:             ObserveProbe,
		Budget:           outbound.L2Budget(fastSettings()),
		ObservationOrder: 42,
	}
}

// ── 测试 ─────────────────────────────────────────────────

// 成功路径：恰好一次 RoundTrip，probe 模式首语义后主动断流（ExpectedCancel），
// SentAt 非零，execution 落库且两个 disposition 为 not_applicable。
func TestExecutor_SuccessSingleRoundTrip(t *testing.T) {
	rt := &countingRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		return respFrom(200, "text/event-stream", anthropicSemanticBody()), nil
	}}
	recorder := &captureRecorder{}
	up := upstreamFor("https://example.test")
	exec := newTestExecutorFor(up, rt, recorder, AlwaysOpenAdmission(), WallClock())

	result, err := exec.Execute(context.Background(), l2RequestFor(up))
	if err != nil {
		t.Fatalf("Execute 不该返回基础设施错误: %v", err)
	}
	if rt.count() != 1 {
		t.Fatalf("必须恰好一次 RoundTrip，实际 %d", rt.count())
	}
	if !result.Decision.Success {
		t.Errorf("应判成功，Decision=%+v", result.Decision)
	}
	if result.Outcome.Verdict != health.VerdictOK {
		t.Errorf("Outcome 应为 OK，实际 %s", result.Outcome.Verdict)
	}
	if !result.ExpectedCancel {
		t.Error("probe 模式首语义后应主动断流，ExpectedCancel 应为 true")
	}
	if result.Execution.SentAtMS == 0 {
		t.Error("进入过 RoundTrip，SentAt 不应为零")
	}
	if result.Execution.ObservationOrder != 42 {
		t.Errorf("ObservationOrder 应透传，实际 %d", result.Execution.ObservationOrder)
	}
	if recorder.calls != 1 {
		t.Fatalf("应落库一次，实际 %d", recorder.calls)
	}
	if result.Execution.CapabilityDisposition != model.ApplyNotApplicable {
		t.Errorf("capability disposition 应为 not_applicable，实际 %q",
			result.Execution.CapabilityDisposition)
	}
}

// 本地配置错误（legacy auto fail-closed）：不出网、RequestBytes=0、RoundTrip=0、
// Reachability not_applicable、Capability not_applicable（无当前期望）。
func TestExecutor_ConfigErrorDoesNotSend(t *testing.T) {
	rt := &countingRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		t.Error("配置错误绝不该进入 RoundTrip")
		return respFrom(200, "", ""), nil
	}}
	recorder := &captureRecorder{}
	up := upstreamFor("https://example.test")
	up.AuthStyle = model.AuthAuto // → legacy_auto_real_only：合成探活 fail closed
	exec := newTestExecutorFor(up, rt, recorder, AlwaysOpenAdmission(), WallClock())

	result, err := exec.Execute(context.Background(), l2RequestFor(up))
	if err != nil {
		t.Fatalf("配置错误应记录而非返回错误: %v", err)
	}
	if rt.count() != 0 {
		t.Fatalf("配置错误不该出网，RoundTrip=%d", rt.count())
	}
	if result.Sent {
		t.Error("config_error 的 Sent 应为 false")
	}
	if result.Execution.RequestBytes != 0 {
		t.Errorf("RequestBytes 应为 0，实际 %d", result.Execution.RequestBytes)
	}
	if result.Execution.SentAtMS != 0 {
		t.Errorf("未进入 RoundTrip，SentAt 应为 0，实际 %d", result.Execution.SentAtMS)
	}
	if result.Execution.ErrorClass != model.ErrorConfig {
		t.Errorf("应为 config_error，实际 %q", result.Execution.ErrorClass)
	}
	if result.Decision.Capability != model.CapabilityUnknown {
		t.Errorf("无当前期望时 capability 应保持 unknown，实际 %q", result.Decision.Capability)
	}
	if result.Execution.ReachabilityDisposition != model.ApplyNotApplicable {
		t.Errorf("reachability disposition 应为 not_applicable")
	}
}

// 有当前 Capability 期望时，配置错误把 capability 记成 config_error。
func TestExecutor_ConfigErrorWithExpectationIsConfigError(t *testing.T) {
	rt := &countingRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		return respFrom(200, "", ""), nil
	}}
	up := upstreamFor("https://example.test")
	up.AuthStyle = model.AuthAuto
	exec := newTestExecutorFor(up, rt, &captureRecorder{}, AlwaysOpenAdmission(), WallClock())

	req := l2RequestFor(up)
	req.CapabilityExpectation = &model.SemanticExpectation{}

	result, _ := exec.Execute(context.Background(), req)
	if result.Decision.Capability != model.CapabilityConfigError {
		t.Errorf("有当前期望时 capability 应为 config_error，实际 %q", result.Decision.Capability)
	}
}

// 真实流量不取合成 lease（§P0-09 第 4 条）。
func TestExecutor_RealTrafficDoesNotAcquireLease(t *testing.T) {
	rt := &countingRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		return respFrom(200, "text/event-stream", anthropicSemanticBody()), nil
	}}
	admission := &spyAdmission{}
	up := upstreamFor("https://example.test")
	exec := newTestExecutorFor(up, rt, &captureRecorder{}, admission, WallClock())

	req := l2RequestFor(up)
	req.Trigger = model.TriggerRealTraffic
	req.Mode = ObserveReal

	if _, err := exec.Execute(context.Background(), req); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if admission.acquires != 0 {
		t.Errorf("真实流量不该取合成 lease，acquires=%d", admission.acquires)
	}
}

// 合成探活取一次 lease 并在返回时 release 恰好一次（成功路径）。
func TestExecutor_SyntheticAcquiresAndReleasesOnce(t *testing.T) {
	rt := &countingRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		return respFrom(200, "text/event-stream", anthropicSemanticBody()), nil
	}}
	admission := &spyAdmission{}
	up := upstreamFor("https://example.test")
	exec := newTestExecutorFor(up, rt, &captureRecorder{}, admission, WallClock())

	if _, err := exec.Execute(context.Background(), l2RequestFor(up)); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if admission.acquires != 1 || admission.releases != 1 {
		t.Errorf("应 acquire/release 各一次，实际 acquire=%d release=%d",
			admission.acquires, admission.releases)
	}
}

// 配置错误路径同样 release 恰好一次。
func TestExecutor_ReleaseOnceOnConfigError(t *testing.T) {
	rt := &countingRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		return respFrom(200, "", ""), nil
	}}
	admission := &spyAdmission{}
	up := upstreamFor("https://example.test")
	up.AuthStyle = model.AuthAuto
	exec := newTestExecutorFor(up, rt, &captureRecorder{}, admission, WallClock())

	if _, err := exec.Execute(context.Background(), l2RequestFor(up)); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if admission.releases != 1 {
		t.Errorf("配置错误路径也应 release 一次，实际 %d", admission.releases)
	}
}

// admission 拿不到 lease：作为 Go error 上抛，不构造 execution。
func TestExecutor_AdmissionErrorPropagates(t *testing.T) {
	sentinel := errors.New("no lease")
	rt := &countingRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		t.Error("拿不到 lease 不该出网")
		return respFrom(200, "", ""), nil
	}}
	recorder := &captureRecorder{}
	up := upstreamFor("https://example.test")
	exec := newTestExecutorFor(up, rt, recorder, &spyAdmission{err: sentinel}, WallClock())

	_, err := exec.Execute(context.Background(), l2RequestFor(up))
	if !errors.Is(err, sentinel) {
		t.Fatalf("应上抛 admission 错误，实际 %v", err)
	}
	if recorder.calls != 0 {
		t.Errorf("拿不到 lease 不该落库，calls=%d", recorder.calls)
	}
}

// 写库失败作为 Go error（§P0-09 第 8 条），Outcome 仍反映站点结果。
func TestExecutor_RecorderErrorIsGoError(t *testing.T) {
	sentinel := errors.New("db down")
	rt := &countingRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		return respFrom(200, "text/event-stream", anthropicSemanticBody()), nil
	}}
	recorder := &captureRecorder{err: sentinel}
	up := upstreamFor("https://example.test")
	exec := newTestExecutorFor(up, rt, recorder, AlwaysOpenAdmission(), WallClock())

	result, err := exec.Execute(context.Background(), l2RequestFor(up))
	if !errors.Is(err, sentinel) {
		t.Fatalf("写库失败应作为 Go error 上抛，实际 %v", err)
	}
	if result.Outcome.Verdict != health.VerdictOK {
		t.Errorf("Outcome 应仍反映站点成功，不该被伪装成失败，实际 %s", result.Outcome.Verdict)
	}
}

// 传输层失败：status=0、unreachable、SentAt 非零、不 reachable。
func TestExecutor_TransportFailure(t *testing.T) {
	rt := &countingRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused")
	}}
	up := upstreamFor("https://example.test")
	exec := newTestExecutorFor(up, rt, &captureRecorder{}, AlwaysOpenAdmission(), WallClock())

	result, err := exec.Execute(context.Background(), l2RequestFor(up))
	if err != nil {
		t.Fatalf("传输失败是站点结果，不该是 Go error: %v", err)
	}
	if result.Decision.Reachable {
		t.Error("传输失败应判 unreachable")
	}
	if result.Decision.StatusCode != 0 {
		t.Errorf("连响应头都没拿到，status 应为 0，实际 %d", result.Decision.StatusCode)
	}
	if result.Outcome.Verdict != health.VerdictUnavailable {
		t.Errorf("传输失败应为 unavailable，实际 %s", result.Outcome.Verdict)
	}
	if !result.Sent || result.Execution.SentAtMS == 0 {
		t.Error("进入过 RoundTrip，Sent/SentAt 应已置")
	}
}

// 200 但流内无语义证据 → fake_alive → unavailable。
func TestExecutor_FakeAlive(t *testing.T) {
	rt := &countingRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		return respFrom(200, "text/event-stream",
			"event: message_start\ndata: {\"type\":\"message_start\"}\n\n"), nil
	}}
	up := upstreamFor("https://example.test")
	exec := newTestExecutorFor(up, rt, &captureRecorder{}, AlwaysOpenAdmission(), WallClock())

	result, err := exec.Execute(context.Background(), l2RequestFor(up))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Decision.Success {
		t.Error("无语义证据不该判成功")
	}
	if result.Outcome.Verdict != health.VerdictUnavailable {
		t.Errorf("假活应为 unavailable，实际 %s", result.Outcome.Verdict)
	}
	if result.Decision.ErrorClass != model.ErrorFakeAlive {
		t.Errorf("应归类 fake_alive，实际 %q", result.Decision.ErrorClass)
	}
}

// 执行不写任何明文：脱敏详情不含 key/密钥字节（§P0-09 第 9 条）。
func TestExecutor_NoPlaintextInExecution(t *testing.T) {
	rt := &countingRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		return respFrom(401, "application/json", `{"error":"Invalid API key: sk-test-key-123456"}`), nil
	}}
	recorder := &captureRecorder{}
	up := upstreamFor("https://example.test")
	exec := newTestExecutorFor(up, rt, recorder, AlwaysOpenAdmission(), WallClock())

	result, err := exec.Execute(context.Background(), l2RequestFor(up))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if strings.Contains(result.Execution.RedactedDetail, "sk-test-key") {
		t.Errorf("execution 明文泄露: %q", result.Execution.RedactedDetail)
	}
	_ = time.Now
}
