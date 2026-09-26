package probe

// Executor 是「恰好一次请求的可观测执行单元」（§4.7、§8.6 的 ProbeExecutor）。
//
// 它把探活主链收敛成唯一一条路径：admission → 准备（解析/渲染/认证）→
// 单次 RoundTrip → 按 Clock 分阶段读流 → 用 ResponseClassifier 归约成 Decision →
// 展平进 ProbeExecution 并交给 recorder 落库。L1/L2/ProbeNow 与将来的真实流量
// 旁路都走这一条，所以「探活到底发了什么、看到了什么」只有一个答案。
//
// 为什么不复用旧 Prober.L1/L2 的发送段：那两段各自拼请求、各自读流、各自
// 把结果映射成 health.Verdict，而 §4.6 要的是一个带**作用范围**的 Decision。
// 本执行器只产出 Decision（+ 一份供 P0-10 之前的 health.Tracker 消费的
// 兼容 Outcome 映射），状态推进留给 P0-10 的 Registry。
//
// 时间只从注入的 Clock 取（§4.6/§7.4）：阶段超时、绝对时间戳、Retry-After
// 的 headerAt 必须同一口径，否则「同一次响应」会在 execution 行里出现互相
// 矛盾的时间。测试用 ManualClock 拨快，不睡真实时间。

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

// 默认解码预算：单事件 1 MiB、总量 8 MiB。探活正文都很小，这两个上限只是
// 防一个恶意/故障上游用无穷流把内存打爆，正常响应远够不到。
const (
	defaultMaxEventBytes = int64(1) << 20
	defaultMaxTotalBytes = int64(8) << 20
	// readChunk 是每次网络读的缓冲大小。探活正文小，4 KiB 足够一次读完
	// 绝大多数首事件。
	readChunk = 4096
)

// TargetResolver 是 Executor 需要的出站目标解析面。
//
// 定义成窄接口而不是直接收 *outbound.Provider：Executor 只用到「把一次探活
// 解析成 URL/Host/认证 profile」这一件事，而 outbound.TargetProvider 正好是
// 这个形状。**不新增第二套 URL 规则**（§7.1）：解析仍由 outbound 独占。
type TargetResolver = outbound.TargetProvider

// TransportManager 按网络身份提供 RoundTripper。
//
// 收接口而不是 *outbound.Manager：生产经 ManagerTransports 适配（连接池与
// 真实转发共用，§7.3），测试注入一个返回计数 RoundTripper 的实现，从而能
// 在不出网的前提下断言「至多一次 RoundTrip」（§P0-09 第 1 条）。
type TransportManager interface {
	RoundTripper(network outbound.NetworkConfig) (http.RoundTripper, error)
}

// ManagerTransports 把 *outbound.Manager 适配成 TransportManager。
//
// *outbound.Transport 本身就是 http.RoundTripper，这里只是把「取池」与
// 「当作 RoundTripper 用」这两件事在类型上接起来，不引入第二个连接池来源。
type ManagerTransports struct{ Manager *outbound.Manager }

// RoundTripper 取（或建）这份网络身份的连接池。
func (m ManagerTransports) RoundTripper(network outbound.NetworkConfig) (http.RoundTripper, error) {
	transport, err := m.Manager.Transport(network)
	if err != nil {
		return nil, err
	}
	return transport, nil
}

// ExecutionRecorder 落一次观测（§4.7）。P0-09 的实现是 ExecutionOnlyRecorder。
type ExecutionRecorder interface {
	Record(ctx context.Context, v *model.ProbeObservation) (model.ProbeApplyResult, error)
}

// ExecutionRequest 是一次执行的全部输入。
//
// 与 §4.7 的字段清单对齐，但携带领域对象（*Upstream/*ModelName/*Route）而非
// 预解析的 Recipe：这样 Executor 能直接复用已被充分测试的 prepare（解析 →
// 渲染 → 认证），避免把那条链再抄一遍。调用方（Scheduler）负责算出 Budget、
// 期望与 ObservationOrder。
type ExecutionRequest struct {
	ExecutionID string
	Trigger     model.ProbeTrigger
	Upstream    *model.Upstream
	ModelName   *model.ModelName
	Route       *model.Route
	Endpoint    model.EndpointKind
	// Mode 区分主动探活与真实流量旁路（§6.8）。零值按 probe 处理。
	Mode ObservationMode
	// Budget 是这次执行的分阶段时间预算，从 Settings 经 outbound.*Budget 得到。
	Budget outbound.Budget

	ReachabilityPolicy      *model.ReachabilityReductionPolicy
	CapabilityPolicy        *model.CapabilityReductionPolicy
	ReachabilityExpectation *model.ReachabilityExpectation
	CapabilityExpectation   *model.SemanticExpectation

	ObservationOrder int64
	CalibrationRunID string
	CandidateOrdinal int

	// ExplicitRecipe / AuthOverride 供 CalibrationRun 使用（§P0-11）：
	// 必须测已经物化的 DB version，并用候选的单一 AuthMode，不能走四级解析后再
	// 声称另一个 version 已通过。二者都非 nil 时 prepare 走显式路径。
	ExplicitRecipe *ResolvedRecipe
	AuthOverride   *model.EndpointAuthProfile

	// DiagnosticEndpoint / ProbeSettingsFingerprint / ProbeSecretRevisionsHash
	// 只用于校准：把 test 当时的 Endpoint/Auth/Settings/Secret 口径冻进 execution，
	// 供 CommitCalibrationSuccess 在 commit 时与 DB-current 比对（§P0-11 第 14 条）。
	// 不作为 CapabilityExpectation，避免校准中间态经 ResultRecorder 提前写能力。
	DiagnosticEndpoint        *model.UpstreamEndpoint
	CalibrationPolicySelector model.EvidencePolicySelector
	ProbeSettingsFingerprint  string
	ProbeSecretRevisionsHash  string
}

// ExecutionResult 是一次执行的产出。
//
// Decision 是权威结论；Outcome 是给 P0-10 之前的 health.Tracker 用的兼容映射；
// Execution 是落库的那一行（recorder 为 nil 时仍然构造，供调用方观察）。
type ExecutionResult struct {
	Decision       Decision
	Outcome        Outcome
	Execution      model.ProbeExecution
	Apply          model.ProbeApplyResult
	ExpectedCancel bool
	// Sent 表示请求已交给 Transport（进入过 RoundTrip）。config_error 保持 false。
	Sent bool
}

// Executor 见文件头。字段全部私有：装配只经 NewExecutor。
type Executor struct {
	resolver   TargetResolver
	secrets    outbound.SecretSource
	recipes    *RecipeResolver
	transports TransportManager
	clock      Clock
	log        *slog.Logger
	recorder   ExecutionRecorder
	admission  SyntheticAdmission
}

// NewExecutor 装配一个执行器。
//
// resolver/secrets/recipes 一起构成出站解析面（与真实转发共用，§7.1）；
// transports 提供连接池；recorder 落库；admission 控合成额度；clock 是唯一
// 时间来源；log 记诊断。任何一个都不该在运行时替换。
func NewExecutor(resolver TargetResolver, secrets outbound.SecretSource,
	recipes *RecipeResolver, transports TransportManager, recorder ExecutionRecorder,
	admission SyntheticAdmission, clock Clock, log *slog.Logger) *Executor {

	if clock == nil {
		clock = WallClock()
	}
	if log == nil {
		log = slog.Default()
	}
	return &Executor{
		resolver:   resolver,
		secrets:    secrets,
		recipes:    recipes,
		transports: transports,
		clock:      clock,
		log:        log,
		recorder:   recorder,
		admission:  admission,
	}
}

// Execute 跑完一次探活的全部主链。返回的 error 只表示**基础设施故障**
// （admission 拿不到、写库失败）—— 站点自身的失败在 Decision/Outcome 里，
// 绝不冒充成 Go error（§P0-09 第 8、10 条）。
func (e *Executor) Execute(ctx context.Context, req ExecutionRequest) (ExecutionResult, error) {
	if req.Mode == "" {
		req.Mode = ObserveProbe
	}

	// 合成探活取 admission，真实流量不取（§P0-09 第 4 条）。
	var release func()
	if req.Trigger != model.TriggerRealTraffic && e.admission != nil {
		attemptCtx, rel, err := e.admission.AcquireSynthetic(ctx, req.Trigger)
		if err != nil {
			// 拿不到 lease 不是站点失败：不构造 execution，直接上抛。
			return ExecutionResult{}, err
		}
		ctx = attemptCtx
		release = rel
	}
	// release 恰好一次，覆盖下面所有返回路径（§P0-09 第 5 条）。
	if release != nil {
		defer release()
	}

	// 准备阶段：解析 → 渲染 → 认证。任何一步失败都是 route-local 的
	// config_error，**不出网**（§8.6）。这里刻意不传 Transport 构造 Prober ——
	// 它只借用 prepare，不发送。
	preparer := &Prober{Targets: e.resolver, Secrets: e.secrets, Recipes: e.recipes}
	var prepared *preparedProbe
	var resolved ResolvedRecipe
	var err error
	if req.ExplicitRecipe != nil {
		prepared, resolved, err = preparer.prepareExplicit(ctx, req)
	} else {
		prepared, resolved, err = preparer.prepare(ctx, req.Upstream, req.ModelName, req.Route, req.Endpoint)
	}
	if err != nil {
		// resolved 可能是零值（解析本身就失败）：finishConfigError 会兜一份
		// 合法的 identity，好让 config_error 行也能落库（成本证据要求
		// RecipeOrigin.Valid()）。
		return e.finishConfigError(ctx, req, resolved, err)
	}

	return e.send(ctx, req, prepared)
}

// finishConfigError 处理「还没发出去就失败」：RequestBytes=0、无 RoundTrip、
// Reachability not_applicable，Capability 只在有当前真实期望时才记 config_error
// （§P0-09 第 3 条）。
//
// recipe 是准备阶段解析到的配方。解析成功但渲染/URL/认证失败时它已定，
// 用它把 recipe origin/version 落进这一行；解析本身失败时是零值，
// fallbackIdentity 会兜一份合法的 embedded identity —— 否则成本证据
// （CostEvidenceFromExecution 要求 RecipeOrigin.Valid()）建不起来，整行写库失败。
func (e *Executor) finishConfigError(ctx context.Context, req ExecutionRequest,
	recipe ResolvedRecipe, cause error) (ExecutionResult, error) {

	// Capability 只在有「当前真实期望」时才记 config_error（§P0-09 第 3 条、
	// 第 8 条）：没有期望时（显式探测/测试）能力维度不适用，保持 unknown。
	// RecipeBindingUse 会是 explicit_test 的那类将来经期望缺席被自然挡在这里。
	capState := model.CapabilityUnknown
	if req.CapabilityExpectation != nil {
		capState = model.CapabilityConfigError
	}

	now := e.clock.Now()
	decision := Decision{
		Final:                true,
		Success:              false,
		Reachable:            false,
		Capability:           capState,
		Scope:                model.ScopeNone,
		ErrorClass:           model.ErrorConfig,
		CandidateDisposition: model.CandidateStop,
		RedactedDetail:       "config_error",
	}

	exec := e.buildExecution(req, recipe, decision, sendTiming{doneAtMS: now.UnixMilli()}, 0, 0, 0, false, "", "")
	result := ExecutionResult{
		Decision:  decision,
		Outcome:   probeConfigOutcome(cause),
		Execution: exec,
		Sent:      false,
	}
	apply, recErr := e.recordExecution(ctx, req, &result.Execution)
	if recErr != nil {
		return result, recErr
	}
	result.Apply = apply
	return result, nil
}

// sendTiming 收集单调的阶段时间戳（毫秒）。零表示「没走到这个阶段」。
type sendTiming struct {
	sentAtMS              int64
	tlsHandshakeStartAtMS int64
	tlsHandshakeDoneAtMS  int64
	gotConnAtMS           int64
	responseHeaderAtMS    int64
	firstByteAtMS         int64
	firstEventAtMS        int64
	firstSemanticAtMS     int64
	doneAtMS              int64
}

// applyTrace 把 outbound.WithTrace 收集到的建连观测点落进 timing（§4.6）。
//
// 复用连接时 Reused 为 true，握手没有发生 —— TLS 两个时刻保持 0，只留
// GotConn。这些回调用的是 httptrace 的墙钟而非注入的 Clock（httptrace 不接受
// 外部时钟），所以只有走真实 Transport 的执行才会有非零值；stub RoundTripper
// 不触发回调，字段保持 0，ManualClock 测试因此不受影响。
func (t *sendTiming) applyTrace(trace *outbound.Trace) {
	if trace == nil {
		return
	}
	if !trace.GotConn.IsZero() {
		t.gotConnAtMS = trace.GotConn.UnixMilli()
	}
	if trace.Reused {
		return
	}
	if !trace.TLSHandshakeStart.IsZero() {
		t.tlsHandshakeStartAtMS = trace.TLSHandshakeStart.UnixMilli()
	}
	if !trace.TLSHandshakeDone.IsZero() {
		t.tlsHandshakeDoneAtMS = trace.TLSHandshakeDone.UnixMilli()
	}
}

// send 执行单次 RoundTrip 与分阶段读流。
func (e *Executor) send(ctx context.Context, req ExecutionRequest, prepared *preparedProbe) (ExecutionResult, error) {
	// 配方档位在 prepare 之后才确定：这里再补一次长思考 first_semantic 硬下限，
	// 挡住调用方只塞了 L2Budget（标准短窗）却跑 l2_long_thinking 的静默缩短。
	budget := outbound.ApplyLongThinkFirstSemanticFloor(req.Budget, prepared.recipe.TimeoutProfile)

	// 取连接池：网络身份含 connect 预算（§7.3）。
	network := outbound.NetworkFor(req.Upstream.ProbeConfig(), budget.Connect)
	transport, err := e.transports.RoundTripper(network)
	if err != nil {
		// 取连接池失败发生在 SentAt 之前（未发送）：走 config_error，
		// 用已解析的 recipe 填 identity。
		return e.finishConfigError(ctx, req, prepared.recipe, fmt.Errorf("取连接池失败: %w", err))
	}

	// 一个可取消的上下文覆盖整次发送：阶段超时与首语义后主动断流都靠 cancel。
	sendCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	httpReq := prepared.request.WithContext(sendCtx)

	// 装上建连观测：TLS 握手起止与 GotConn 由 outbound.WithTrace 填（§4.6）。
	// 每次请求各一个 Trace，避免并发探活串写（见 outbound.WithTrace 说明）。
	trace := &outbound.Trace{}
	httpReq = outbound.WithTrace(httpReq, trace)

	requestBytes := httpReq.ContentLength
	if requestBytes < 0 {
		requestBytes = 0
	}

	// SentAt 恰好在 RoundTrip 之前、且在取到连接池之后取（§P0-09 第 2 条）：
	// 上面取连接池失败会走 finishConfigError（SentAt=0，未发送）。
	// 进入 RoundTrip 后若 GotConn 从未到达（DNS/dial/TLS 失败），
	// finishTransportFailure 会清掉发送事实 —— 请求字节从未写出（§8.6）。
	sentAt := e.clock.Now()
	timing := sendTiming{sentAtMS: sentAt.UnixMilli()}
	estInputTokens := int64(prepared.estimatedTokens(req.ModelName))

	totalTimer := e.clock.NewTimer(budget.Total)
	defer totalTimer.Stop()

	// 响应头阶段：仅当配了 ResponseHead 才单独设时限（L1 只有 connect+total）。
	var headerTimer Timer
	if budget.ResponseHead > 0 {
		headerTimer = e.clock.NewTimer(stageDuration(sentAt, budget.ResponseHeadDeadline(sentAt)))
		defer headerTimer.Stop()
	}

	// RoundTrip 在自己的 goroutine 里跑，主 goroutine 用 select 守住时限。
	type rtResult struct {
		resp *http.Response
		err  error
	}
	rtCh := make(chan rtResult, 1)
	go func() {
		resp, rtErr := transport.RoundTrip(httpReq)
		rtCh <- rtResult{resp: resp, err: rtErr}
	}()

	var resp *http.Response
	var rtErr error
	headerTimedOut := false
	select {
	case res := <-rtCh:
		resp, rtErr = res.resp, res.err
	case <-timerC(headerTimer):
		headerTimedOut = true
		cancel()
		res := <-rtCh
		resp, rtErr = res.resp, res.err
	case <-timerC(totalTimer):
		cancel()
		res := <-rtCh
		resp, rtErr = res.resp, res.err
	}

	// RoundTrip 已返回：建连观测点此刻定稿，读它是 happens-after（经 rtCh）。
	timing.applyTrace(trace)

	// 传输层失败：连响应头都没拿到，status=0 → unreachable（§8.9）。
	if rtErr != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		timing.doneAtMS = e.clock.Now().UnixMilli()
		return e.finishTransportFailure(ctx, req, prepared, rtErr, headerTimedOut,
			requestBytes, estInputTokens, timing, sentAt)
	}
	defer resp.Body.Close()

	headerAt := e.clock.Now()
	timing.responseHeaderAtMS = headerAt.UnixMilli()

	classifier := NewResponseClassifier(req.Mode, req.Endpoint, resp.StatusCode, resp.Header, headerAt)

	// 连接层探测（空 l1_path）：拿到任何响应头即算通，不必读流（§4.1）。
	if prepared.connectionOnly {
		timing.doneAtMS = e.clock.Now().UnixMilli()
		decision := classifier.Finish(nil, nil)
		// connectionOnly 覆盖 models 的「必须是模型列表」判据：这里只探连接。
		decision.Success = decision.Reachable
		return e.finishSuccessPath(ctx, req, prepared, decision, timing,
			requestBytes, 0, estInputTokens, false, sentAt)
	}

	protocol := model.Protocol("")
	if req.ModelName != nil {
		protocol = req.ModelName.Protocol
	}
	decoder, decErr := NewDecoder(DecoderSpec{Endpoint: req.Endpoint, Protocol: protocol},
		WireAuto, defaultMaxEventBytes, defaultMaxTotalBytes)
	if decErr != nil {
		// 解码器建不起来是**我们自己的**观测故障，且请求已经发出去了
		// （§P0-09 第 2 条）：不能倒回 config_error（那会抹掉 SentAt 并谎称
		// 未发送），记成「已发送但观测未完成」，不记上游的账。
		return e.finishObserverIncomplete(ctx, req, prepared, resp.StatusCode,
			model.ObserverDecodeFailure, "observer_decode_setup", requestBytes,
			estInputTokens, timing, sentAt)
	}

	// 按 Content-Encoding 解压响应体再喂解码器（§P0-09 第 3 条）。未知/畸形
	// 编码就地失败，且绝不把正文明文泄进 RedactedDetail —— 内容解码器只吐
	// 结构化哨兵错误。identity/gzip/br 之外一律拒绝。
	bodyReader, cdErr := NewContentDecoder(resp.Header.Get("Content-Encoding"), resp.Body,
		ContentCodingLimits{MaxEncodedBytes: defaultMaxTotalBytes, MaxDecodedBytes: defaultMaxTotalBytes})
	if cdErr != nil {
		return e.finishObserverIncomplete(ctx, req, prepared, resp.StatusCode,
			model.ObserverDecodeFailure, "observer_content_encoding", requestBytes,
			estInputTokens, timing, sentAt)
	}
	defer bodyReader.Close()

	readResult := e.readStream(sendCtx, cancel, bodyReader, decoder, classifier, req, budget, sentAt, &timing)
	timing.doneAtMS = e.clock.Now().UnixMilli()

	decision := classifier.Finish(readResult.readErr, readResult.cancelCause)

	return e.finishSuccessPath(ctx, req, prepared, decision, timing, requestBytes,
		readResult.bytesRead, estInputTokens, readResult.expectedCancel, sentAt)
}

// streamResultExec 收集读流阶段的产物。
type streamResultExec struct {
	bytesRead      int64
	readErr        error
	cancelCause    error
	expectedCancel bool
}

// readStream 分阶段读响应体，把事件喂给 decoder+classifier。
//
// probe 模式下 classifier 在首个语义证据后回 final=true，此时立即 cancel 停止
// 消耗 token，并标记 expectedCancel（§4.1、§6.8、§P0-09 第 6 条）。
func (e *Executor) readStream(ctx context.Context, cancel context.CancelFunc, body io.Reader,
	decoder Decoder, classifier *ResponseClassifier, req ExecutionRequest, budget outbound.Budget,
	sentAt time.Time, timing *sendTiming) streamResultExec {

	var result streamResultExec

	// 首字节/首事件/首语义阶段共用一个「等语义」定时器：在拿到首语义前，
	// 用 FirstSemantic 截止时刻兜底；拿到后（probe 模式已 final）不再需要。
	var semanticTimer Timer
	if budget.FirstSemantic > 0 {
		semanticTimer = e.clock.NewTimer(stageDuration(sentAt, budget.FirstSemanticDeadline(sentAt)))
		defer func() {
			if semanticTimer != nil {
				semanticTimer.Stop()
			}
		}()
	}
	totalTimer := e.clock.NewTimer(stageDuration(sentAt, budget.TotalDeadline(sentAt)))
	defer totalTimer.Stop()

	// 读 goroutine：每读到一块就投递，读完/出错投递终止。
	type chunk struct {
		data []byte
		err  error
	}
	chunks := make(chan chunk)
	go func() {
		buf := make([]byte, readChunk)
		for {
			n, err := body.Read(buf)
			if n > 0 {
				cp := make([]byte, n)
				copy(cp, buf[:n])
				select {
				case chunks <- chunk{data: cp}:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				select {
				case chunks <- chunk{err: err}:
				case <-ctx.Done():
				}
				return
			}
		}
	}()

	feed := func(events []ProtocolEvent) (finalReached bool) {
		for _, event := range events {
			if timing.firstEventAtMS == 0 {
				timing.firstEventAtMS = e.clock.Now().UnixMilli()
			}
			_, final := classifier.Observe(event)
			if event.Semantic && timing.firstSemanticAtMS == 0 {
				timing.firstSemanticAtMS = e.clock.Now().UnixMilli()
			}
			if final {
				return true
			}
		}
		return false
	}

	for {
		select {
		case c := <-chunks:
			if c.err != nil {
				if c.err == io.EOF {
					events, finishErr := decoder.Finish()
					feed(events)
					result.readErr = finishErr
				} else {
					result.readErr = fmt.Errorf("%w: %v", ErrProbeTransportFailed, c.err)
				}
				return result
			}
			if timing.firstByteAtMS == 0 {
				timing.firstByteAtMS = e.clock.Now().UnixMilli()
			}
			result.bytesRead += int64(len(c.data))
			events, decErr := decoder.Feed(c.data)
			if final := feed(events); final {
				// probe 模式首语义后主动断流：预期取消 = 成功（§6.8 末句）。
				if req.Mode == ObserveProbe {
					result.expectedCancel = true
					result.cancelCause = ErrProbeCanceledAfterSemantic
					cancel()
				}
				return result
			}
			if decErr != nil {
				result.readErr = decErr
				return result
			}

		case <-timerC(semanticTimer):
			// 首语义超时：响应头已到但迟迟没有语义证据。
			result.readErr = ErrProbeSemanticTimeout
			cancel()
			return result

		case <-timerC(totalTimer):
			result.readErr = context.DeadlineExceeded
			cancel()
			return result

		case <-ctx.Done():
			// 外层取消（暂停/关闭/客户端断开）：交给 classifier 归为 ignored。
			result.cancelCause = ErrServicePaused
			return result
		}
	}
}

// finishTransportFailure 处理拿不到响应头的情形。
//
// GotConn 是已有的「连接已到手」观测（outbound.WithTrace）：未到达则 HTTP
// 请求字节不可能已写出。CostEvidenceFromExecution 以 SentAtMS>0 为发送门禁，
// 若此处保留 RoundTrip 前写入的 SentAt，会把 DNS/dial/connection refused
// 记成一次完整探测成本，违反 §8.6「实际发出去那份内容」。GotConn 已到则
// 可能已写过请求，按「可能已执行」记账，不清发送事实。
func (e *Executor) finishTransportFailure(ctx context.Context, req ExecutionRequest,
	prepared *preparedProbe, rtErr error, headerTimedOut bool, requestBytes, estInputTokens int64,
	timing sendTiming, sentAt time.Time) (ExecutionResult, error) {

	sent := true
	if timing.gotConnAtMS <= 0 {
		timing.sentAtMS = 0
		estInputTokens = 0
		requestBytes = 0
		sent = false
	}

	var cancelCause error
	if ctx.Err() != nil {
		// 外层 ctx 取消：暂停/关闭，不算上游的账。
		cancelCause = ErrServicePaused
	}
	var readErr error
	if headerTimedOut {
		readErr = ErrProbeSemanticTimeout
	}
	// status=0 的分类器：走 unreachable / ignored。
	classifier := NewResponseClassifier(req.Mode, req.Endpoint, 0, nil, sentAt)
	decision := classifier.Finish(readErr, cancelCause)
	if cancelCause == nil && readErr == nil {
		// 纯传输错误。
		decision.RedactedDetail = "transport_failure"
	}

	outcome := e.transportOutcome(ctx, req, decision, rtErr, headerTimedOut)
	outcome.Sent = sent
	exec := e.buildExecution(req, prepared.recipe, decision, timing, requestBytes, 0, estInputTokens, false,
		prepared.resolvedURLHash, prepared.requestURLHash)
	result := ExecutionResult{Decision: decision, Outcome: outcome, Execution: exec, Sent: sent}
	apply, recErr := e.recordExecution(ctx, req, &result.Execution)
	if recErr != nil {
		return result, recErr
	}
	result.Apply = apply
	return result, nil
}

// finishObserverIncomplete 处理「请求已发出、但我们自己没能观测完」：解码器
// 建不起来、或响应体的 Content-Encoding 无法解压（§P0-09 第 2、3 条）。
//
// 关键区别于 config_error：这次**已经发送**（SentAt 非零、Sent=true），
// 所以绝不能倒回 config_error。归为 ignored（不记上游的账）并置
// ObserverIncomplete，让 P0-10 的状态机据此跳过而不是判死一个可能健康的站。
func (e *Executor) finishObserverIncomplete(ctx context.Context, req ExecutionRequest,
	prepared *preparedProbe, statusCode int, reason model.ObserverIncompleteReason, detail string,
	requestBytes, estInputTokens int64, timing sendTiming, sentAt time.Time) (ExecutionResult, error) {

	timing.doneAtMS = e.clock.Now().UnixMilli()
	decision := Decision{
		Final:                true,
		Reachable:            statusCode > 0,
		Capability:           model.CapabilityUnknown,
		Scope:                model.ScopeNone,
		ErrorClass:           model.ErrorIgnored,
		StatusCode:           statusCode,
		CandidateDisposition: model.CandidateStop,
		RedactedDetail:       detail,
	}

	exec := e.buildExecution(req, prepared.recipe, decision, timing, requestBytes, 0, estInputTokens, false,
		prepared.resolvedURLHash, prepared.requestURLHash)
	exec.ObserverIncomplete = true
	exec.ObserverIncompleteReason = reason

	result := ExecutionResult{
		Decision:  decision,
		Outcome:   Outcome{Verdict: health.VerdictIgnore, Status: statusCode},
		Execution: exec,
		Sent:      true,
	}
	apply, recErr := e.recordExecution(ctx, req, &result.Execution)
	if recErr != nil {
		return result, recErr
	}
	result.Apply = apply
	return result, nil
}

// finishSuccessPath 处理拿到响应头后的收尾（含成功、假活、流内错误等）。
func (e *Executor) finishSuccessPath(ctx context.Context, req ExecutionRequest, prepared *preparedProbe,
	decision Decision, timing sendTiming, requestBytes, responseBytes, estInputTokens int64,
	expectedCancel bool, sentAt time.Time) (ExecutionResult, error) {

	outcome := e.decisionOutcome(req, decision)
	outcome.Sent = true
	outcome.Status = decision.StatusCode
	outcome.TTFT = ttftFrom(timing)

	exec := e.buildExecution(req, prepared.recipe, decision, timing, requestBytes, responseBytes, estInputTokens, expectedCancel,
		prepared.resolvedURLHash, prepared.requestURLHash)
	result := ExecutionResult{
		Decision:       decision,
		Outcome:        outcome,
		Execution:      exec,
		ExpectedCancel: expectedCancel,
		Sent:           true,
	}
	apply, recErr := e.recordExecution(ctx, req, &result.Execution)
	if recErr != nil {
		return result, recErr
	}
	result.Apply = apply
	return result, nil
}

// recordExecution 交给 recorder 落库。recorder 为 nil 时跳过（测试/装配前）。
func (e *Executor) recordExecution(ctx context.Context, req ExecutionRequest,
	exec *model.ProbeExecution) (model.ProbeApplyResult, error) {

	if e.recorder == nil {
		return model.ProbeApplyResult{}, nil
	}
	obs := &model.ProbeObservation{
		Execution:               *exec,
		ReachabilityExpectation: req.ReachabilityExpectation,
		CapabilityExpectation:   req.CapabilityExpectation,
		ReachabilityPolicy:      req.ReachabilityPolicy,
		CapabilityPolicy:        req.CapabilityPolicy,
	}
	// EvidenceHash 覆盖整份观测（execution + 期望 + 归约策略），必须在写库前
	// 由本包算好：store 只按它做幂等比对，不自己重算。算它要求 execution 的
	// 数值字段（token/字节/order）非负 —— 上面各 finish 路径都保证了这点。
	hash, err := revisioncodec.NewProbeEvidenceHash(*obs)
	if err != nil {
		return model.ProbeApplyResult{}, fmt.Errorf("计算 probe evidence hash: %w", err)
	}
	obs.Execution.EvidenceHash = hash
	exec.EvidenceHash = hash

	apply, err := e.recorder.Record(ctx, obs)
	if err != nil {
		return model.ProbeApplyResult{}, err
	}
	// 把 recorder 补齐的 disposition 回写到调用方能看到的那份 execution。
	exec.ReachabilityDisposition = apply.Reachability
	exec.CapabilityDisposition = apply.Capability
	return apply, nil
}

// buildExecution 把 Decision 与本次执行的元数据展平成一行 ProbeExecution。
//
// 只写结构化字段：secret/header/body 的明文从不进入 execution 行（§P0-09
// 第 9 条）。recipe identity/origin/version 从解析出的 recipe 取（§P0-09 第 1 条）——
// 缺了 origin 的话，写库时 CostEvidenceFromExecution 因 RecipeOrigin.Valid()
// 失败，整行落不下去，探活从此不再更新健康。
func (e *Executor) buildExecution(req ExecutionRequest, recipe ResolvedRecipe, decision Decision,
	timing sendTiming, requestBytes, responseBytes, estInputTokens int64,
	expectedCancel bool, resolvedURLHash, requestURLHash string) model.ProbeExecution {

	var routeID int64
	if req.Route != nil {
		routeID = req.Route.ID
	}
	var upstreamID, upstreamNetworkRev, upstreamCredentialRev int64
	if req.Upstream != nil {
		upstreamID = req.Upstream.ID
		upstreamNetworkRev = req.Upstream.NetworkRevision
		upstreamCredentialRev = req.Upstream.CredentialRevision
	}

	exec := model.ProbeExecution{
		ID:                         req.ExecutionID,
		Trigger:                    req.Trigger,
		UpstreamID:                 upstreamID,
		UpstreamNetworkRevision:    upstreamNetworkRev,
		UpstreamCredentialRevision: upstreamCredentialRev,
		RouteID:                    routeID,
		Endpoint:                   req.Endpoint,
		StatusCode:                 decision.StatusCode,
		ErrorClass:                 decision.ErrorClass,
		Capability:                 decision.Capability,
		Scope:                      decision.Scope,
		Reachable:                  decision.Reachable,
		Final:                      decision.Final,
		Success:                    decision.Success,
		SemanticSeen:               decision.SemanticSeen,
		NormalEndSeen:              decision.NormalEndSeen,
		Partial:                    decision.Partial,
		CandidateDisposition:       decision.CandidateDisposition,
		RedactedDetail:             decision.RedactedDetail,
		ResolvedURLHash:            resolvedURLHash,
		RequestURLHash:             requestURLHash,
		SentAtMS:                   timing.sentAtMS,
		TLSHandshakeStartAtMS:      timing.tlsHandshakeStartAtMS,
		TLSHandshakeDoneAtMS:       timing.tlsHandshakeDoneAtMS,
		GotConnAtMS:                timing.gotConnAtMS,
		ResponseHeaderAtMS:         timing.responseHeaderAtMS,
		FirstByteAtMS:              timing.firstByteAtMS,
		FirstEventAtMS:             timing.firstEventAtMS,
		FirstSemanticAtMS:          timing.firstSemanticAtMS,
		DoneAtMS:                   timing.doneAtMS,
		RequestBytes:               requestBytes,
		ResponseBytes:              responseBytes,
		EstimatedInputTokens:       estInputTokens,
		ObservedInputTokens:        decision.ObservedInputTokens,
		ObservedOutputTokens:       decision.ObservedOutputTokens,
		RetryAfterUntilMS:          decision.RetryAfterUntilMS,
		ObservationOrder:           req.ObservationOrder,
		ExpectedCancel:             expectedCancel,
		CalibrationRunID:           req.CalibrationRunID,
		CandidateOrdinal:           req.CandidateOrdinal,
		// 两个 disposition 由 recorder 补齐（本版恒为 not_applicable）。
	}

	applyRecipeIdentity(&exec, recipe, req.Trigger)
	// 期望在场时用它覆盖 selector/fingerprint/token/revision（§P0-09 第 11、
	// 14、17 条）。P0-09 的 Scheduler 不传期望（ExecutionOnlyRecorder 的两个
	// disposition 恒为 not_applicable），所以这段现在是空跑；留着是为了 P0-10
	// 接入期望后，落库的证据与期望在同一口径上对齐，而不必改这里。
	applyExpectationColumns(&exec, req.ReachabilityExpectation, req.CapabilityExpectation)
	stampCalibrationDiagnostics(&exec, req)
	return exec
}

// stampCalibrationDiagnostics 把校准候选测试时的配置口径冻进 execution。
//
// 不经 CapabilityExpectation：校准成功前 Auth 尚未 commit，ResultRecorder 若按
// 完整语义期望落能力会把中间态写进 Registry。commit 侧只比对这里冻住的字段。
func stampCalibrationDiagnostics(exec *model.ProbeExecution, req ExecutionRequest) {
	if req.CalibrationRunID == "" {
		return
	}
	if req.DiagnosticEndpoint != nil {
		exec.EndpointID = req.DiagnosticEndpoint.ID
		exec.EndpointRevision = req.DiagnosticEndpoint.Revision
		exec.AuthProfileRevision = req.DiagnosticEndpoint.AuthProfile.Revision
	}
	if req.Route != nil {
		exec.RouteCapabilityRevision = req.Route.CapabilityRevision
	}
	if req.ModelName != nil {
		exec.ModelCapabilityRevision = req.ModelName.CapabilityRevision
	}
	if req.ProbeSettingsFingerprint != "" {
		exec.ProbeSettingsFingerprint = req.ProbeSettingsFingerprint
		exec.CapabilityPolicySelector = req.CalibrationPolicySelector
	}
	if req.ProbeSecretRevisionsHash != "" {
		exec.ProbeSecretRevisionsHash = req.ProbeSecretRevisionsHash
	}
}

// applyRecipeIdentity 把解析出的 recipe 身份/来源/版本展平进 execution。
//
// recipe 为零值（解析本身失败的 config_error）时兜一份合法的 embedded
// identity：RecipeOrigin 必须 Valid()，否则成本证据建不起来、整行写库失败。
// 未发送的 config_error 成本贡献为 0（SentAt=0），这份兜底不会污染计费。
func applyRecipeIdentity(exec *model.ProbeExecution, recipe ResolvedRecipe, trigger model.ProbeTrigger) {
	identity := recipe.Identity
	if !identity.Origin.Valid() {
		// 解析未产出合法 identity：给一份 embedded 兜底，好让写库通过。
		identity = model.RecipeIdentity{
			Storage: model.RecipeStorageEmbedded, Origin: model.RecipeBasic,
			TemplateID: "unresolved:" + string(exec.Endpoint), Revision: 1,
		}
	}
	exec.RecipeStorage = identity.Storage
	exec.RecipeOrigin = identity.Origin
	exec.RecipeVersionID = identity.DBVersionID
	exec.ClientProfileID = identity.ClientProfileID
	exec.TemplateID = identity.TemplateID
	exec.RecipeIdentityRevision = identity.Revision

	facts := recipe.Facts
	if facts.Use == "" {
		// 周期 L1/L2 就是 resolved 绑定（§P0-09 第 1 条）。
		facts.Use = model.BindingResolved
	}
	exec.RecipeBindingUse = facts.Use
	exec.RecipeBindingFacts = facts

	// RecipeID / RecipeBindingRevision 取选中层的那一份；被遮蔽层留零值。
	switch facts.ResolvedLayer {
	case model.ResolvedRoute:
		exec.RecipeID = facts.RouteRecipeID
		exec.RecipeBindingRevision = facts.RouteBindingRevision
	case model.ResolvedUpstream:
		exec.RecipeID = facts.UpstreamRecipeID
		exec.RecipeBindingRevision = facts.UpstreamBindingRevision
	}
}

// applyExpectationColumns 在期望在场时把它的 selector/fingerprint/token/revision
// 覆盖进 execution（§P0-09 第 11、14、17 条）。期望是「这次探活按哪套配置去比对」
// 的权威口径，落库的证据必须与它一致，否则 P0-10 的 reducer 会把一致的观测判成
// config_stale。两个期望都为 nil（P0-09 的常态）时本函数不动任何字段。
func applyExpectationColumns(exec *model.ProbeExecution,
	reach *model.ReachabilityExpectation, capExp *model.SemanticExpectation) {

	if reach != nil {
		exec.ReachabilityPolicySelector = reach.PolicySelector
		exec.ReachabilitySettingsFingerprint = reach.Revision.SettingsFingerprint
		exec.ReachabilityToken = reach.ObservationToken
		exec.UpstreamNetworkRevision = reach.Revision.NetworkRevision
	}
	if capExp != nil {
		exec.CapabilityPolicySelector = capExp.PolicySelector
		exec.CapabilityToken = capExp.ObservationToken
		exec.ProbeSettingsFingerprint = capExp.Revision.ProbeSettingsFingerprint
		exec.UpstreamNetworkRevision = capExp.Revision.UpstreamNetwork
		exec.UpstreamCredentialRevision = capExp.Revision.UpstreamCredential
		exec.EndpointID = capExp.Revision.EndpointID
		exec.EndpointRevision = capExp.Revision.EndpointRevision
		exec.ModelCapabilityRevision = capExp.Revision.ModelCapability
		exec.RouteCapabilityRevision = capExp.Revision.RouteCapability
		exec.AuthProfileRevision = capExp.Revision.AuthProfile
		exec.RecipeBindingRevision = capExp.Revision.RecipeBindingRevision
		exec.RequestTransformBindingRevision = capExp.Revision.RequestTransform
		// 期望自带的 BindingFacts 是权威口径（含 explicit_test 等 Use）。
		exec.RecipeBindingUse = capExp.BindingFacts.Use
		exec.RecipeBindingFacts = capExp.BindingFacts
	}
}

// decisionOutcome 把 Decision 映射成 P0-10 之前 health.Tracker 消费的 Outcome。
//
// 这层映射是临时的：Decision 才是权威结论，但现有健康状态机只认三态 Verdict。
// L1（models 端点）对 404/405 判通 —— 站不提供 /v1/models 不等于站挂了（§4.1）。
func (e *Executor) decisionOutcome(req ExecutionRequest, decision Decision) Outcome {
	// L1（models 端点）是**可达性**探测，判据是状态码而不是能力：拿到任何
	// 非硬失败的响应就算通。这与新 Classifier 的能力判据（必须是可识别的模型
	// 列表）刻意分开 —— 否则一个只回 200 空体的 /v1/models 会让整站误判死。
	if req.Endpoint == model.EndpointModels {
		return e.l1Outcome(decision)
	}
	switch decision.ErrorClass {
	case model.ErrorIgnored:
		return Outcome{Verdict: health.VerdictIgnore, Status: decision.StatusCode}
	case model.ErrorNone:
		return Outcome{Verdict: health.VerdictOK, Status: decision.StatusCode}
	case model.ErrorRateLimited:
		return Outcome{
			Verdict:    health.VerdictRateLimited,
			Status:     decision.StatusCode,
			RetryAfter: retryAfterDuration(decision, e.clock.Now()),
			Err:        detailErr(decision),
		}
	case model.ErrorAuthRejected, model.ErrorModelNotFound, model.ErrorShapeRejected, model.ErrorConfig:
		return Outcome{Verdict: health.VerdictFatal, Status: decision.StatusCode, Err: detailErr(decision)}
	case model.ErrorUnsupported:
		// L1/models 的 404/405 判通；其余端点的 unsupported 归 fatal（配置层面）。
		if req.Endpoint == model.EndpointModels {
			return Outcome{Verdict: health.VerdictOK, Status: decision.StatusCode}
		}
		return Outcome{Verdict: health.VerdictFatal, Status: decision.StatusCode, Err: detailErr(decision)}
	default:
		// unreachable / transient / fake_alive / partial 都归不可用。
		return Outcome{Verdict: health.VerdictUnavailable, Status: decision.StatusCode, Err: detailErr(decision)}
	}
}

// l1Outcome 按状态码把 L1 的 Decision 映射成可达性 Verdict（§4.1）。
//
// 404/405 判通：站不提供 /v1/models 不等于站挂了，而 L1 是 Upstream 粒度的，
// 一次误判会连坐它下面所有 Route。
func (e *Executor) l1Outcome(decision Decision) Outcome {
	if decision.ErrorClass == model.ErrorIgnored {
		return Outcome{Verdict: health.VerdictIgnore, Status: decision.StatusCode}
	}
	switch {
	case decision.StatusCode == 0:
		return Outcome{Verdict: health.VerdictUnavailable, Err: detailErr(decision)}
	case decision.StatusCode == http.StatusTooManyRequests:
		return Outcome{Verdict: health.VerdictRateLimited, Status: decision.StatusCode,
			RetryAfter: retryAfterDuration(decision, e.clock.Now())}
	case decision.StatusCode == http.StatusUnauthorized || decision.StatusCode == http.StatusForbidden:
		return Outcome{Verdict: health.VerdictFatal, Status: decision.StatusCode, Err: detailErr(decision)}
	case decision.StatusCode >= 500:
		return Outcome{Verdict: health.VerdictUnavailable, Status: decision.StatusCode, Err: detailErr(decision)}
	case decision.StatusCode == http.StatusNotFound || decision.StatusCode == http.StatusMethodNotAllowed:
		return Outcome{Verdict: health.VerdictOK, Status: decision.StatusCode}
	case decision.StatusCode >= 200 && decision.StatusCode < 300:
		return Outcome{Verdict: health.VerdictOK, Status: decision.StatusCode}
	default:
		return Outcome{Verdict: health.VerdictUnavailable, Status: decision.StatusCode, Err: detailErr(decision)}
	}
}

// transportOutcome 给「拿不到响应头」的情形定 Verdict。
//
// Outcome.Err 只带 Decision 的脱敏详情，绝不包装 RoundTrip 原文：
// net/http 的 *url.Error 会把完整请求 URL（含 fixed_query 里的 Secret）
// 拼进 Error()，而 Scheduler 会把 out.Err 打进「上游 L1 失败」等日志。
func (e *Executor) transportOutcome(ctx context.Context, req ExecutionRequest, decision Decision,
	_ error, headerTimedOut bool) Outcome {

	if decision.ErrorClass == model.ErrorIgnored || ctx.Err() != nil {
		return Outcome{Verdict: health.VerdictIgnore}
	}
	if headerTimedOut {
		return Outcome{Verdict: health.VerdictUnavailable,
			Err: fmt.Errorf("%w: 响应头未按时返回", ErrProbeSemanticTimeout)}
	}
	return Outcome{Verdict: health.VerdictUnavailable, Err: detailErr(decision)}
}

// ── 小工具 ────────────────────────────────────────────────

// timerC 安全地取 Timer 的通道；nil timer 返回一个永不触发的通道。
func timerC(t Timer) <-chan time.Time {
	if t == nil {
		return nil
	}
	return t.C()
}

// stageDuration 把绝对截止时刻换算成从现在起的时长，下限为 0。
func stageDuration(sentAt time.Time, deadline time.Time) time.Duration {
	d := deadline.Sub(sentAt)
	if d < 0 {
		return 0
	}
	return d
}

// ttftFrom 取首 Token 时间：优先首语义，退到首事件、首字节。
func ttftFrom(timing sendTiming) time.Duration {
	var at int64
	switch {
	case timing.firstSemanticAtMS > 0:
		at = timing.firstSemanticAtMS
	case timing.firstEventAtMS > 0:
		at = timing.firstEventAtMS
	case timing.firstByteAtMS > 0:
		at = timing.firstByteAtMS
	default:
		return 0
	}
	if timing.sentAtMS <= 0 || at < timing.sentAtMS {
		return 0
	}
	return time.Duration(at-timing.sentAtMS) * time.Millisecond
}

// retryAfterDuration 把 Decision 里的绝对 Retry-After 时刻换算成时长。
func retryAfterDuration(decision Decision, now time.Time) time.Duration {
	if decision.RetryAfterUntilMS <= 0 {
		return 0
	}
	d := time.UnixMilli(decision.RetryAfterUntilMS).Sub(now)
	if d < 0 {
		return 0
	}
	return d
}

// detailErr 从脱敏详情造一个 error，供健康视图展示。绝不含明文。
func detailErr(decision Decision) error {
	if decision.RedactedDetail == "" {
		return errors.New(string(decision.ErrorClass))
	}
	return errors.New(decision.RedactedDetail)
}
