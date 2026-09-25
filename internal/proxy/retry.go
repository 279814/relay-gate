package proxy

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/sample"
	"github.com/279814/relay-gate/internal/transform"
)

// 请求内重试（§3.5）。
//
// ── 能重试的前提是「还没写出任何字节」──
//
// 一旦向客户端写出第一个字节，状态码与响应头就已经定死，流也无法回滚 ——
// 客户端已经在解析 SSE 了。所以重试的全部空间都在 Send 与 Commit 之间，
// forward.go 把这两步拆开正是为此。这个文件做的事就是在那个窗口里判断
// 「这次响应值不值得丢掉、换个站重来」。
//
// ── 为什么每次尝试都必须从**入站原文**重建全部出站产物 ──
//
// 出站请求由四样东西拼成：改写后的 body（model 映射）、注入了上游 key 的
// 请求头、拼好的 URL、以及该站的 Transport（可能带自己的 proxy）。
// 这四样**全部**是 per-Upstream 的。复用上一次尝试的产物就是把 A 站的 key
// 发给 B 站（必 401，然后 B 站被判死 —— 一个好站因为我们的 bug 被踢出池子），
// 或者把 A 站的 upstream_model 二次套用到 B 站的映射上。
//
// dispatch 的入参只有 pre.body（入站原文）与 cand，就是为了让这件事在
// 结构上做不到，而不是靠记得。

// LogSink 接收请求日志。由 sample.LogRecorder 实现，可为 nil（关闭日志）。
//
// Record 必须是**非阻塞**的：它在转发路径的收尾处被调用，阻塞就等于让
// 「记日志」拖慢真实请求（§3.6.3a 的主次关系对日志同样成立）。
type LogSink interface {
	Record(*model.RequestLog)
}

// forwardOutcome 是转发（含重试）结束后，收尾阶段需要的全部信息。
//
// 它描述的是**最终那次**尝试 —— 也就是客户端实际拿到的那个响应。
// 被丢弃的尝试在循环里就已经回写过健康状态并记过日志，不留在这里：
// 样本表的一行代表「客户端的一次请求」，把 N 次尝试记成 N 行会让
// 样本浏览器显示成 N 个客户端请求，那比不记更误导。
// 逐次尝试的完整留档归 request_log。
type forwardOutcome struct {
	cand      *router.Candidate
	outBody   []byte
	outHeader http.Header
	outURL    string
	respTee   *sample.HeadTail
	secTee    *sample.HeadTail // passive security scan copy (§14.2); independent of sample switch
	res       *Result
	keys      []string
	// attempts 是实际发出的尝试次数。1 = 没有重试。
	attempts int
	// halfOpen 表示最终这次尝试是 §4.4c 半开试探。只用于网关自生成
	// 错误响应上的 X-Relay-Half-Open；成功的上游响应不得带该头（§2.3）。
	halfOpen bool
	// reqID 把这次客户端请求的样本与它的多行日志串起来。
	reqID string
	// logs 是**全部**尝试的日志（含被丢弃的），等 attempts 定下来之后
	// 才由调用方统一投递 —— 见 forwardWithRetry 里的说明。
	logs []*model.RequestLog
}

// liveAttempt 是一次已发出、**尚未提交**的尝试，连同它的出站产物。
type liveAttempt struct {
	cand   *router.Candidate
	at     *Attempt
	tee    *sample.HeadTail
	secTee *sample.HeadTail
	keys   []string
	body   []byte
	header http.Header
	url    string
	instr  health.AttemptInstrumentation
	// Published transform selected at dispatch (immutable for this Attempt).
	compiled   *transform.Compiled
	verID      int64
	endpointID int64
}

// retryPlan 是重试循环的不变量：预算、次数上限、已试过哪些 Route。
type retryPlan struct {
	maxAttempts int
	// deadline 是**整个客户端请求**的总时限，由所有尝试共享（§4.2）。
	deadline time.Time
	// connectCost 是「还值不值得再试一次」的门槛，取连接建立超时：
	// 连一次 TCP + TLS 握手都容不下的剩余时间，拿去开一个必然超时的
	// 请求毫无意义，只是让客户端多等几秒再看到同一个错误。
	connectCost time.Duration
	tried       map[int64]bool
	// maxLocalSkips bounds route-local failures (§6.5): Transform / binding
	// errors that never hit the wire. They do not consume maxAttempts.
	maxLocalSkips int
}

// dispatchStatus distinguishes fatal client errors from route-local skips (§6.5).
type dispatchStatus int

const (
	dispatchSent dispatchStatus = iota
	dispatchFatal
	dispatchRouteLocal // nothing written; try next Route without a network Attempt
)

// forwardWithRetry 完成选路 + 转发，失败时按 §3.5 换站重试。
//
// 返回 ok=false 表示错误响应已经写好了（选路失败或配置错误），调用方直接返回。
// 返回的 outcome 里那个 Candidate 的并发额度**已经归还** —— 本函数全程持有
// 额度的所有权，调用方不需要（也不应该）再 Release 一次。
func (h *Handler) forwardWithRetry(w http.ResponseWriter, r *http.Request,
	proto model.Protocol, pre *preambleResult, recvAt time.Time) (*forwardOutcome, bool) {

	settings := pre.settings
	plan := &retryPlan{
		maxAttempts:   settings.RetryMaxAttempts,
		deadline:      time.Now().Add(time.Duration(settings.RealTotalSec) * time.Second),
		connectCost:   time.Duration(settings.RealConnectSec) * time.Second,
		tried:         map[int64]bool{},
		maxLocalSkips: countCandidateRoutes(pre.snapshot, pre.inModel, proto),
	}
	if plan.maxAttempts < 1 {
		// Validate 已保证 ≥ 1。这里兜的是「旧库升级后该字段是零值」——
		// 那种情况下 0 不是「关闭重试」而是「一次都不发」，等于关闭转发。
		plan.maxAttempts = 1
	}

	// 半开只在第一次尝试时允许（§4.4c）。它的语义是「全都 dead 了，放一个
	// 真实请求去试探」；而重试链走到这里说明已经试过一个活站并失败了，那时
	// 再去挨个试 dead 站，花的是客户端剩下的预算，撞上的是已知挂掉的站。
	cand, halfOpen, err := h.selectFor(pre, proto, nil, true)
	if err != nil {
		h.writeSelectError(w, err, proto, pre.inModel)
		return nil, false
	}
	// 半开之后不会有重试：半开的前提是全部 Route 都 dead，而重试用的
	// SelectExcluding 只挑非 dead 的，必然选不到。也就是说 §4.4c 的
	// 「放行一次」是结构上保证的，不需要额外的开关去限制它。
	//
	// X-Relay-Half-Open / X-Relay-Attempts 不得写在这里：Commit 会把上游
	// 响应原样交给客户端，§2.3 禁止成功（及任何透传）上游响应新增网关
	// 诊断头。半开/重试信息进 request_log；诊断头只在 writeForwardError
	// 等网关自生成错误响应上补。

	// held tracks the Candidate whose max_concurrency / RecoveryGate slot we
	// own. §9.4 requires release on panic: net/http recovers the handler so the
	// process stays up, but without defer the slot would stick for the life of
	// the process. Do not recover here — a panic must not start another
	// upstream attempt. Release is idempotent (sync.Once); normal paths clear
	// held after an explicit Release so the defer is a no-op.
	held := cand
	defer func() {
		if held != nil {
			held.Release()
		}
	}()

	// RecoveryGate/TryAcquire 之后、RoundTrip 之前再读一次：停用可能已经
	// 落库并发布。halfOpen 选路用的是 preamble 快照；已武装的试探必须自己
	// 停在出网前，且不得另起一次探活。
	if halfOpen && !h.halfOpenStillEnabled(cand.Route.ID, cand.Upstream.ID) {
		h.log.Info("Route/Upstream 已停用，跳过已武装的半开试探",
			"upstream", cand.Upstream.Name, "route", cand.Route.ID)
		held.Release()
		held = nil
		h.writeSelectError(w, router.ErrNoRouteAvailable, proto, pre.inModel)
		return nil, false
	}

	// reqID 在这里生成而不是在写日志时：同一次客户端请求的所有尝试
	// （以及它那条样本）都要用同一个值，而日志是逐次写的。
	reqID := sample.NewReqID()
	var logs []*model.RequestLog
	localSkips := 0
	attempt := 0

	for {
		plan.tried[cand.Route.ID] = true

		la, status := h.dispatch(w, r, proto, pre, cand, time.Until(plan.deadline))
		if status == dispatchFatal {
			cand.Release()
			held = nil
			return nil, false
		}
		if status == dispatchRouteLocal {
			// §6.5 / §15.7: Transform fail_closed is route-local — no upstream
			// send, no maxAttempts burn; skip to the next Route.
			cand.Release()
			held = nil
			localSkips++
			h.log.Info("route-local 请求转换失败，跳过本 Route",
				"route", cand.Route.ID, "local_skips", localSkips,
				"max_local_skips", plan.maxLocalSkips)
			if localSkips >= plan.maxLocalSkips {
				writeAPIError(w, http.StatusBadGateway, proto, "api_error", "请求转换失败（fail_closed）")
				return nil, false
			}
			next, _, selErr := h.selectFor(pre, proto, plan.tried, false)
			if selErr != nil || next == nil {
				writeAPIError(w, http.StatusBadGateway, proto, "api_error", "请求转换失败（fail_closed）")
				return nil, false
			}
			cand = next
			held = cand
			continue
		}
		attempt++

		next := h.nextCandidate(r, pre, proto, plan, la, attempt)
		if next == nil {
			oc := &forwardOutcome{
				cand: la.cand, outBody: la.body, outHeader: la.header,
				outURL: la.url, respTee: la.tee, secTee: la.secTee, keys: la.keys,
				res: la.at.Result(), attempts: attempt, halfOpen: halfOpen,
				reqID: reqID,
			}
			if la.at.CanCommit() {
				oc.res = h.commitLive(w, la)
				// fail_closed response transform before any client byte.
				if oc.res != nil && oc.res.Err != nil && !oc.res.HeadersSent &&
					la.compiled != nil {
					writeAPIError(w, http.StatusBadGateway, proto, "api_error", "响应转换失败（fail_closed）")
					finishObserver(la, health.AttemptFinish{})
					la.cand.Release()
					held = nil
					return nil, false
				}
			} else {
				la.at.Discard()
			}
			finishObserver(la, health.AttemptFinish{ClientCommitted: oc.res != nil && oc.res.BytesWritten > 0})
			la.cand.Release()
			held = nil

			// 最后一行日志要在 Commit **之后**记：BytesWritten 与 DoneAt
			// 都是流式写完才有的，提前记会把每个成功响应的字节数记成 0。
			oc.logs = append(logs, h.attemptLog(la, pre, proto, reqID,
				attempt, halfOpen && attempt == 1, false, oc.res, recvAt))

			// attempts 到这一刻才知道。逐行写的话前面几行只能填一个
			// 猜的值 —— 而列表页正是靠它显示「这次试了 3 个站」。
			for _, l := range oc.logs {
				l.Attempts = attempt
			}
			return oc, true
		}

		// 换站。这次尝试的健康结论**必须**在这里回写：它是一次真实请求的
		// 失败证据，而 §3.5 把「真实请求失败立即回写 + 触发即时探活」列为
		// 最快的故障发现路径 —— 比 dead 状态 20 秒的探活周期快得多。
		// 丢弃掉就不回写的话，一个刚挂掉的站会因为「重试成功了所以没人报告」
		// 而一直显示 alive，直到下一个定时探活撞上去。
		//
		// TriggerL2 由 Reporter.ReportResult 在判定非 OK 时自己发（见
		// probe/reporter.go），这里不重复触发。
		//
		// 顺序：**先 Discard 再回写**。Discard 才会把错误响应体填进
		// Result.ErrBody（那段字节是排水时顺手留下的），反过来的话回写拿到
		// 的永远是空 body —— 于是 ClassifyHTTP 只能看状态码，
		// 「500 + body 里写着 rate limit」会被判成故障而累计判死，
		// 本该只是冷却 60 秒。
		la.at.Discard()
		finishObserver(la, health.AttemptFinish{})
		h.logRetry(la, pre.inModel, attempt, plan.maxAttempts)
		logs = append(logs, h.attemptLog(la, pre, proto, reqID,
			attempt, halfOpen && attempt == 1, true, la.at.Result(), recvAt))
		if h.reporter != nil {
			ep, _ := proto.Endpoint()
			h.reporter.ReportResult(la.cand.Route.ID, la.cand.HealthGeneration, viewOf(la.at.Result(), la.keys, ep))
		}
		la.cand.Release()
		cand = next
		held = cand
	}
}

// selectFor 选一个候选。allowHalfOpen 仅第一次尝试为 true。
//
// recovering 态的 Route 须额外占 RecoveryGate（§9.4 / Lazy §8.11）：拿不到则
// 跳过该 Route 继续选，不排队。
//
// 刻意不写错误响应：重试路径上选不到站**不是**错误 —— 那时手上还捏着
// 上一次尝试的响应，正确动作是把它交给客户端，而不是回一个 503。
func (h *Handler) selectFor(pre *preambleResult, proto model.Protocol,
	exclude map[int64]bool, allowHalfOpen bool) (*router.Candidate, bool, error) {

	if exclude == nil {
		exclude = map[int64]bool{}
	}
	ep, _ := proto.Endpoint()
	for {
		cand, err := router.SelectExcluding(pre.snapshot, h.health, pre.inModel, proto, exclude)
		if err == nil {
			if h.capabilityExcludes(cand.Route.ID, ep) {
				exclude[cand.Route.ID] = true
				cand.Release()
				continue
			}
			// 脏行/历史短 api_key：SelectExcluding 已按短钥剔除并阻断前缀/兜底回落。
			// 若仍选出，fail closed，不得再 exclude 后跨 ModelName 重选。
			if model.APIKeyTooShortForOutbound(cand.Upstream.APIKey) {
				h.log.Warn("上游 api_key 短于脱敏下限，拒绝出站",
					"upstream", cand.Upstream.ID, "route", cand.Route.ID,
					"min_len", model.MinRedactableKeyLen, "got_len", len(cand.Upstream.APIKey))
				cand.Release()
				return nil, false, fmt.Errorf("%w: 上游 api_key 短于脱敏下限", router.ErrNoRouteAvailable)
			}
			wrapped, ok := h.wrapRecoveryIfNeeded(cand)
			if ok {
				return wrapped, false, nil
			}
			exclude[cand.Route.ID] = true
			cand.Release()
			continue
		}
		if !allowHalfOpen {
			return nil, false, err
		}
		if c := h.halfOpen(pre.snapshot, pre.inModel, proto, pre.settings, err); c != nil {
			return c, true, nil
		}
		return nil, false, err
	}
}

// wrapRecoveryIfNeeded takes RecoveryGate when the Route is recovering.
// ok=false means the gate is busy; caller must Release cand and try another Route.
func (h *Handler) wrapRecoveryIfNeeded(cand *router.Candidate) (*router.Candidate, bool) {
	if cand == nil || cand.Route == nil {
		return cand, true
	}
	if h.health == nil || h.health.State(cand.Route.ID) != model.StateRecovering {
		return cand, true
	}
	if h.recovery == nil {
		return cand, true
	}
	relGate, ok := h.recovery.TryAcquire(cand.Route.ID)
	if !ok {
		return nil, false
	}
	rt, up, mn := cand.Route, cand.Upstream, cand.ModelName
	prevRelease := cand.Release
	return router.NewCandidate(rt, up, mn, func() {
		prevRelease()
		relGate()
	}, cand.HealthGeneration), true
}

// dispatch 重建全部出站产物并发出请求。
//
// 只收入站原文与候选 —— 见文件头「为什么每次尝试都必须重建」。
// budget 是本次请求剩余的总时长预算。
//
// dispatchFatal：错误响应已写好。这类失败是 request-global（非法 body、
// 协议/全局配置），换站无意义。
// dispatchRouteLocal：尚未写客户端、尚未发上游（§6.5 Transform fail_closed）；
// 调用方应跳过本 Route 并选下一个，不消耗 retry_max_attempts。
// dispatchSent：已发出上游请求，la 非空。
func (h *Handler) dispatch(w http.ResponseWriter, r *http.Request,
	proto model.Protocol, pre *preambleResult, cand *router.Candidate,
	budget time.Duration) (*liveAttempt, dispatchStatus) {

	settings := pre.settings

	outBody, err := ReplaceModel(pre.body, cand.Route.UpstreamModel)
	if err != nil {
		h.log.Error("替换 model 失败", "err", err, "route", cand.Route.ID)
		writeAPIError(w, http.StatusInternalServerError, proto, "api_error",
			fmt.Sprintf("改写请求失败: %v", err))
		return nil, dispatchFatal
	}

	// 出站 URL 只有一个来源（§7.1）。endpoint 由入站协议决定 ——
	// 这三个透传端点与协议是一一对应的。
	kind, ok := proto.Endpoint()
	if !ok {
		h.log.Error("协议没有对应的 Endpoint", "proto", proto, "route", cand.Route.ID)
		writeAPIError(w, http.StatusInternalServerError, proto, "api_error", "配置错误")
		return nil, dispatchFatal
	}
	target, err := h.resolveTarget(r, cand, kind)
	if err != nil {
		h.log.Error("解析出站目标失败", "err", err, "upstream", cand.Upstream.ID)
		writeAPIError(w, http.StatusInternalServerError, proto, "api_error", "配置错误")
		return nil, dispatchFatal
	}

	// 认证也只有一个来源（§7.2）。profile 跟着 target 一起来，两者出自
	// 同一条 Endpoint 记录的同一个 revision —— 分两次读会让请求「用新 URL
	// 配旧认证」，症状是偶发 401。
	outHeader, err := h.outboundHeaders(r, cand, target, proto)
	if err != nil {
		h.log.Error("改写出站认证失败", "err", err, "upstream", cand.Upstream.ID)
		writeAPIError(w, http.StatusInternalServerError, proto, "api_error", "配置错误")
		return nil, dispatchFatal
	}

	// Published binding only; unbound → passthrough (§15.1).
	var compiled *transform.Compiled
	var verID int64
	redactKeys := h.credentialsOf(r, cand)
	if h.transforms != nil && target.EndpointID != 0 {
		var terr error
		compiled, verID, terr = h.transforms.PublishedCompiled(cand.Route.ID, target.EndpointID)
		if terr != nil {
			h.log.Error("加载 transform 失败", "err", terr, "route", cand.Route.ID)
			return nil, dispatchRouteLocal
		}
		if compiled != nil {
			beforeBody := outBody
			// Resolve upstream_api_key for secret_ref / {{SECRET:…}} on the
			// live path; rendered plaintext is tainted for sample redaction.
			var secrets transform.SecretMap
			if key := cand.Upstream.APIKey; key != "" && !model.APIKeyTooShortForOutbound(key) {
				secrets = transform.SecretMap{"upstream_api_key": []byte(key)}
			}
			tr := compiled.ApplyRequestSecrets(
				transform.RequestInput{Header: outHeader, Body: outBody}, secrets)
			if tr.Err != nil && tr.PolicyUsed == transform.FailClosed {
				h.transforms.RecordExecution(transform.ExecutionRecord{
					RouteID: cand.Route.ID, EndpointID: target.EndpointID, VersionID: verID,
					Mode: "published", Phase: "request", OK: false, Error: tr.Err.Error(),
					FailPolicyUsed: tr.PolicyUsed, InputHash: transform.HashBytes(beforeBody),
				})
				return nil, dispatchRouteLocal
			}
			outHeader, outBody = tr.Header, tr.Body
			if tr.Changed || tr.Err != nil {
				errText := ""
				if tr.Err != nil {
					errText = tr.Err.Error()
				}
				h.transforms.RecordExecution(transform.ExecutionRecord{
					RouteID: cand.Route.ID, EndpointID: target.EndpointID, VersionID: verID,
					Mode: "published", Phase: "request", OK: tr.Err == nil,
					HitRules: tr.HitRules, FailPolicyUsed: tr.PolicyUsed,
					InputHash: transform.HashBytes(beforeBody), OutputHash: transform.HashBytes(outBody),
					Error: errText,
				})
			}
			// Post-transform sample redaction must include tainted secrets
			// (§5.4 / §16.3): body PrepareBody already scans credentialsOf,
			// but custom headers and any secret distinct from APIKey need
			// the taint set merged in before store/encrypt.
			if tr.Taint != nil {
				redactKeys = append(redactKeys, tr.Taint.Secrets()...)
			}
		}
	}

	realBudget := outbound.RealBudget(settings).CapTotal(budget)
	tr, err := h.TransportFor(cand.Upstream, realBudget)
	if err != nil {
		h.log.Error("取连接池失败", "err", err, "upstream", cand.Upstream.ID)
		writeAPIError(w, http.StatusInternalServerError, proto, "api_error", "配置错误")
		return nil, dispatchFatal
	}

	to := TimeoutsFrom(realBudget)
	if settings.RetryPolicy.Normalize() == model.RetryPolicyAggressive {
		to = to.WithAggressivePeek(time.Duration(settings.RealFirstByteSec) * time.Second)
	}
	fwd := &Forwarder{Transport: tr, Timeouts: to,
		RequestHost: target.RequestHost, RedactSecrets: redactKeys}

	// 每次尝试各用一个新 tee。共用一个的话，被丢弃的那次尝试的响应字节会
	// 混进最终样本的 resp_body —— 样本就变成了两个站的响应拼起来的东西。
	var tee *sample.HeadTail
	if h.samples != nil && settings.SampleEnabled {
		tee = sample.NewHeadTail(settings.SampleRespHeadBytes, settings.SampleRespTailBytes)
		// §5.4：完整模式下若本条响应会撑破剩余磁盘配额，采集当场切头尾，
		// 不能等 PruneSamples —— 全量已进 RAM 再删救不了峰值。
		if settings.SampleDiskQuotaBytes > 0 {
			remaining := settings.SampleDiskQuotaBytes
			if h.sampleDisk != nil {
				if used, err := h.sampleDisk.SampleDiskBytes(); err == nil {
					remaining -= used
				}
			}
			// 本条 in/out 与 resp 共享配额；先扣掉已知的请求体，剩余才给响应。
			remaining -= int64(len(pre.body) + len(outBody))
			tee.LimitToRemaining(remaining,
				settings.SampleRespHeadBytes, settings.SampleRespTailBytes)
		}
	}
	// 被动扫描副本与样本开关无关（§14.3：样本关闭时仍可扫描）。
	var secTee *sample.HeadTail
	if h.security != nil {
		secTee = sample.NewHeadTail(256<<10, 256<<10)
	}
	switch {
	case tee != nil && secTee != nil:
		fwd.RespTee = io.MultiWriter(tee, secTee)
	case tee != nil:
		fwd.RespTee = tee
	case secTee != nil:
		fwd.RespTee = secTee
	}

	instr := health.NoopInstrumentation()
	if h.observers != nil {
		instr = h.observers.PrepareAttempt(r.Context(), health.AttemptTarget{
			Attempt:    0,
			Protocol:   proto,
			Endpoint:   kind,
			UpstreamID: cand.Upstream.ID,
			RouteID:    cand.Route.ID,
			Config: health.AttemptConfigFacts{
				EndpointRevision: target.EndpointRevision,
				ResolvedURLHash:  target.ResolvedURLHash,
			},
		}, health.AttemptRequestView{
			Header:   outHeader,
			RawQuery: "",
			Body:     outBody,
		})
	}

	sendCtx := r.Context()
	if instr.Trace != nil {
		sendCtx = outbound.WithAttemptTrace(sendCtx, instr.Trace)
		instr.Trace.MarkSent(time.Now())
	}
	at := fwd.Send(sendCtx, r.Method, target.RawURL, outHeader, outBody)
	if instr.Observer != nil && at.Result() != nil && at.Result().Status > 0 {
		instr.Observer.TryHeaders(at.Result().Status, at.Result().RespHeaders, time.Now())
	}

	return &liveAttempt{
		cand: cand, at: at, tee: tee, secTee: secTee,
		keys: redactKeys,
		body: outBody, header: outHeader, url: target.RawURL,
		instr:    instr,
		compiled: compiled, verID: verID, endpointID: target.EndpointID,
	}, dispatchSent
}

// countCandidateRoutes returns how many enabled Routes could be selected for
// this model (§6.5 max local skip bound). Falls back to 1 when unknown.
func countCandidateRoutes(snap *router.Snapshot, inModel string, proto model.Protocol) int {
	if snap == nil {
		return 1
	}
	mn, err := router.MatchModelName(snap, inModel, proto)
	if err != nil || mn == nil {
		return 1
	}
	n := 0
	for _, rt := range snap.RoutesByModelName[mn.ID] {
		if rt == nil || !rt.Enabled {
			continue
		}
		up := snap.Upstreams[rt.UpstreamID]
		if up == nil || !up.Enabled {
			continue
		}
		n++
	}
	if n < 1 {
		return 1
	}
	return n
}

// nextCandidate 判断这次尝试要不要换站重来，要的话选出下一个候选。
// 返回 nil 表示就用当前这次的结果作答。
//
// 顺序是刻意的：**先确定有下一个站可用，再丢弃当前尝试**。反过来的话，
// 「上游 500 但这个 ModelName 只绑了一个 Route」会先把那个 500 响应丢掉、
// 然后发现没站可换 —— 于是一个本可以原样透传给客户端的上游错误变成了
// 空响应，而 §3.3 要求响应方向原样回传。
func (h *Handler) nextCandidate(r *http.Request, pre *preambleResult,
	proto model.Protocol, plan *retryPlan, la *liveAttempt, attempt int) *router.Candidate {

	if attempt >= plan.maxAttempts {
		return nil
	}
	if !h.retryableAttempt(r, la, pre.settings.RetryPolicy) {
		return nil
	}
	// 客户端已经走了就别再花上游额度了 —— 没人在等这个响应。
	if r.Context().Err() != nil {
		return nil
	}
	if time.Until(plan.deadline) < plan.connectCost {
		return nil
	}
	cand, _, err := h.selectFor(pre, proto, plan.tried, false)
	if err != nil {
		return nil
	}
	return cand
}

// retryableAttempt 在旧 classifyPayload 之上叠加 P0-13 RetryDecider 与 P1 RetryPolicy。
func (h *Handler) retryableAttempt(r *http.Request, la *liveAttempt, policy model.RetryPolicy) bool {
	if la == nil || la.at == nil {
		return false
	}
	base := retryable(la.at)
	if !base {
		return false
	}
	policy = policy.Normalize()
	if policy == model.RetryPolicySafe && !safeRetryEvidence(la) {
		return false
	}
	// §11.2: Balanced/Aggressive inherit Safe's connect-failure scope.
	// ErrConnect after possible write (GotConn) must not failover — retrying
	// that POST on another upstream can double-apply it. Status-based retries
	// (429/5xx/…) and non-ErrConnect faults keep existing policy rules.
	if res := la.at.Result(); res != nil && res.Err != nil &&
		errors.Is(res.Err, ErrConnect) && !safeRetryEvidence(la) {
		return false
	}
	// §11.2 Aggressive only: 提交前首响应体字节超时 (ErrFirstTokenTimeout).
	// Default Balanced must not switch stations — client gets the gateway
	// timeout from this upstream, no second RoundTrip.
	if res := la.at.Result(); res != nil && res.Err != nil &&
		errors.Is(res.Err, ErrFirstTokenTimeout) &&
		policy != model.RetryPolicyAggressive {
		return false
	}
	// §11.2: Balanced named HTTP statuses only (429/502/503/504).
	// General 5xx (500, 501, 529, …) is Aggressive-only. Safe already
	// blocks status-based retries via safeRetryEvidence (Status > 0).
	if res := la.at.Result(); res != nil && res.Err == nil {
		st := la.at.Status()
		if st >= 500 && !balancedNamedFailoverStatus(st) &&
			policy != model.RetryPolicyAggressive {
			return false
		}
	}
	if la.instr.Retry == nil {
		return true
	}
	res := la.at.Result()
	if res == nil {
		return true
	}
	prefix := la.at.Peek()
	advice := la.instr.Retry.DecidePeek(r.Context(), res.Status, res.RespHeaders, prefix, true)
	if advice.Disposition == health.RetryTryNextRoute {
		return true
	}
	// KeepAttempt from decider does not widen beyond base; Safe already filtered.
	if policy == model.RetryPolicyAggressive {
		return base
	}
	return base
}

// safeRetryEvidence is true only when nothing proves the request reached the upstream (§11.2 Safe).
func safeRetryEvidence(la *liveAttempt) bool {
	if la == nil || la.at == nil {
		return false
	}
	res := la.at.Result()
	if res != nil && res.Status > 0 {
		// Any HTTP status means headers arrived — request was accepted upstream.
		return false
	}
	if la.instr.Trace != nil {
		snap := la.instr.Trace.Snapshot()
		if !snap.ResponseHeaderAt.IsZero() {
			return false
		}
		// Got a connection but no response: body may already have been written.
		if !snap.GotConnAt.IsZero() {
			return false
		}
	}
	return true
}

// balancedNamedFailoverStatus is the HTTP status set §11.2 names for Balanced
// (in addition to Safe's connect-failure scope). 429 is handled separately
// in retryable; this helper is for the 5xx subset of that named list.
func balancedNamedFailoverStatus(st int) bool {
	switch st {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// retryable 判断一次**尚未提交**的尝试是否值得换站重来（§3.5）。
//
// 可重试（base）：连接失败、TLS 失败、首 Token 超时、5xx、429、200 但载荷是错误。
// 不可重试：4xx（除 429）、客户端自己断开、ErrUpstreamBroke。
//
// 策略收窄在 retryableAttempt：§11.2 规定 ErrFirstTokenTimeout 与通用 5xx
// 仅 Aggressive 换站；Balanced 仅 429/502/503/504（及载荷侧临时错误）。
// Balanced/Safe 对收窄项的 base 仍为 true（健康回写仍算上游账），但不 failover。
//
// 「已写出字节后不得重试」这条不在这里判 —— 结构上到不了：判定发生在
// Commit 之前，而 Commit 是唯一会写字节给客户端的地方。
func retryable(at *Attempt) bool {
	// Send 阶段就失败：连不上、TLS 失败、首 Token 超时。
	//
	// 客户端断开/取消时重试毫无意义；我们自己的超时则算上游的账、可以换站。
	// 这个区分已经在 IsUpstreamFault 里做好了，在这里重写一遍迟早会与它分叉。
	//
	// ErrUpstreamBroke：GotConn 后、无响应头的传输失败（或 Peek 零字节断流）。
	// 请求可能已写入上游，§11.2 不允许按 Safe 建连失败换站。
	if err := at.Result().Err; err != nil {
		if errors.Is(err, ErrUpstreamBroke) {
			return false
		}
		return IsUpstreamFault(err)
	}

	switch st := at.Status(); {
	case st == http.StatusTooManyRequests:
		// 429 换站是这个网关最值当的一次重试：站没坏，只是这一刻不让进，
		// 而我们手上正好还有别的站。
		return true
	case st >= 500:
		return true
	case st >= 400:
		// 4xx 是请求本身的问题（参数不合法、模型名不对、key 无效）。换个站
		// 会拿到同一个 4xx，只是多花一次额度、还把一个明确的错误信息推迟了。
		//
		// **在预读之前**返回是刻意的：4xx 注定不重试，为它等一次首 Token
		// 超时是纯白等 —— 而那个超时默认是 20 分钟。
		return false
	}

	// 2xx：要看载荷才知道（§3.5 的「200 但流内立刻 error」）。
	// 判据必须保守，见 errorpayload.go 的开头：拿不准一律放行，因为误判的
	// 代价是丢掉一个已经生成好的答案，而且它不报错、只表现为「偶尔慢一倍」。
	ct := ""
	if h := at.Result().RespHeaders; h != nil {
		ct = h.Get("Content-Type")
	}
	verdict := classifyPayload(at.Peek(), ct)

	// Peek **自己**可能失败：上游回了响应头却迟迟不吐 body（首 Token 超时），
	// 或者吐了头就断开。那时 Err 是刚刚才填上的，所以必须在预读之后再读
	// 一次 —— 只在函数开头读一次的话，这一整类故障永远等不到重试，
	// 而「响应头回得很快、body 一个字节都不来」正是公益站最常见的挂法。
	if err := at.Result().Err; err != nil {
		if errors.Is(err, ErrUpstreamBroke) {
			return false
		}
		return IsUpstreamFault(err)
	}
	return verdict == payloadError
}

func finishObserver(la *liveAttempt, fin health.AttemptFinish) {
	if la == nil || la.instr.Observer == nil {
		return
	}
	defer func() { _ = recover() }()
	la.instr.Observer.Finish(fin)
}

// attemptLog 把一次尝试整理成一行日志。
//
// retried 表示这次尝试被丢弃并换了站。它与「失败」不是一回事：最后一次
// 尝试失败时同样是失败，但没有被重试（次数用尽、无站可换、或本就不可重试）。
// 区分这两者才能回答「重试有没有救回来」—— 而那是这张表存在的理由。
//
// Attempts 字段在这里**填不上**（总次数要等循环结束才知道），由调用方
// 在最后统一回填。
//
// 刻意不记任何 body 与头：那是样本的职责，两边都存一份只会让磁盘翻倍，
// 还多一处需要脱敏的地方 —— 而漏一处就是明文 key 落库。
// 两张表靠 req_id 关联。
func (h *Handler) attemptLog(la *liveAttempt, pre *preambleResult,
	proto model.Protocol, reqID string, attempt int,
	halfOpen, retried bool, res *Result, recvAt time.Time) *model.RequestLog {

	modelOut := pre.inModel
	if la.cand.Route.UpstreamModel != "" {
		modelOut = la.cand.Route.UpstreamModel
	}

	l := &model.RequestLog{
		ReqID: reqID, Attempt: attempt,
		TSRecv:      recvAt.UnixMilli(),
		TSSent:      msOrZero(res.SentAt),
		TSFirstByte: msOrZero(res.FirstByteAt),
		TSDone:      msOrZero(res.DoneAt),

		Endpoint:    proto.Path(),
		ModelIn:     pre.inModel,
		ModelOut:    modelOut,
		ModelNameID: la.cand.ModelName.ID,
		RouteID:     la.cand.Route.ID,
		UpstreamID:  la.cand.Upstream.ID,
		// 站名冗余存一份：站被删掉之后，日志仍要能说清当时走的是哪个站。
		UpstreamName: la.cand.Upstream.Name,

		RespStatus:   res.Status,
		TTFTMs:       res.TTFT().Milliseconds(),
		BytesWritten: res.BytesWritten,

		Outcome:  classifyOutcome(res),
		Retried:  retried,
		HalfOpen: halfOpen,
	}
	if retried {
		l.DuplicateRisk = !safeRetryEvidence(la)
		if l.DuplicateRisk {
			l.RetryReason = "policy_retry_after_possible_upstream_accept"
		} else {
			l.RetryReason = "safe_connect_failure"
		}
	}
	if res.Err != nil {
		// 与样本、健康回写同一条脱敏规则。日志会显示在管理界面上，
		// 而错误文本里可能带出站 URL —— FixedQueryTemplate / legacy_exact
		// 可能把 key 放在 query 里（§7.1）。
		l.Error = sample.RedactDiagnosticText(res.Err.Error(), la.keys)
	}
	return l
}

// logRetry 记一次被丢弃的尝试。
//
// 单独一条日志而不是复用 logResult：这是**不同的事件** —— 客户端最终没有
// 看到这个响应。混在一起的话，日志里会出现一次客户端请求对应多条
// 「转发失败」，而其中几条其实已经被成功兜住了，看日志的人会以为出了
// 比实际更严重的问题。
func (h *Handler) logRetry(la *liveAttempt, inModel string, attempt, maxAttempts int) {
	res := la.at.Result()
	attrs := []any{
		"model", inModel,
		"upstream", la.cand.Upstream.Name,
		"route", la.cand.Route.ID,
		"attempt", attempt,
		"max_attempts", maxAttempts,
		"status", res.Status,
	}
	if res.Err != nil {
		attrs = append(attrs, "err", res.Err)
	}
	h.log.Warn("这次尝试失败，换站重试", attrs...)
}
