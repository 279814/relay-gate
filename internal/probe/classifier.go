package probe

// 统一响应分类器（§4.6、§8.12）。
//
// 它替掉的是 ClassifyHTTP + scanStream 那套「看状态码 + 在正文里搜关键词」的
// 判定。为什么必须替：关键词判定给不出**作用范围**。旧路径把一切都归成
// health.Verdict 三态，由调用方按错误字符串猜「这是站挂了还是这一个 Route
// 配错了」—— 而每个猜的地方都是一次可能的连坐。实测过的后果是：一个模型名
// 手误让整站的全部 Route 一起判死，界面上看不出与那个手误有任何关系。
//
// 本文件只做映射，不做动作：Decision 描述「观察到了什么、结论作用于哪一层」，
// 状态写入归 P0-10 的 Registry，换候选归 P0-11 的 CalibrationService。
// 混进来的话，一次分类会同时改健康状态和调度计划，而两者的正确性无法分别验证。

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// ObservationMode 区分主动探活与真实流量旁路。
//
// 两者的完成规则不同（§6.8）：Probe 在首个语义证据后就够了并主动断流，
// 真实流量必须等协议正常结束。用同一套规则的话，真实流量里一次中途断流会被
// 记成成功 —— 于是一个持续截断回复的站在健康看板上完全正常。
type ObservationMode string

const (
	ObserveProbe ObservationMode = "probe"
	ObserveReal  ObservationMode = "real"
)

// 取消原因哨兵。调用方必须显式给出原因，Classifier 不猜。
//
// 不复用 proxy 的哨兵是刻意的：P0-08 要求新 Classifier 不导入 proxy
// （proxy 反过来也不导入 probe），否则 P0-13 接入真实流量时会成环。
// 更要紧的是语义 —— proxy.IsUpstreamFault 回答的是「这个错误算不算上游的账」，
// 而这里要区分的是「谁取消的」：我们自己在首个语义后主动断流是**预期成功**，
// 客户端断开是 ignored，两者在 proxy 的口径里都只是「非上游故障」。
var (
	// ErrClientCanceled 表示客户端断开或取消（§8.12：ignored）。
	ErrClientCanceled = errors.New("client canceled the request")
	// ErrServicePaused 表示网关被人为暂停（§8.12：ignored）。
	ErrServicePaused = errors.New("probe service paused")
	// ErrServiceShutdown 表示进程正在关闭（§8.12：ignored）。
	ErrServiceShutdown = errors.New("probe service shutting down")
	// ErrProbeCanceledAfterSemantic 是 Executor 在首个语义证据后主动断流。
	//
	// 这是**预期成功**（§6.8 末句），不是失败：Token 优化的核心就是拿到证据
	// 就走。当成异常的话，每次成功的探活都会附带一个取消错误，而运维看到的
	// 是「全部探活都以取消结束」。
	ErrProbeCanceledAfterSemantic = errors.New("probe canceled after first semantic evidence")
	// ErrProbeTransportFailed 是传输层失败（DNS/TCP/TLS/连接中断/异常 EOF）。
	ErrProbeTransportFailed = errors.New("probe transport failed")
	// ErrProbeSemanticTimeout 是响应头已到但迟迟没有语义证据。
	ErrProbeSemanticTimeout = errors.New("probe timed out waiting for semantic evidence")
)

// Decision 是一次响应观察的唯一结论。
//
// 作用范围由 Scope 明确表达，调用方不得再按错误字符串二次推断 —— 那正是
// 旧路径连坐问题的来源。三类 token 计数与状态码一并带出，供 P0-09 展平进
// ProbeExecution（字段与 model.ProbeExecution 一一对应）。
type Decision struct {
	Final                bool
	Success              bool
	Reachable            bool
	Capability           model.CapabilityState
	Scope                model.ObservationScope
	ErrorClass           model.ErrorClass
	StatusCode           int
	RetryAfterUntilMS    int64
	SemanticSeen         bool
	NormalEndSeen        bool
	Partial              bool
	ObservedInputTokens  int64
	ObservedOutputTokens int64
	CandidateDisposition model.CandidateDisposition
	RedactedDetail       string
}

// maxRedactedDetail 是脱敏详情的长度上限。
//
// 详情只由结构化枚举拼装（type/code/param），而这三个字段的长度由上游控制 ——
// 一个回了几 KB "type" 的站会让每一行 execution 都带上那几 KB。
const maxRedactedDetail = 200

// maxRetryAfterWindow 是 Retry-After 允许推到多远。
//
// 上游误填毫秒（`Retry-After: 60000`）会把站冷藏 16 小时，而它其实一分钟后
// 就恢复了。超出窗口按「没给这个头」处理，回落到配置的冷却时间。
const maxRetryAfterWindow = 30 * time.Minute

// ResponseClassifier 把协议事件流归约成一个 Decision。
//
// 状态是私有的，只能通过 Observe/Finish 推进：中间态（见过语义没见过结束）
// 本身不是任何一层能消费的结论，暴露出去只会让调用方自己拼半个判定。
type ResponseClassifier struct {
	mode     ObservationMode
	endpoint model.EndpointKind
	status   int
	headerAt time.Time

	retryAfterUntilMS int64

	semanticSeen  bool
	normalEndSeen bool
	modelListOK   bool

	observedInput  int64
	observedOutput int64

	remoteError     *ProtocolEvent
	firstErrorAfter bool

	decision *Decision
}

// NewResponseClassifier 按已收到的响应头构造分类器。
//
// status 为 0 表示连响应头都没拿到 —— 那是 §8.9 里唯一允许短路本轮昂贵 L2
// 的情形。headerAt 由调用方的 Clock 提供：§4.6 禁止本包读时钟，好让 Executor
// 与真实流量观察器对同一次响应得出同一个时间口径。
func NewResponseClassifier(mode ObservationMode, endpoint model.EndpointKind,
	status int, header http.Header, headerAt time.Time) *ResponseClassifier {

	return &ResponseClassifier{
		mode:              mode,
		endpoint:          endpoint,
		status:            status,
		headerAt:          headerAt,
		retryAfterUntilMS: retryAfterUntilMS(header, headerAt),
	}
}

// Observe 吃一个协议事件，并回答「是否已经可以收工」。
//
// final 为 true 时调用方可以立即断流（Probe 模式的首个语义证据）。
// 已经终结之后再喂事件不会改变结论：探活主动断流后在途字节仍会到达，
// 让其中的 error 事件翻掉已成立的成功等于「取消得越慢成功率越低」。
func (classifier *ResponseClassifier) Observe(event ProtocolEvent) (Decision, bool) {
	if classifier.decision != nil {
		return *classifier.decision, true
	}

	switch event.Kind {
	case EventSemantic:
		// 只认 Decoder 已经判定过的语义证据。这里不重新看 SemanticKind 是否
		// 非空之类：判据只有一份，在 Decoder 里（§8.8 的那张清单）。
		if event.Semantic {
			classifier.semanticSeen = true
		}
	case EventUsage:
		// count_tokens 的正整数 input、以及模型端点的正数 output usage，
		// 都由 Decoder 经 §8.8 判据置 Semantic；这里只认那一面旗帜。
		if event.Semantic {
			classifier.semanticSeen = true
		}
	case EventModelList:
		classifier.modelListOK = classifier.modelListOK || event.ModelListRecognized
	case EventProtocolEnd:
		classifier.normalEndSeen = true
		// Responses 的 response.completed 可同时携带正数 usage（§8.8）。
		if event.Semantic {
			classifier.semanticSeen = true
		}
	case EventRemoteError:
		// 只留第一个错误。后续错误多半是同一次故障的回声（上游先发
		// overloaded 再发 stream 中断），而按最后一个分类会让结论取决于
		// 我们什么时候断流。
		if classifier.remoteError == nil {
			captured := event
			classifier.remoteError = &captured
			classifier.firstErrorAfter = classifier.semanticSeen
		}
	case EventMetadata, EventKeepalive:
		// §8.8 明确列为不能判活：message_start、response.created、ping、
		// 空 delta。它们只证明「连上了」，而那已经由 status 表达。
	}

	// token 与 Kind 无关地累加。原先只在 EventUsage 分支累加，而 Kind 是
	// **互斥**的：Decoder 见到 Semantic 就把事件归为 EventSemantic，于是同一个
	// 事件上的 token 被丢掉。丢的恰好是两类最要紧的：count_tokens 的
	// input_tokens（它是唯一带 input 的探活端点，且那个数字就长在它的语义
	// 事件上），以及非流式正文里与 content 同在一个 JSON 对象的 usage。
	// 后果是 §5.2d 的成本核算长期少算 —— 一个会骗人的计数器比没有更糟。
	classifier.addTokens(event)

	if classifier.readyToFinish() {
		decision := classifier.conclude(nil, nil)
		return decision, true
	}
	return Decision{}, false
}

// readyToFinish 判断证据是否已经足够收工。
//
// models 端点用它自己的证据：一份可解析的模型列表就是全部结论，没有「语义
// delta」也没有「协议结束」可等（§4.6 的 models 专用解析）。用同一套语义
// 判据的话 models 永远探不通 —— 它压根不会产生 EventSemantic。
//
// 其余四个端点在这里分叉，也只在这里分叉（§6.8）：Probe 拿到首个语义证据
// 就够，Real 必须等协议正常结束。
func (classifier *ResponseClassifier) readyToFinish() bool {
	if classifier.endpoint == model.EndpointModels {
		return classifier.modelListOK
	}
	if classifier.mode == ObserveProbe {
		return classifier.semanticSeen
	}
	return classifier.semanticSeen && classifier.normalEndSeen
}

// Finish 给出最终 Decision，可以重复调用并返回同一结果。
//
// readErr 是读取正文时的失败，cancelCause 是取消原因（两者都可为 nil）。
// 幂等是必需的：调用方会在 readErr 分支上再兜一次 Finish，而第二次返回
// 一个不同的 Decision 会让落库的那份与已经上报的那份对不上。
func (classifier *ResponseClassifier) Finish(readErr, cancelCause error) Decision {
	if classifier.decision != nil {
		return *classifier.decision
	}
	return classifier.conclude(readErr, cancelCause)
}

func (classifier *ResponseClassifier) conclude(readErr, cancelCause error) Decision {
	decision := classifier.classify(readErr, cancelCause)
	decision.Final = true
	decision.StatusCode = classifier.status
	decision.SemanticSeen = classifier.semanticSeen
	decision.NormalEndSeen = classifier.normalEndSeen
	decision.ObservedInputTokens = classifier.observedInput
	decision.ObservedOutputTokens = classifier.observedOutput
	classifier.decision = &decision
	return decision
}

// classify 是判定顺序本身，顺序是刻意的。
//
// 每一步都必须排在它现在的位置上：
//  1. 取消优先于一切 —— 一次 pause 期间恰好收到的 503 不是上游的账，
//     否则「暂停探活」这个动作自己会制造健康数据。
//  2. 主动断流优先于「缺少结束事件」—— 那次取消是我们发的，而 Probe 的
//     成功判据里本来就没有结束事件（§6.8 末句明确不许套用真实流量规则）。
//  3. 没有响应头才是 unreachable —— 排在状态码分类之前，因为 status 为 0
//     时下面所有按状态码的分支都没有意义。
//  4. 语义之后的失败是 partial —— 排在通用错误分类之前：客户端已经收到内容，
//     §6.8 要求它累计失败但绝不重试，而通用分类给不出这个区别。
func (classifier *ResponseClassifier) classify(readErr, cancelCause error) Decision {
	if classifier.isIgnoredCause(cancelCause) {
		return Decision{
			Reachable:            classifier.status > 0,
			Capability:           model.CapabilityUnknown,
			Scope:                model.ScopeNone,
			ErrorClass:           model.ErrorIgnored,
			CandidateDisposition: model.CandidateStop,
		}
	}
	if errors.Is(cancelCause, ErrProbeCanceledAfterSemantic) && classifier.semanticSeen {
		return classifier.success()
	}
	if classifier.status <= 0 {
		return Decision{
			Reachable:            false,
			Capability:           model.CapabilityUnknown,
			Scope:                model.ScopeUpstreamReachability,
			ErrorClass:           model.ErrorUnreachable,
			CandidateDisposition: model.CandidateStop,
			RedactedDetail:       "transport_failure",
		}
	}
	if classifier.semanticSeen && classifier.hasFailedAfterSemantic(readErr) {
		return Decision{
			Reachable:            true,
			Capability:           model.CapabilityTransientError,
			Scope:                classifier.scope(),
			ErrorClass:           model.ErrorPartial,
			Partial:              true,
			CandidateDisposition: model.CandidateStop,
			RedactedDetail:       classifier.partialDetail(readErr),
		}
	}
	if classifier.readyToFinish() {
		return classifier.success()
	}
	return classifier.failure(readErr)
}

func (classifier *ResponseClassifier) isIgnoredCause(cause error) bool {
	return errors.Is(cause, ErrClientCanceled) ||
		errors.Is(cause, ErrServicePaused) ||
		errors.Is(cause, ErrServiceShutdown)
}

// hasFailedAfterSemantic 判断语义证据之后是否出了问题。
//
// Probe 模式排除在外：它在首个语义事件就 final 了，之后到达的字节是在途数据。
// 把它们算进来会让「取消得慢」变成失败，而快慢取决于网络而不是站的健康。
func (classifier *ResponseClassifier) hasFailedAfterSemantic(readErr error) bool {
	if classifier.mode == ObserveProbe {
		return false
	}
	if readErr != nil {
		return true
	}
	if classifier.remoteError != nil && classifier.firstErrorAfter {
		return true
	}
	return !classifier.normalEndSeen
}

func (classifier *ResponseClassifier) partialDetail(readErr error) string {
	if readErr != nil {
		return "partial_after_semantic:transport"
	}
	if classifier.remoteError != nil {
		return truncateDetail("partial_after_semantic:" + errorDetail(*classifier.remoteError))
	}
	return "partial_after_semantic:missing_protocol_end"
}

func (classifier *ResponseClassifier) success() Decision {
	return Decision{
		Success:              true,
		Reachable:            true,
		Capability:           model.CapabilitySupported,
		Scope:                classifier.scope(),
		ErrorClass:           model.ErrorNone,
		CandidateDisposition: model.CandidateStop,
	}
}

// failure 分类「没有取得成功证据」的各种情形。
//
// 状态码先于流内错误：401 就是 401，哪怕正文里写着 "rate limit exceeded"
// （余额耗尽的 key 很常见这么写）。反过来的话，一个需要充值的 key 会被判成
// 限流 —— 冷却 60 秒再试，永远攒不够失败次数，于是永远不判死，而它只能靠
// 人去充值。这条顺序是从旧 ClassifyHTTP 的注释里继承来的实测结论。
func (classifier *ResponseClassifier) failure(readErr error) Decision {
	decision := Decision{
		Reachable:            true,
		Scope:                classifier.scope(),
		CandidateDisposition: model.CandidateStop,
		RetryAfterUntilMS:    classifier.retryAfterUntilMS,
	}

	switch {
	case classifier.status == http.StatusTooManyRequests:
		decision.Capability = model.CapabilityTransientError
		decision.ErrorClass = model.ErrorRateLimited

	case classifier.status == http.StatusUnauthorized || classifier.status == http.StatusForbidden:
		// 永远只到 auth_rejected。§8.12 把「穷尽候选后才写 config_error」
		// 交给 CalibrationService —— 这里抢先写的话，第一次 401 就把端点
		// 判成配置错误，而 §8.13 规定 config_error 只能由配置变更或人工测试
		// 解除，于是校准还没开始就没得救了。也绝不连坐 Upstream。
		decision.Capability = model.CapabilityUnknown
		decision.ErrorClass = model.ErrorAuthRejected
		decision.CandidateDisposition = model.CandidateTryNextAuth

	case classifier.status == http.StatusNotFound || classifier.status == http.StatusMethodNotAllowed:
		decision.Capability = model.CapabilityUnsupported
		decision.ErrorClass = model.ErrorUnsupported

	case classifier.status >= 500:
		decision.Capability = model.CapabilityTransientError
		decision.ErrorClass = model.ErrorTransient

	case classifier.remoteError != nil:
		classifier.applyRemoteError(&decision)

	case classifier.status >= 400:
		// 其余 4xx 没有结构化错误可依据：保守归为请求形状问题。
		// 探活请求是我们自己构造的，一个没预料到的 400 更可能是「这个站的
		// 参数要求特殊」，而那正是 P0-11 换 shape 候选要解决的事。
		decision.Capability = model.CapabilityConfigError
		decision.ErrorClass = model.ErrorShapeRejected

	case errors.Is(readErr, ErrProbeSemanticTimeout):
		decision.Capability = model.CapabilityTransientError
		decision.ErrorClass = model.ErrorTransient
		decision.RedactedDetail = "semantic_timeout"

	case readErr != nil:
		decision.Capability = model.CapabilityTransientError
		decision.ErrorClass = model.ErrorTransient
		decision.RedactedDetail = "read_failure"

	default:
		// 2xx 走到这里说明「协议上完成了，却没有任何语义证据」。
		// §6.8 归为 fake_alive，也就是这个项目最核心要识别的那种站：
		// HTTP 层一切正常，模型什么都没输出。
		decision.Capability = model.CapabilityTransientError
		decision.ErrorClass = model.ErrorFakeAlive
		decision.RedactedDetail = classifier.fakeAliveDetail()
	}

	if decision.RedactedDetail == "" && classifier.remoteError != nil {
		decision.RedactedDetail = truncateDetail(errorDetail(*classifier.remoteError))
	}
	return decision
}

// fakeAliveDetail 说明「2xx 但没有语义证据」的具体形态。
//
// models 只有一种形态可报：Decoder 对「不是模型列表」的 200 正文一律降为
// EventMetadata（见 stream.go 的 eventFromObject），不会产出「model_list
// 事件但 recognized=false」这种组合。
//
// 第一版按那个组合分了两支（model_list_unrecognized / model_list_absent），
// 故障注入时才发现两支都不可达 —— Decoder 压根不产生它依赖的输入。
// 留着的话下一个人会以为「能从详情区分这两种失败」，而实际永远只出一个值。
func (classifier *ResponseClassifier) fakeAliveDetail() string {
	if classifier.endpoint == model.EndpointModels {
		return "model_list_unrecognized"
	}
	if classifier.normalEndSeen {
		return "normal_end_without_semantic"
	}
	return "no_semantic_evidence"
}

// applyRemoteError 按结构化字段分类 HTTP 200 的流内错误。
//
// 只看 Decoder 已经规范化的 type/code，绝不解析自由文本（§4.6）。
// 靠措辞猜的话，一个描述里带 "header" 的无关错误会让校准白烧三次候选的钱。
func (classifier *ResponseClassifier) applyRemoteError(decision *Decision) {
	event := *classifier.remoteError
	decision.RedactedDetail = truncateDetail(errorDetail(event))

	if isModelNotFound(event) {
		decision.Capability = model.CapabilityConfigError
		decision.ErrorClass = model.ErrorModelNotFound
		decision.Scope = model.ScopeRouteEndpoint
		return
	}

	switch event.RedactedType {
	case "rate_limit_error", "overloaded_error":
		// overloaded 归限流而不是服务故障：Anthropic 的 529 overloaded_error
		// 表达的是「太受欢迎」，按 5xx 累计判死会把一个可用的站踢出池子。
		decision.Capability = model.CapabilityTransientError
		decision.ErrorClass = model.ErrorRateLimited
	case "authentication_error", "permission_error":
		decision.Capability = model.CapabilityUnknown
		decision.ErrorClass = model.ErrorAuthRejected
		decision.CandidateDisposition = model.CandidateTryNextAuth
	case "invalid_request_error", "request_too_large":
		decision.Capability = model.CapabilityConfigError
		decision.ErrorClass = model.ErrorShapeRejected
		decision.CandidateDisposition = shapeDisposition(event)
	case "api_error", "server_error", "overloaded", "service_unavailable":
		decision.Capability = model.CapabilityTransientError
		decision.ErrorClass = model.ErrorTransient
	default:
		// 未知的结构化 type：当作瞬时故障并停止换候选。
		// 猜成配置错误会让一个临时故障永久排除该端点（config_error 只能人工
		// 解除），猜成可换候选会白烧钱 —— 两个方向都比「等下次再探」更糟。
		decision.Capability = model.CapabilityTransientError
		decision.ErrorClass = model.ErrorTransient
	}
}

// modelNotFoundCodes 是「模型不存在」的结构化 code 白名单。
//
// 只认结构化字段，不再像旧 ClassifyHTTP 那样在正文里搜 "model not found"
// 之类的措辞：那份关键词表会把一个正常回答里提到模型名的响应判成配置错误。
var modelNotFoundCodes = map[string]struct{}{
	"model_not_found":     {},
	"model_not_available": {},
	"invalid_model":       {},
	"unknown_model":       {},
}

func isModelNotFound(event ProtocolEvent) bool {
	_, found := modelNotFoundCodes[event.ErrorCode]
	return found
}

// shapeCandidateCodes 是允许换请求形状候选的结构化 code 白名单。
//
// §4.6 要求只有白名单里的结构化错误能产生 try_next_shape。清单收窄是刻意的：
// 每多一个条目就多一次「烧三个候选的钱去试一个不会成功的形状」的机会，
// 而漏掉一个的代价只是那个站需要人工配一份 Recipe。
var shapeCandidateCodes = map[string]struct{}{
	"missing_beta_header":     {},
	"unsupported_beta_header": {},
	"beta_header_required":    {},
	"unknown_parameter":       {},
	"unsupported_parameter":   {},
	"unsupported_field":       {},
}

func shapeDisposition(event ProtocolEvent) model.CandidateDisposition {
	if _, found := shapeCandidateCodes[event.ErrorCode]; found {
		return model.CandidateTryNextShape
	}
	return model.CandidateStop
}

// scope 回答「这个结论作用于哪一层」。
//
// models 是站级端点，其余四个都挂在具体 Route 上。这条区分是 §8.9 的直接
// 要求：models 404 只写站的 models 能力，绝不动任何 Route 的健康。
func (classifier *ResponseClassifier) scope() model.ObservationScope {
	if classifier.endpoint == model.EndpointModels {
		return model.ScopeUpstreamEndpoint
	}
	return model.ScopeRouteEndpoint
}

// addTokens 单调累加 token 计数。
//
// 只拒绝**下降**，其余按累加：usage 事件在不同协议里含义不同 ——
// Anthropic 的 message_delta 给累计值，而别的协议给增量。取 max 会漏掉真增量，
// 一律相加又会把累计协议重复计数。负值在 Decoder 那层已经丢过一次，
// 这里是第二道：让 -5 流进去会让总和往回走，于是「这次探活比上次少花了
// token」这种不可能的结论会进数据库，而到那一层已经查不出是哪个站发的。
func (classifier *ResponseClassifier) addTokens(event ProtocolEvent) {
	if event.InputTokens > 0 {
		classifier.observedInput += event.InputTokens
	}
	if event.OutputTokens > 0 {
		classifier.observedOutput += event.OutputTokens
	}
}

// errorDetail 用结构化字段拼出脱敏详情。
//
// 只用 Decoder 已经规范化的 type/code/param —— 上游的 message 从来不进
// ProtocolEvent，所以这里也不可能把它拼回去（§4.6 的明文要求）。
func errorDetail(event ProtocolEvent) string {
	parts := make([]string, 0, 3)
	for _, field := range []string{event.RedactedType, event.ErrorCode, event.ErrorField} {
		if field != "" {
			parts = append(parts, field)
		}
	}
	if len(parts) == 0 {
		return "remote_error"
	}
	return strings.Join(parts, ":")
}

func truncateDetail(detail string) string {
	if len(detail) <= maxRedactedDetail {
		return detail
	}
	return detail[:maxRedactedDetail]
}

// retryAfterUntilMS 把 Retry-After 换算成绝对毫秒时刻。
//
// 用注入的 headerAt 而不是 time.Now()（§4.6 明文禁止）：Executor 的 Clock
// 与真实流量观察器的 TryHeaders 时间必须与这里同一口径，各读一次时钟会让
// 「同一次响应」在 execution 行里出现两个互相矛盾的时间。
//
// 返回 0 表示「上游没给可用的值」，调用方回落到配置的冷却时间。负数、
// 超窗口、溢出和非法格式都按没给处理 —— 一个写错的 Retry-After 不该让站
// 冷藏几小时，而它其实早就恢复了。
func retryAfterUntilMS(header http.Header, headerAt time.Time) int64 {
	if header == nil {
		return 0
	}
	raw := strings.TrimSpace(header.Get("Retry-After"))
	if raw == "" {
		return 0
	}

	if seconds, err := strconv.ParseInt(raw, 10, 64); err == nil {
		if seconds < 0 {
			return 0
		}
		delta := time.Duration(seconds) * time.Second
		// 先比秒数再乘：seconds 足够大时 time.Duration 的乘法会溢出成负数，
		// 于是一个荒谬的大值会变成「立刻重试」——  与它表达的意思正好相反。
		if seconds > int64(maxRetryAfterWindow/time.Second) || delta < 0 {
			return 0
		}
		return headerAt.Add(delta).UnixMilli()
	}

	instant, err := http.ParseTime(raw)
	if err != nil {
		return 0
	}
	// 过去的日期 clamp 到 headerAt：负的剩余时间会让 reducer 立刻重试，
	// 等于无视了上游的限流要求。上游时钟比我们快时这是常见形态。
	if instant.Before(headerAt) {
		return headerAt.UnixMilli()
	}
	if instant.Sub(headerAt) > maxRetryAfterWindow {
		return 0
	}
	return instant.UnixMilli()
}
