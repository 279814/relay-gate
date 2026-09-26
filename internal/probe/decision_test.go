package probe

import (
	"go/parser"
	"go/token"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// headerAt 是所有 Retry-After 断言的固定基准时刻。
//
// 用固定值而不是 time.Now()：§4.6 明确禁止 classifier 内部读时钟，
// 而测试若自己取 now 就无法钉住「过去日期 clamp 到 headerAt」这类边界 ——
// 那条断言的两边都会随执行时刻漂移。
var headerAt = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func modelsClassifier(status int, header http.Header) *ResponseClassifier {
	return NewResponseClassifier(ObserveProbe, model.EndpointModels, status, header, headerAt)
}

func messagesClassifier(status int) *ResponseClassifier {
	return NewResponseClassifier(ObserveProbe, model.EndpointMessages, status, nil, headerAt)
}

// 任意合法 HTTP 响应都表示站可达。
//
// 这是 §8.9 的硬要求，也是本包存在的首要理由：旧路径把 401/404/429 一律
// 经 health.VerdictFatal 传成「整站 dead」，于是一个只是模型名配错的 Route
// 会把同站其余 Route 全部连坐。收到任何状态码都证明 DNS/TCP/TLS 走通了。
func TestAnyHTTPStatusMeansReachable(t *testing.T) {
	for _, status := range []int{200, 400, 401, 403, 404, 405, 429, 500, 502, 503, 529} {
		decision := modelsClassifier(status, nil).Finish(nil, nil)
		if !decision.Reachable {
			t.Errorf("status %d: Reachable = false, want true", status)
		}
		if decision.ErrorClass == model.ErrorUnreachable {
			t.Errorf("status %d: ErrorClass = unreachable, want a business class", status)
		}
	}
}

// models 200 只有真的解析出模型列表才算 supported。
//
// HTML 与任意 JSON 对象是 fake_alive：公益站被网关拦下时回一整页 HTML 却带
// 200，而「200 就算能力可用」会让一个根本不工作的端点显示为 supported，
// 之后 L2 持续往它上面烧 token。
func TestModelsCapabilityRequiresARecognizedList(t *testing.T) {
	recognized := modelsClassifier(200, nil)
	recognized.Observe(ProtocolEvent{Kind: EventModelList, ModelListRecognized: true, ModelCount: 3})
	decision := recognized.Finish(nil, nil)
	if !decision.Success || decision.Capability != model.CapabilitySupported {
		t.Fatalf("recognized list: success=%v capability=%v", decision.Success, decision.Capability)
	}
	if decision.Scope != model.ScopeUpstreamEndpoint {
		t.Fatalf("models scope = %v, want upstream_endpoint", decision.Scope)
	}

	// 空但结构合法的列表仍表示端点可解析（§4.6）。一个刚建好还没配模型的
	// 中转站回 {"data":[]} 是正常的，判成不支持会让它永远探不通。
	empty := modelsClassifier(200, nil)
	empty.Observe(ProtocolEvent{Kind: EventModelList, ModelListRecognized: true, ModelCount: 0})
	if decision := empty.Finish(nil, nil); !decision.Success {
		t.Fatalf("empty but valid list: success=false class=%v", decision.ErrorClass)
	}

	unrecognized := modelsClassifier(200, nil)
	unrecognized.Observe(ProtocolEvent{Kind: EventModelList, ModelListRecognized: false})
	decision = unrecognized.Finish(nil, nil)
	if decision.Success {
		t.Fatal("unrecognized body was treated as success")
	}
	if decision.ErrorClass != model.ErrorFakeAlive {
		t.Fatalf("unrecognized body class = %v, want fake_alive", decision.ErrorClass)
	}

	// 连 model_list 事件都没有（HTML 错误页解析不出任何东西）同样是 fake_alive。
	silent := modelsClassifier(200, nil).Finish(nil, nil)
	if silent.Success || silent.ErrorClass != model.ErrorFakeAlive {
		t.Fatalf("silent 200 = success:%v class:%v, want fake_alive", silent.Success, silent.ErrorClass)
	}
}

// 404/405 是 unsupported，401/403 是 unknown + auth_rejected。
//
// 这两组必须分开：unsupported 是「这个站没有这个端点」，是稳定事实；
// auth_rejected 是「可能是认证方式没配对」，而 §8.12 要求先走校准，
// 单个 401 绝不能直接判 config_error（那会让一个只是认证形式不同的站
// 被永久排除，且不连坐 Upstream）。
func TestStatusCodesMapToTheSpecifiedCapability(t *testing.T) {
	tests := []struct {
		status     int
		capability model.CapabilityState
		class      model.ErrorClass
	}{
		{404, model.CapabilityUnsupported, model.ErrorUnsupported},
		{405, model.CapabilityUnsupported, model.ErrorUnsupported},
		{401, model.CapabilityUnknown, model.ErrorAuthRejected},
		{403, model.CapabilityUnknown, model.ErrorAuthRejected},
		{429, model.CapabilityTransientError, model.ErrorRateLimited},
		{500, model.CapabilityTransientError, model.ErrorTransient},
		{502, model.CapabilityTransientError, model.ErrorTransient},
		{503, model.CapabilityTransientError, model.ErrorTransient},
		{504, model.CapabilityTransientError, model.ErrorTransient},
		// 3xx：不跟随；成功只认 2xx，归 soft transient（非 Success）
		{301, model.CapabilityTransientError, model.ErrorTransient},
		{302, model.CapabilityTransientError, model.ErrorTransient},
		{303, model.CapabilityTransientError, model.ErrorTransient},
		{307, model.CapabilityTransientError, model.ErrorTransient},
		{308, model.CapabilityTransientError, model.ErrorTransient},
	}
	for _, tc := range tests {
		decision := modelsClassifier(tc.status, nil).Finish(nil, nil)
		if decision.Capability != tc.capability || decision.ErrorClass != tc.class {
			t.Errorf("status %d = capability:%v class:%v, want capability:%v class:%v",
				tc.status, decision.Capability, decision.ErrorClass, tc.capability, tc.class)
		}
		if decision.Success {
			t.Errorf("status %d was treated as success", tc.status)
		}
		if !decision.Reachable {
			t.Errorf("status %d: reachable = false", tc.status)
		}
	}
}

// Classifier 对 401/403 只返回 auth_rejected，永不自行升级为 config_error。
//
// §8.12 把「穷尽候选后才写 config_error」这一步交给 CalibrationService。
// Classifier 抢先写的话，第一次 401 就把端点判成配置错误，而 §8.13 规定
// config_error 只能由配置变更或人工测试解除 —— 于是校准还没开始就没得救了。
func TestClassifierNeverEscalatesAuthRejectionToConfigError(t *testing.T) {
	for _, status := range []int{401, 403} {
		for _, mode := range []ObservationMode{ObserveProbe, ObserveReal} {
			classifier := NewResponseClassifier(mode, model.EndpointMessages, status, nil, headerAt)
			classifier.Observe(ProtocolEvent{Kind: EventRemoteError, RedactedType: "authentication_error"})
			decision := classifier.Finish(nil, nil)
			if decision.Capability == model.CapabilityConfigError {
				t.Errorf("mode %v status %d escalated to config_error", mode, status)
			}
			if decision.ErrorClass != model.ErrorAuthRejected {
				t.Errorf("mode %v status %d class = %v, want auth_rejected", mode, status, decision.ErrorClass)
			}
		}
	}
}

// count_tokens 200 必须有正整数 input_tokens 才算 supported。
func TestCountTokensRequiresAPositiveInputCount(t *testing.T) {
	supported := NewResponseClassifier(ObserveProbe, model.EndpointCountTokens, 200, nil, headerAt)
	supported.Observe(ProtocolEvent{Kind: EventUsage, Semantic: true, InputTokens: 8})
	decision := supported.Finish(nil, nil)
	if !decision.Success || decision.Capability != model.CapabilitySupported {
		t.Fatalf("positive input tokens: success=%v capability=%v", decision.Success, decision.Capability)
	}
	if decision.ObservedInputTokens != 8 {
		t.Fatalf("ObservedInputTokens = %d, want 8", decision.ObservedInputTokens)
	}
	if decision.ObservedOutputTokens != 0 {
		t.Fatalf("count_tokens must not report output tokens, got %d", decision.ObservedOutputTokens)
	}

	// 没有 input_tokens 的 200 不能算通：那份响应结构上不是 count_tokens 的回复。
	silent := NewResponseClassifier(ObserveProbe, model.EndpointCountTokens, 200, nil, headerAt)
	if got := silent.Finish(nil, nil); got.Success {
		t.Fatal("count_tokens 200 without input tokens was treated as success")
	}

	unsupported := NewResponseClassifier(ObserveProbe, model.EndpointCountTokens, 404, nil, headerAt)
	if got := unsupported.Finish(nil, nil); got.Capability != model.CapabilityUnsupported {
		t.Fatalf("count_tokens 404 capability = %v, want unsupported", got.Capability)
	}
}

// model_not_found 是 Route 级配置错误。
//
// 作用范围必须是 route_endpoint 而不是 upstream_endpoint：配错的是这一个
// Route 的 upstream_model 映射，而同站其余 Route 可能完全正常。写成站级的话
// 一个模型名手误会让整站的全部模型一起消失。
func TestModelNotFoundIsARouteScopedConfigError(t *testing.T) {
	classifier := messagesClassifier(400)
	classifier.Observe(ProtocolEvent{Kind: EventRemoteError, RedactedType: "invalid_request_error",
		ErrorCode: "model_not_found"})
	decision := classifier.Finish(nil, nil)
	if decision.Capability != model.CapabilityConfigError {
		t.Fatalf("capability = %v, want config_error", decision.Capability)
	}
	if decision.ErrorClass != model.ErrorModelNotFound {
		t.Fatalf("class = %v, want model_not_found", decision.ErrorClass)
	}
	if decision.Scope != model.ScopeRouteEndpoint {
		t.Fatalf("scope = %v, want route_endpoint", decision.Scope)
	}
}

// 只有白名单里的结构化错误能让校准换候选。
//
// 自由文本、缺少结构化字段、以及本地配置错误一律 CandidateStop。§4.6 明确
// 要求「Calibration 只读取该枚举，绝不解析 RedactedDetail 或上游错误字符串」——
// 靠字符串猜的话，一个措辞里带 "header" 的无关错误会让校准白烧三次候选的钱。
func TestOnlyWhitelistedStructuredErrorsAdvanceCandidates(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		event       ProtocolEvent
		disposition model.CandidateDisposition
	}{
		{
			name:   "authentication error advances auth candidate",
			status: 401,
			event: ProtocolEvent{Kind: EventRemoteError, RedactedType: "authentication_error",
				ErrorCode: "invalid_api_key"},
			disposition: model.CandidateTryNextAuth,
		},
		{
			name:   "missing beta header advances shape candidate",
			status: 400,
			event: ProtocolEvent{Kind: EventRemoteError, RedactedType: "invalid_request_error",
				ErrorCode: "missing_beta_header", ErrorField: "anthropic-beta"},
			disposition: model.CandidateTryNextShape,
		},
		{
			name:   "unknown structured code stops",
			status: 400,
			event: ProtocolEvent{Kind: EventRemoteError, RedactedType: "invalid_request_error",
				ErrorCode: "something_we_have_never_seen"},
			disposition: model.CandidateStop,
		},
		{
			name:        "free text error stops",
			status:      400,
			event:       ProtocolEvent{Kind: EventRemoteError, RedactedType: "error"},
			disposition: model.CandidateStop,
		},
		{
			name:        "rate limit stops even though it is retryable",
			status:      429,
			event:       ProtocolEvent{Kind: EventRemoteError, RedactedType: "rate_limit_error"},
			disposition: model.CandidateStop,
		},
		{
			name:        "server error stops",
			status:      503,
			event:       ProtocolEvent{Kind: EventRemoteError, RedactedType: "server_error"},
			disposition: model.CandidateStop,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			classifier := messagesClassifier(tc.status)
			classifier.Observe(tc.event)
			decision := classifier.Finish(nil, nil)
			if decision.CandidateDisposition != tc.disposition {
				t.Fatalf("disposition = %v, want %v", decision.CandidateDisposition, tc.disposition)
			}
		})
	}
}

// 429、502/503/504、connect failure、语义超时立即停止换候选（§P0-11 第 7 条）。
//
// 与上面那条不同的角度：这里问的是「传输层失败会不会被当成换候选的理由」。
// 会的话，一个正在限流的站会把三个候选连着烧完，而三次都会因为同一个 429 失败。
func TestTransportFailuresNeverAdvanceCandidates(t *testing.T) {
	for _, cause := range []error{ErrProbeTransportFailed, ErrProbeSemanticTimeout} {
		classifier := messagesClassifier(0)
		decision := classifier.Finish(cause, nil)
		if decision.CandidateDisposition != model.CandidateStop {
			t.Errorf("cause %v: disposition = %v, want stop", cause, decision.CandidateDisposition)
		}
	}
}

// 429 的 Retry-After 以注入的 headerAt 换算成绝对时刻。
//
// 禁止内部读时钟（§4.6）：Executor 的 Clock 与真实流量观察器的 TryHeaders
// 时间必须与这里同一口径，各读一次 time.Now() 会让「同一次响应」在
// execution 行里出现两个互相矛盾的时间。
func TestRetryAfterBecomesAnAbsoluteDeadlineFromHeaderAt(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  int64
	}{
		{"delta seconds", "30", headerAt.Add(30 * time.Second).UnixMilli()},
		{"zero delta clamps to headerAt", "0", headerAt.UnixMilli()},
		{"http date", headerAt.Add(90 * time.Second).UTC().Format(http.TimeFormat),
			headerAt.Add(90 * time.Second).UnixMilli()},
		// 过去的日期 clamp 到 headerAt 而不是产生一个已经过期的绝对时刻：
		// 负的剩余时间会让 reducer 立刻重试，等于无视了上游的限流要求。
		{"past http date clamps to headerAt", headerAt.Add(-time.Hour).UTC().Format(http.TimeFormat),
			headerAt.UnixMilli()},
		{"negative delta is ignored", "-5", 0},
		{"absurd delta is ignored", "999999999999", 0},
		{"overflowing delta is ignored", "9223372036854775807", 0},
		{"garbage is ignored", "soon", 0},
		{"empty is ignored", "", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			header := http.Header{}
			if tc.value != "" {
				header.Set("Retry-After", tc.value)
			}
			decision := modelsClassifier(429, header).Finish(nil, nil)
			if decision.RetryAfterUntilMS != tc.want {
				t.Fatalf("RetryAfterUntilMS = %d, want %d", decision.RetryAfterUntilMS, tc.want)
			}
		})
	}
}

// §8.8 列出的「不能单独判活」形态一条都不能算成功。
func TestNonSemanticEventsNeverSucceed(t *testing.T) {
	tests := []struct {
		name   string
		events []ProtocolEvent
	}{
		{"http 200 alone", nil},
		{"message_start only", []ProtocolEvent{{Kind: EventMetadata, EventName: "message_start"}}},
		{"response.created only", []ProtocolEvent{{Kind: EventMetadata, EventName: "response.created"}}},
		{"ping only", []ProtocolEvent{{Kind: EventKeepalive, EventName: "ping"}}},
		{"empty delta", []ProtocolEvent{{Kind: EventMetadata, EventName: "content_block_delta"}}},
		{"zero output usage", []ProtocolEvent{{Kind: EventUsage, EventName: "message_delta", OutputTokens: 0}}},
		{"protocol end only", []ProtocolEvent{{Kind: EventProtocolEnd, EventName: "message_stop"}}},
		{"metadata then end", []ProtocolEvent{
			{Kind: EventMetadata, EventName: "message_start"},
			{Kind: EventProtocolEnd, EventName: "message_stop"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			classifier := messagesClassifier(200)
			for _, event := range tc.events {
				classifier.Observe(event)
			}
			decision := classifier.Finish(nil, nil)
			if decision.Success {
				t.Fatalf("success on %s", tc.name)
			}
			if decision.SemanticSeen {
				t.Fatalf("SemanticSeen on %s", tc.name)
			}
			if decision.ErrorClass != model.ErrorFakeAlive {
				t.Fatalf("class = %v, want fake_alive", decision.ErrorClass)
			}
		})
	}
}

// §8.8：正数 output usage（Decoder 已置 Semantic）是判活证据。
func TestPositiveOutputUsageSetsSemanticInProbe(t *testing.T) {
	classifier := messagesClassifier(200)
	decision, final := classifier.Observe(ProtocolEvent{
		Kind: EventUsage, EventName: "message_delta", Semantic: true, OutputTokens: 3, InputTokens: 10,
	})
	if !final || !decision.Success || !decision.SemanticSeen {
		t.Fatalf("positive usage must succeed in probe mode: final=%v decision=%+v", final, decision)
	}
	if decision.ObservedInputTokens != 10 || decision.ObservedOutputTokens != 3 {
		t.Fatalf("tokens = in:%d out:%d, want in:10 out:3",
			decision.ObservedInputTokens, decision.ObservedOutputTokens)
	}
}

// Real 模式下 Semantic 的 usage 仍累加 token，且须等协议结束。
func TestPositiveOutputUsageAccumulatesTokensInRealMode(t *testing.T) {
	classifier := NewResponseClassifier(ObserveReal, model.EndpointMessages, 200, nil, headerAt)
	if _, final := classifier.Observe(ProtocolEvent{
		Kind: EventUsage, Semantic: true, InputTokens: 10, OutputTokens: 3,
	}); final {
		t.Fatal("real mode must not finish on first usage alone")
	}
	classifier.Observe(ProtocolEvent{Kind: EventUsage, Semantic: true, OutputTokens: 4})
	classifier.Observe(ProtocolEvent{Kind: EventProtocolEnd, EventName: "message_stop"})
	got := classifier.Finish(nil, nil)
	if !got.Success || !got.SemanticSeen {
		t.Fatalf("decision = %+v", got)
	}
	if got.ObservedInputTokens != 10 || got.ObservedOutputTokens != 7 {
		t.Fatalf("tokens = in:%d out:%d, want in:10 out:7",
			got.ObservedInputTokens, got.ObservedOutputTokens)
	}
}

// Decoder 未置 Semantic 的 usage 只记数：Classifier 不二次发明判活。
func TestUsageWithoutSemanticFlagDoesNotSetSemanticSeen(t *testing.T) {
	classifier := messagesClassifier(200)
	classifier.Observe(ProtocolEvent{Kind: EventUsage, OutputTokens: 5})
	decision := classifier.Finish(nil, nil)
	if decision.SemanticSeen || decision.Success {
		t.Fatalf("usage without Semantic flag must not succeed: %+v", decision)
	}
	if decision.ObservedOutputTokens != 5 {
		t.Fatalf("ObservedOutputTokens = %d, want 5", decision.ObservedOutputTokens)
	}
}

// token 汇总必须单调：回退值与负值都不能让总数往下走。
//
// 负数在 Decoder 那层已经被丢掉了，这里守的是第二道：usage 事件本身可能是
// 「累计值」而不是「增量」（Anthropic 的 message_delta 就是累计），
// 于是同一个字段会重复出现且值递增。取 max 而不是相加会漏掉真增量协议，
// 相加又会把累计协议重复计数 —— 所以只拒绝**下降**，其余按累加。
func TestTokenTotalsNeverWalkBackwards(t *testing.T) {
	classifier := messagesClassifier(200)
	classifier.Observe(ProtocolEvent{Kind: EventUsage, OutputTokens: 12})
	classifier.Observe(ProtocolEvent{Kind: EventUsage, OutputTokens: -5})
	decision := classifier.Finish(nil, nil)
	if decision.ObservedOutputTokens != 12 {
		t.Fatalf("ObservedOutputTokens = %d, want 12 (negative delta must be dropped)",
			decision.ObservedOutputTokens)
	}
}

// Probe 模式在首个语义事件后就成功，并允许主动取消。
//
// Observe 返回 final=true 是 Executor 断流的信号（§4.6：「Probe 模式在首个
// Semantic Event 后返回成功并允许主动取消」）。这是 Token 优化的核心：
// 一次探活只需要证明「模型开始输出了」，等它把整段话说完是白花钱。
func TestProbeSucceedsAtFirstSemanticEvent(t *testing.T) {
	classifier := messagesClassifier(200)
	if decision, final := classifier.Observe(ProtocolEvent{Kind: EventMetadata,
		EventName: "message_start"}); final {
		t.Fatalf("metadata was final: %+v", decision)
	}
	decision, final := classifier.Observe(ProtocolEvent{Kind: EventSemantic,
		EventName: "content_block_delta", Semantic: true, SemanticKind: "text"})
	if !final {
		t.Fatal("first semantic event was not final in probe mode")
	}
	if !decision.Success || !decision.SemanticSeen || decision.Capability != model.CapabilitySupported {
		t.Fatalf("decision = %+v", decision)
	}
	// 主动取消不能把已经成立的成功翻掉：那次取消正是我们自己发的。
	if got := classifier.Finish(nil, ErrProbeCanceledAfterSemantic); !got.Success {
		t.Fatalf("expected cancel turned success into failure: %+v", got)
	}
}

// Real 模式必须等协议正常结束，不能在首个语义事件就收。
//
// §6.8 把两种模式的完成规则分开：真实流量要的是「客户端确实拿到了完整回复」，
// 而 Probe 要的是「这个站还活着」。混用的话，真实流量里一次中途断流会被
// 记成成功，于是一个持续截断回复的站在健康看板上完全正常。
func TestRealModeRequiresANormalProtocolEnd(t *testing.T) {
	classifier := NewResponseClassifier(ObserveReal, model.EndpointMessages, 200, nil, headerAt)
	if _, final := classifier.Observe(ProtocolEvent{Kind: EventSemantic, Semantic: true,
		SemanticKind: "text"}); final {
		t.Fatal("real mode ended at the first semantic event")
	}
	if decision, final := classifier.Observe(ProtocolEvent{Kind: EventProtocolEnd,
		EventName: "message_stop"}); !final || !decision.Success {
		t.Fatalf("normal end did not complete real observation: final=%v decision=%+v", final, decision)
	}
	if !classifier.Finish(nil, nil).NormalEndSeen {
		t.Fatal("NormalEndSeen was not recorded")
	}
}

// 语义之后出现错误或异常 EOF 是 partial_failure。
//
// 与 fake_alive 是两回事：partial 表示客户端已经收到了一部分内容，
// §6.8 要求它累计 Route 失败但绝不触发重试（已经 Commit 了，重试会让
// 客户端看到两段拼接的回复）。混成一类的话重试逻辑就没有依据了。
func TestErrorAfterSemanticIsPartialFailure(t *testing.T) {
	tests := []struct {
		name   string
		finish func(*ResponseClassifier) Decision
	}{
		{"error event after semantic", func(classifier *ResponseClassifier) Decision {
			classifier.Observe(ProtocolEvent{Kind: EventRemoteError, RedactedType: "overloaded_error"})
			return classifier.Finish(nil, nil)
		}},
		{"abnormal EOF after semantic", func(classifier *ResponseClassifier) Decision {
			return classifier.Finish(ErrProbeTransportFailed, nil)
		}},
		{"missing protocol end", func(classifier *ResponseClassifier) Decision {
			return classifier.Finish(nil, nil)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			classifier := NewResponseClassifier(ObserveReal, model.EndpointMessages, 200, nil, headerAt)
			classifier.Observe(ProtocolEvent{Kind: EventSemantic, Semantic: true, SemanticKind: "text"})
			decision := tc.finish(classifier)
			if decision.Success {
				t.Fatalf("%s was treated as success", tc.name)
			}
			if !decision.Partial || decision.ErrorClass != model.ErrorPartial {
				t.Fatalf("partial=%v class=%v, want partial + partial_failure",
					decision.Partial, decision.ErrorClass)
			}
			if !decision.SemanticSeen {
				t.Fatal("SemanticSeen was lost")
			}
		})
	}
}

// HTTP 200 的流内结构化错误按错误码分类，不能因 200 判活。
func TestInStreamErrorsAreClassifiedByStructuredCode(t *testing.T) {
	tests := []struct {
		name       string
		event      ProtocolEvent
		capability model.CapabilityState
		class      model.ErrorClass
	}{
		{"overloaded is rate limited", ProtocolEvent{Kind: EventRemoteError,
			RedactedType: "overloaded_error"}, model.CapabilityTransientError, model.ErrorRateLimited},
		{"rate limit error", ProtocolEvent{Kind: EventRemoteError,
			RedactedType: "rate_limit_error"}, model.CapabilityTransientError, model.ErrorRateLimited},
		{"server error is transient", ProtocolEvent{Kind: EventRemoteError,
			RedactedType: "server_error"}, model.CapabilityTransientError, model.ErrorTransient},
		{"authentication error", ProtocolEvent{Kind: EventRemoteError,
			RedactedType: "authentication_error"}, model.CapabilityUnknown, model.ErrorAuthRejected},
		{"invalid request is a shape problem", ProtocolEvent{Kind: EventRemoteError,
			RedactedType: "invalid_request_error"}, model.CapabilityConfigError, model.ErrorShapeRejected},
		{"model not found", ProtocolEvent{Kind: EventRemoteError,
			RedactedType: "invalid_request_error", ErrorCode: "model_not_found"},
			model.CapabilityConfigError, model.ErrorModelNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			classifier := messagesClassifier(200)
			classifier.Observe(tc.event)
			decision := classifier.Finish(nil, nil)
			if decision.Success {
				t.Fatal("200 with an in-stream error was treated as success")
			}
			if decision.Capability != tc.capability || decision.ErrorClass != tc.class {
				t.Fatalf("capability=%v class=%v, want capability=%v class=%v",
					decision.Capability, decision.ErrorClass, tc.capability, tc.class)
			}
			if !decision.Reachable {
				t.Fatal("in-stream error must not affect reachability")
			}
		})
	}
}

// 客户端取消、暂停与关闭都是 ignored，不改变任何健康状态。
func TestCancellationCausesAreIgnored(t *testing.T) {
	for _, cause := range []error{ErrClientCanceled, ErrServicePaused, ErrServiceShutdown} {
		classifier := messagesClassifier(200)
		classifier.Observe(ProtocolEvent{Kind: EventMetadata, EventName: "message_start"})
		decision := classifier.Finish(nil, cause)
		if decision.ErrorClass != model.ErrorIgnored {
			t.Errorf("cause %v: class = %v, want ignored", cause, decision.ErrorClass)
		}
		if decision.Scope != model.ScopeNone {
			t.Errorf("cause %v: scope = %v, want none", cause, decision.Scope)
		}
		if decision.Success {
			t.Errorf("cause %v was treated as success", cause)
		}
	}
}

// 取消判定优先于流里已经出现的错误。
//
// 顺序反了的话，一次 pause 期间恰好收到 503 的探活会被记成上游故障，
// 于是「暂停探活」这个动作本身会制造健康数据 —— 而那是用户主动停的。
func TestCancellationWinsOverAnInStreamError(t *testing.T) {
	classifier := messagesClassifier(200)
	classifier.Observe(ProtocolEvent{Kind: EventRemoteError, RedactedType: "server_error"})
	decision := classifier.Finish(nil, ErrServicePaused)
	if decision.ErrorClass != model.ErrorIgnored {
		t.Fatalf("class = %v, want ignored", decision.ErrorClass)
	}
}

// 传输失败没有拿到响应头时不可达。
//
// 与「拿到了任意状态码」正好相反的一侧：status 为 0 表示连响应头都没到，
// 那才是 §8.9 允许短路本轮昂贵 L2 的唯一情形。
func TestTransportFailureBeforeHeadersIsUnreachable(t *testing.T) {
	decision := messagesClassifier(0).Finish(ErrProbeTransportFailed, nil)
	if decision.Reachable {
		t.Fatal("transport failure before headers reported reachable")
	}
	if decision.ErrorClass != model.ErrorUnreachable {
		t.Fatalf("class = %v, want unreachable", decision.ErrorClass)
	}
	if decision.Scope != model.ScopeUpstreamReachability {
		t.Fatalf("scope = %v, want upstream_reachability", decision.Scope)
	}
	if decision.Capability != model.CapabilityUnknown {
		t.Fatalf("capability = %v, want unknown (no evidence about the endpoint)", decision.Capability)
	}
}

// 首语义超时与无语义 EOF 都是 transient（§8.12）。
func TestSemanticTimeoutAndSilentEOFAreTransient(t *testing.T) {
	timeout := messagesClassifier(200).Finish(ErrProbeSemanticTimeout, nil)
	if timeout.Capability != model.CapabilityTransientError {
		t.Fatalf("semantic timeout capability = %v, want transient_error", timeout.Capability)
	}
	if timeout.Success {
		t.Fatal("semantic timeout was treated as success")
	}

	// 正常 EOF 但没有任何语义证据：站在协议上「完成」了，却什么都没说。
	// 这正是假活站的典型形态，§6.8 归为 fake_alive。
	silent := messagesClassifier(200)
	silent.Observe(ProtocolEvent{Kind: EventProtocolEnd, EventName: "message_stop"})
	if got := silent.Finish(nil, nil); got.ErrorClass != model.ErrorFakeAlive {
		t.Fatalf("silent normal end class = %v, want fake_alive", got.ErrorClass)
	}
}

// Decision 自己表达作用范围，调用方不再猜。
//
// 这是 P0-08 的核心交付：旧路径把 health.VerdictFatal 一路传到调用方，
// 由调用方按错误字符串猜「这是站的问题还是这个 Route 的问题」。
// 每个猜的地方都是一次可能的连坐。
func TestEveryDecisionCarriesAnExplicitScope(t *testing.T) {
	tests := []struct {
		name  string
		build func() Decision
		scope model.ObservationScope
	}{
		{"models endpoint is upstream scoped", func() Decision {
			classifier := modelsClassifier(200, nil)
			classifier.Observe(ProtocolEvent{Kind: EventModelList, ModelListRecognized: true, ModelCount: 1})
			return classifier.Finish(nil, nil)
		}, model.ScopeUpstreamEndpoint},
		{"model endpoint success is route scoped", func() Decision {
			classifier := messagesClassifier(200)
			classifier.Observe(ProtocolEvent{Kind: EventSemantic, Semantic: true, SemanticKind: "text"})
			return classifier.Finish(nil, nil)
		}, model.ScopeRouteEndpoint},
		{"transport failure is reachability scoped", func() Decision {
			return messagesClassifier(0).Finish(ErrProbeTransportFailed, nil)
		}, model.ScopeUpstreamReachability},
		{"ignored has no scope", func() Decision {
			return messagesClassifier(200).Finish(nil, ErrClientCanceled)
		}, model.ScopeNone},
		{"count_tokens is route scoped", func() Decision {
			classifier := NewResponseClassifier(ObserveProbe, model.EndpointCountTokens, 404, nil, headerAt)
			return classifier.Finish(nil, nil)
		}, model.ScopeRouteEndpoint},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.build().Scope; got != tc.scope {
				t.Fatalf("scope = %v, want %v", got, tc.scope)
			}
		})
	}
}

// RedactedDetail 只用结构化枚举拼装，永不含上游原文。
//
// §4.6 要求「所有 RedactedDetail 在构造时经过已知凭据扫描，调用方不能把
// 原始 error body 拼回去」。Decoder 已经不保留 message，这里守的是
// Classifier 不要自己造一个「看起来有用」的详情字段出来。
func TestRedactedDetailContainsOnlyStructuredFacts(t *testing.T) {
	classifier := messagesClassifier(400)
	classifier.Observe(ProtocolEvent{Kind: EventRemoteError, RedactedType: "invalid_request_error",
		ErrorCode: "missing_beta_header", ErrorField: "anthropic-beta"})
	detail := classifier.Finish(nil, nil).RedactedDetail
	for _, want := range []string{"invalid_request_error", "missing_beta_header"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("RedactedDetail %q does not mention %q", detail, want)
		}
	}
	if len(detail) > maxRedactedDetail {
		t.Fatalf("RedactedDetail length = %d, want at most %d", len(detail), maxRedactedDetail)
	}
}

// Finish 可以重复调用并返回同一结果。
//
// 与 Decoder.Finish 同样的理由：调用方会在 readErr 分支上再兜一次，
// 而第二次返回一个不同的 Decision 会让落库的那份与已经上报的那份不一致。
func TestFinishIsIdempotent(t *testing.T) {
	classifier := messagesClassifier(200)
	classifier.Observe(ProtocolEvent{Kind: EventSemantic, Semantic: true, SemanticKind: "text"})
	first := classifier.Finish(nil, nil)
	second := classifier.Finish(nil, nil)
	if first != second {
		t.Fatalf("Finish is not idempotent:\nfirst  = %+v\nsecond = %+v", first, second)
	}
}

// Observe 在已经终结之后不再改变结论。
//
// 探活在首个语义事件后主动断流，但在途字节仍会到达（Executor 关闭连接前
// 都会）。那些字节里可能有一个 error 事件 —— 让它翻掉已经成立的成功，
// 等于「取消得越慢，成功率越低」。
func TestObserveAfterFinalDoesNotChangeTheDecision(t *testing.T) {
	classifier := messagesClassifier(200)
	final, _ := classifier.Observe(ProtocolEvent{Kind: EventSemantic, Semantic: true, SemanticKind: "text"})
	classifier.Observe(ProtocolEvent{Kind: EventRemoteError, RedactedType: "server_error"})
	if got := classifier.Finish(nil, nil); got != final {
		t.Fatalf("late error changed the decision:\nfinal = %+v\ngot   = %+v", final, got)
	}
}

// 每个 Decision 的两个枚举都必须是契约内的值。
//
// 这条是兜底：任何一条分支忘了设 ErrorClass 或 Capability 都会在这里被逮到，
// 而空字符串会在 Store 落库时才失败 —— 那时已经看不出是哪条分支漏的。
func TestEveryDecisionUsesContractEnumValues(t *testing.T) {
	builders := []func() Decision{
		func() Decision { return modelsClassifier(200, nil).Finish(nil, nil) },
		func() Decision { return modelsClassifier(404, nil).Finish(nil, nil) },
		func() Decision { return modelsClassifier(429, nil).Finish(nil, nil) },
		func() Decision { return messagesClassifier(0).Finish(ErrProbeTransportFailed, nil) },
		func() Decision { return messagesClassifier(200).Finish(nil, ErrClientCanceled) },
		func() Decision { return messagesClassifier(200).Finish(ErrProbeSemanticTimeout, nil) },
		func() Decision {
			classifier := messagesClassifier(200)
			classifier.Observe(ProtocolEvent{Kind: EventSemantic, Semantic: true, SemanticKind: "text"})
			return classifier.Finish(nil, nil)
		},
		func() Decision {
			classifier := messagesClassifier(200)
			classifier.Observe(ProtocolEvent{Kind: EventRemoteError, RedactedType: "server_error"})
			return classifier.Finish(nil, nil)
		},
	}
	for index, build := range builders {
		decision := build()
		if !decision.Capability.Valid() {
			t.Errorf("builder %d: capability %q is not a contract value", index, decision.Capability)
		}
		if !decision.ErrorClass.Valid() {
			t.Errorf("builder %d: error class %q is not a contract value", index, decision.ErrorClass)
		}
		if !decision.Final {
			t.Errorf("builder %d: Finish returned Final=false", index)
		}
		if decision.StatusCode < 0 {
			t.Errorf("builder %d: negative status %d", index, decision.StatusCode)
		}
	}
}

// 新 Classifier 与 Decoder 不许导入 proxy。
//
// P0-08 的验收条款：「新 Classifier 不导入 proxy，proxy 也不导入 probe」。
// 反向边一旦成环，P0-13 接入真实流量时 proxy 需要调 probe 的 observer 就无路可走 ——
// 那时的解法只剩「把中立接口再抄一份到 proxy 里」，而两份判定必然分叉。
//
// 逐文件查而不是查整个包：classify.go / prober.go / reporter.go 那几个旧路径
// 文件**本来就**导入 proxy（P0-17 随它们一并删除），查包级依赖会永远是红的，
// 于是这条断言只能被删掉或者被忽略。要守的是「新增的这几个文件不新增反向边」。
func TestNewProbePipelineFilesDoNotImportProxy(t *testing.T) {
	newPipeline := []string{
		"classifier.go",
		"stream.go",
		"contentcoding.go",
	}
	for _, name := range newPipeline {
		t.Run(name, func(t *testing.T) {
			parsed, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}
			for _, imported := range parsed.Imports {
				path, err := strconv.Unquote(imported.Path.Value)
				if err != nil {
					t.Fatalf("unquote import %s: %v", imported.Path.Value, err)
				}
				if path == "github.com/279814/relay-gate/internal/proxy" {
					t.Fatalf("%s imports internal/proxy; the new pipeline must stay independent "+
						"so P0-13 can wire real traffic through a neutral interface", name)
				}
			}
		})
	}
}
