package probe

// Decoder 与 Classifier 的接缝回归。
//
// 为什么要单开一个文件：stream_test.go 只看 Decoder 吐出的事件，
// decision_test.go 只喂手写事件给 Classifier，两边各自都是绿的 —— 而这三条
// 缺陷全部长在接缝上，也就是「Decoder 实际发出的事件」与「Classifier 以为
// 会收到的事件」之间的差。手写事件测不出这种差，因为事件是我们自己编的：
// 编的时候用的正是 Classifier 那一侧的假设。
//
// decision_fixture_test.go 用真实抓包跑同一条接缝，但它只覆盖语料里存在的
// 形态。这里补的是语料没有、而生产一定会遇到的三种：非流式正文、Real 模式的
// 完整 Anthropic 流、上游把散文塞进 type 字段。

import (
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

// classifyWire 按真实字节跑完 Decoder→Classifier 全程。
//
// 不在首个 final 处停：这几条断言要看的正是「完整流跑完之后的结论」，
// 而 Probe 模式提前收工会掩盖后面事件的缺失（Real 模式的 message_stop
// 恰恰在语义之后才到）。
func classifyWire(t *testing.T, mode ObservationMode, spec DecoderSpec,
	format WireFormat, wire string) Decision {

	t.Helper()
	decoder, err := NewDecoder(spec, format, 0, 0)
	if err != nil {
		t.Fatalf("new decoder: %v", err)
	}
	classifier := NewResponseClassifier(mode, spec.Endpoint, 200, nil, headerAt)

	events, err := decoder.Feed([]byte(wire))
	if err != nil {
		t.Fatalf("feed: %v", err)
	}
	for _, event := range events {
		classifier.Observe(event)
	}
	tail, err := decoder.Finish()
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	for _, event := range tail {
		classifier.Observe(event)
	}
	return classifier.Finish(nil, nil)
}

// count_tokens 的 input_tokens 必须进 Decision 的 token 汇总。
//
// Decoder 把它放在 EventSemantic 上（那是 count_tokens 唯一的成功证据），
// 而 Classifier 只在 EventUsage 分支累加 token —— 于是这个数字在真实字节
// 路径上一直是 0。decision_test.go 手写的是 `{Kind: EventUsage, InputTokens: 8}`，
// 一个 Decoder 从不产生的组合，所以那条断言测的是一条死路。
//
// 后果落在成本上：§5.2d 要求 ProbeExecution 记录 ObservedInputTokens，
// 而 count_tokens 是**唯一**会产生 input token 的探活端点（其余端点的 usage
// 只带 output）。这一路丢失等于「探活到底花了多少钱」永远少算一整类。
func TestCountTokensInputTokensReachTheDecision(t *testing.T) {
	spec := DecoderSpec{Endpoint: model.EndpointCountTokens, Protocol: model.ProtoAnthropic}
	decision := classifyWire(t, ObserveProbe, spec, WireJSON, `{"input_tokens":8}`)

	if !decision.Success {
		t.Fatalf("count_tokens 200 with positive input_tokens was not success: %+v", decision)
	}
	if decision.ObservedInputTokens != 8 {
		t.Fatalf("ObservedInputTokens = %d, want 8", decision.ObservedInputTokens)
	}
	if decision.ObservedOutputTokens != 0 {
		t.Fatalf("count_tokens reported %d output tokens, want 0",
			decision.ObservedOutputTokens)
	}
}

// 带内容的 delta 同时带 usage 时，token 也必须记上。
//
// 与上一条同源：EventSemantic 上的 token 被丢掉。非流式 chat 的 200 正文
// 就是这种形态（content 与 usage 在同一个 JSON 对象里），而它是
// chat_completions 端点最常见的响应 —— 一个 stream_expected=false 的站
// 每次探活都会走到。
func TestSemanticEventTokensAreNotDropped(t *testing.T) {
	spec := DecoderSpec{Endpoint: model.EndpointChatCompletions, Protocol: model.ProtoOpenAIChat}
	body := `{"choices":[{"message":{"content":"hi"}}],"usage":{"completion_tokens":5}}`
	decision := classifyWire(t, ObserveProbe, spec, WireJSON, body)

	if !decision.Success {
		t.Fatalf("non-streaming chat content was not success: %+v", decision)
	}
	if decision.ObservedOutputTokens != 5 {
		t.Fatalf("ObservedOutputTokens = %d, want 5", decision.ObservedOutputTokens)
	}
}

// Real 模式必须承认各协议真正的结束标记。
//
// Classifier 的 normalEndSeen 只由 EventProtocolEnd 置位，而 Decoder 只对
// `[DONE]`/`done` 发这个事件 —— Anthropic 从不发 [DONE]（它以 message_stop
// 结束），Responses 以 response.completed 结束，非流式 JSON 压根没有结束事件。
// 于是这三种形态在 Real 模式下全部落到 partial_failure。
//
// 后果是 §6.8 里最不该出错的那条：partial 表示「客户端已经收到部分内容」，
// 要求累计 Route 失败且绝不重试。一个完全正常的站会被每次真实请求都记一次
// 失败，攒够阈值后判死 —— 而它从头到尾都在正确工作。P0-13 接入真实流量的
// 那一刻，全部 Anthropic 站会一起开始掉血。
func TestRealModeAcceptsEachProtocolsOwnTerminalEvent(t *testing.T) {
	tests := []struct {
		name   string
		spec   DecoderSpec
		format WireFormat
		wire   string
	}{
		{
			name:   "anthropic message_stop",
			spec:   DecoderSpec{Endpoint: model.EndpointMessages, Protocol: model.ProtoAnthropic},
			format: WireSSE,
			wire: "event: content_block_delta\ndata: {\"type\":\"content_block_delta\"," +
				"\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n" +
				"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
		},
		{
			name:   "responses response.completed",
			spec:   DecoderSpec{Endpoint: model.EndpointResponses, Protocol: model.ProtoOpenAIResponses},
			format: WireSSE,
			wire: "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\"," +
				"\"delta\":\"hi\"}\n\n" +
				"event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n",
		},
		{
			// 非流式正文自己就是完整响应：整份 JSON 到手即协议结束，
			// 没有也不需要一个单独的结束事件。
			name:   "non-streaming chat body",
			spec:   DecoderSpec{Endpoint: model.EndpointChatCompletions, Protocol: model.ProtoOpenAIChat},
			format: WireJSON,
			wire:   `{"choices":[{"message":{"content":"hi"}}]}`,
		},
		{
			name:   "non-streaming count_tokens body",
			spec:   DecoderSpec{Endpoint: model.EndpointCountTokens, Protocol: model.ProtoAnthropic},
			format: WireJSON,
			wire:   `{"input_tokens":8}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decision := classifyWire(t, ObserveReal, tc.spec, tc.format, tc.wire)
			if decision.Partial {
				t.Fatalf("a complete response was judged partial: detail=%q", decision.RedactedDetail)
			}
			if !decision.NormalEndSeen {
				t.Fatal("NormalEndSeen = false on a normally terminated response")
			}
			if !decision.Success || decision.ErrorClass != model.ErrorNone {
				t.Fatalf("success=%v class=%q, want success with no error class",
					decision.Success, decision.ErrorClass)
			}
		})
	}
}

// 截断的正文绝不能算「协议正常结束」。
//
// 这是上一条修复的安全边界，必须单独钉住：非流式正文之所以能算正常结束，
// 全靠「整份 JSON 解析成功」这个前提。若哪天为了让 Real 模式好过而把
// EventProtocolEnd 提前到解析之前，一个被中途掐断的响应就会变成成功 ——
// 而 §6.8 要求截断必须表达为 partial（客户端已经收到半份内容）。
// 那个方向的错误比原缺陷更糟：原缺陷是把好站判坏，这个是把坏站判好。
func TestTruncatedBodyIsNeverANormalEnd(t *testing.T) {
	spec := DecoderSpec{Endpoint: model.EndpointChatCompletions, Protocol: model.ProtoOpenAIChat}
	decoder, err := NewDecoder(spec, WireJSON, 0, 0)
	if err != nil {
		t.Fatalf("new decoder: %v", err)
	}
	classifier := NewResponseClassifier(ObserveReal, spec.Endpoint, 200, nil, headerAt)

	// 半份 JSON：花括号没闭合。
	events, err := decoder.Feed([]byte(`{"choices":[{"message":{"content":"hi"`))
	if err != nil {
		t.Fatalf("feed: %v", err)
	}
	for _, event := range events {
		classifier.Observe(event)
	}
	if _, err := decoder.Finish(); err == nil {
		t.Fatal("Finish accepted a truncated JSON body")
	}

	decision := classifier.Finish(ErrProbeTransportFailed, nil)
	if decision.NormalEndSeen {
		t.Fatal("a truncated body was recorded as a normal protocol end")
	}
	if decision.Success {
		t.Fatalf("a truncated body was treated as success: %+v", decision)
	}
}

// 上游的散文不能借 error type/code 字段进 RedactedDetail。
//
// §2.4 与 §4.6 要求详情只由结构化枚举拼装，而 Decoder 是**逐字**抄
// `error.type` 与 `error.code` 的 —— 那两个字段的内容由上游完全控制。
// 一个把说明文字（乃至 key 本身）写进 type 的站，那段文字会原样进
// probe_execution.redacted_detail，也就是进日志、API 响应和 UI。
//
// 判据是「只接受结构化标识符的字符集」而不是「不等于某个具体串」：
// 要挡的是任意散文，而挡法只能是白名单 —— 黑名单永远漏下一种拼法。
func TestUpstreamProseCannotEnterRedactedDetail(t *testing.T) {
	spec := DecoderSpec{Endpoint: model.EndpointMessages, Protocol: model.ProtoAnthropic}
	credential := "sk-ant-api03-" + strings.Repeat("Z", 24)
	wire := "event: error\ndata: {\"type\":\"error\",\"error\":{" +
		"\"type\":\"your key " + credential + " is out of quota\"," +
		"\"code\":\"code with spaces\"}}\n\n"

	decision := classifyWire(t, ObserveProbe, spec, WireSSE, wire)

	if strings.Contains(decision.RedactedDetail, credential) {
		t.Fatalf("RedactedDetail carries an upstream credential: %q", decision.RedactedDetail)
	}
	for _, character := range decision.RedactedDetail {
		if character == ' ' {
			t.Fatalf("RedactedDetail %q contains prose (a space); only structured "+
				"identifiers are allowed", decision.RedactedDetail)
		}
	}
}
