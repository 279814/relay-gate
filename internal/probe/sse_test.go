package probe

import (
	"strings"
	"testing"
)

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// 三种协议的存活标志都要认。漏一种的后果是那个协议下的所有站
// 都被判成假活 —— 整批好站被踢出池子。
func TestScanStream_DetectsLifeAcrossProtocols(t *testing.T) {
	tests := []struct {
		name string
		sse  string
	}{
		{
			"Anthropic text_delta",
			"event: content_block_delta\n" +
				`data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"2"}}` + "\n\n",
		},
		{
			"Anthropic thinking_delta（长思考先吐思考过程）",
			"event: content_block_delta\n" +
				`data: {"type":"content_block_delta","delta":{"type":"thinking_delta","thinking":"嗯"}}` + "\n\n",
		},
		{
			"OpenAI Chat delta.content",
			`data: {"choices":[{"delta":{"content":"2"}}]}` + "\n\n",
		},
		{
			"OpenAI Chat reasoning_content",
			`data: {"choices":[{"delta":{"reasoning_content":"思考"}}]}` + "\n\n",
		},
		{
			"OpenAI Responses output_text.delta",
			"event: response.output_text.delta\n" +
				`data: {"type":"response.output_text.delta","delta":"2"}` + "\n\n",
		},
		{
			"工具调用也算生成",
			`data: {"choices":[{"delta":{"tool_calls":[{"index":0}]}}]}` + "\n\n",
		},
		{
			// max_tokens=1 时个别站不单发 delta，直接在收尾事件里给 usage。
			// 只认 delta 会把这类可用站误判成假活。
			"只有 usage 也算活着",
			"event: message_delta\n" +
				`data: {"type":"message_delta","usage":{"output_tokens":1}}` + "\n\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := scanStream(strings.NewReader(tc.sse), nil)
			if !res.alive {
				t.Errorf("应判为存活，得到 alive=false errPayload=%q", res.errPayload)
			}
		})
	}
}

// 假活形态一：200 + SSE 但没有任何内容增量。
// 只看状态码会把它当成好站，而它完全不可用（§4.3）。
func TestScanStream_FakeAliveWithNoDelta(t *testing.T) {
	sse := "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"x","content":[]}}` + "\n\n" +
		"event: message_stop\n" +
		`data: {"type":"message_stop"}` + "\n\n"

	res := scanStream(strings.NewReader(sse), nil)
	if res.alive {
		t.Error("无任何内容增量应判为假活")
	}
	if len(res.errPayload) > 0 {
		t.Errorf("没有 error 事件，errPayload 应为空，得到 %q", res.errPayload)
	}
	if res.bytesRead == 0 {
		t.Error("应记录已读字节数，用于区分「空响应」与「有内容但无效」")
	}
}

// 假活形态二：200 + 流内 error 事件。
func TestScanStream_CapturesErrorEvent(t *testing.T) {
	sse := "event: error\n" +
		`data: {"type":"error","error":{"type":"overloaded_error","message":"busy"}}` + "\n\n"

	res := scanStream(strings.NewReader(sse), nil)
	if res.alive {
		t.Error("error 事件不该判为存活")
	}
	if !contains(string(res.errPayload), "overloaded_error") {
		t.Errorf("应捕获错误原文供后续分类，得到 %q", res.errPayload)
	}
}

// 不带 event 行、只在 data 里表达错误的形态也要认。
// New API / One API 流中途出错时经常这样，只认 event 头会丢掉错误原因。
func TestScanStream_CapturesBareErrorPayload(t *testing.T) {
	sse := `data: {"error":{"message":"upstream load balancer error","code":"no_available_channel"}}` + "\n\n"

	res := scanStream(strings.NewReader(sse), nil)
	if res.alive {
		t.Error("裸 error payload 不该判为存活")
	}
	if !contains(string(res.errPayload), "no_available_channel") {
		t.Errorf("应捕获错误原文，得到 %q", res.errPayload)
	}
}

// 完全空的响应体（连 SSE 框架都没有）。
func TestScanStream_EmptyBody(t *testing.T) {
	res := scanStream(strings.NewReader(""), nil)
	if res.alive {
		t.Error("空响应体不该判为存活")
	}
	if res.bytesRead != 0 {
		t.Errorf("空响应体应读到 0 字节，得到 %d", res.bytesRead)
	}
}

// 判定一出就立即返回，不把流读完 —— 这是 §4.1「主动断流不再消耗
// 上游 token」的前提。读完才判的话，探活成本等于一次完整生成。
func TestScanStream_StopsAtFirstVerdict(t *testing.T) {
	head := "event: content_block_delta\n" +
		`data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"2"}}` + "\n\n"
	tail := strings.Repeat("event: content_block_delta\ndata: {\"x\":1}\n\n", 5000)

	r := strings.NewReader(head + tail)
	res := scanStream(r, nil)

	if !res.alive {
		t.Fatal("应判为存活")
	}
	if res.bytesRead >= int64(len(head)+len(tail)) {
		t.Errorf("判定出结果后就该停止读取，却读了 %d 字节（总长 %d）",
			res.bytesRead, len(head)+len(tail))
	}
	if r.Len() == 0 {
		t.Error("流应仍有剩余未读 —— 否则说明读到了 EOF，白耗了上游 token")
	}
}

// 一个不断吐心跳却永不出内容的站，不能让探活一直读到超时。
func TestScanStream_BailsOutOnEndlessNoise(t *testing.T) {
	noise := strings.Repeat("event: ping\ndata: {}\n\n", 200000)
	res := scanStream(strings.NewReader(noise), nil)

	if res.alive {
		t.Error("只有心跳不该判为存活")
	}
	if res.bytesRead > maxStreamScan*2 {
		t.Errorf("应在扫描上限附近停下，却读了 %d 字节", res.bytesRead)
	}
}

// TTFT 只在收到第一个非空行时回调一次。
func TestScanStream_FirstByteCallbackFiresOnce(t *testing.T) {
	sse := "event: message_start\ndata: {}\n\n" +
		"event: content_block_delta\n" +
		`data: {"delta":{"type":"text_delta","text":"2"}}` + "\n\n"

	var calls int
	scanStream(strings.NewReader(sse), func() { calls++ })
	if calls != 1 {
		t.Errorf("首字节回调应只触发一次，得到 %d 次", calls)
	}
}

// 单个 SSE 事件可以很长（message_start 里嵌完整的 message 结构）。
// 行缓冲不够大会让扫描直接失败，把好站判成假活。
func TestScanStream_HandlesVeryLongLines(t *testing.T) {
	padding := strings.Repeat("a", 200<<10)
	sse := "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"` + padding + `"}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"delta":{"type":"text_delta","text":"2"}}` + "\n\n"

	res := scanStream(strings.NewReader(sse), nil)
	if !res.alive {
		t.Error("超长事件行不该导致扫描失败（会把好站误判成假活）")
	}
}

// event 名的作用域到空行为止。不重置的话，一个 error 事件之后的
// 所有 data 行都会被当成 error 内容。
func TestScanStream_EventNameScopeEndsAtBlankLine(t *testing.T) {
	sse := "event: ping\n\n" +
		`data: {"delta":{"type":"text_delta","text":"2"}}` + "\n\n"

	res := scanStream(strings.NewReader(sse), nil)
	if !res.alive {
		t.Error("空行后 event 名应已重置，该 data 应正常参与存活判定")
	}
}

func TestStreamErrStatus(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    int
	}{
		// 上游自报状态码时用它，能让流内的 401 也走到 Fatal 分支
		{"error.code", `{"error":{"code":401,"message":"bad key"}}`, 401},
		{"error.status", `{"error":{"status":429}}`, 429},
		{"无状态码时用 500 占位", `{"error":{"message":"boom"}}`, 500},
		{"非 JSON", `boom`, 500},
		{"越界的 code 忽略", `{"error":{"code":99}}`, 500},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := streamErrStatus([]byte(tc.payload)); got != tc.want {
				t.Errorf("payload %q：期望 %d，得到 %d", tc.payload, tc.want, got)
			}
		})
	}
}
