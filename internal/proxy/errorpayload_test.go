package proxy

import "testing"

// 这组测试的重心不在「能认出错误」，而在「**不会**把好响应当成错误」。
//
// 假阳性的代价是丢掉一个已经生成好的答案并重发，而且不报错 ——
// 表现为「偶尔慢一倍」，几乎不可能被联想到是网关自己丢的。
// 所以下面反例（must_not_be_error）的数量刻意多于正例。

func TestClassifyPayload_RealErrors(t *testing.T) {
	cases := []struct {
		name string
		ct   string
		body string
	}{
		{
			name: "SSE 显式 error 事件（Anthropic）",
			ct:   "text/event-stream",
			body: "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\"}}\n\n",
		},
		{
			name: "SSE 不带 event 行、直接吐 error（New API / One API 的常见形态）",
			ct:   "text/event-stream",
			body: "data: {\"error\":{\"message\":\"insufficient quota\"}}\n\n",
		},
		{
			name: "非流式 JSON 顶层 error",
			ct:   "application/json",
			body: `{"error":{"type":"invalid_request_error","message":"bad"}}`,
		},
		{
			name: "顶层 type=error",
			ct:   "application/json",
			body: `{"type":"error","message":"boom"}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyPayload([]byte(c.body), c.ct); got != payloadError {
				t.Errorf("应判定为错误载荷，得到 %v", got)
			}
		})
	}
}

// 核心防线：这些都**不是**错误，判错了就会丢掉一个好答案。
func TestClassifyPayload_MustNotBeError(t *testing.T) {
	cases := []struct {
		name string
		ct   string
		body string
		why  string
	}{
		{
			name: "流式逐 token 到达，某个 chunk 的内容恰好是 error 这个词",
			ct:   "text/event-stream",
			body: "event: content_block_delta\n" +
				`data: {"type":"content_block_delta","index":0,` +
				`"delta":{"type":"text_delta","text":"error"}}` + "\n\n",
			why: `子串匹配会在这里判错：文本值就是 error，于是字节里出现了未转义的 "error"。` +
				"而流式响应本来就是逐 token 到达的 —— 模型解释报错时，" +
				"「error」单独成一个 chunk 完全正常。这是子串判据最现实的假阳性",
		},
		{
			name: "OpenAI Chat 的 delta 内容恰好是 error",
			ct:   "text/event-stream",
			body: `data: {"choices":[{"delta":{"content":"error"}}]}` + "\n\n",
			why:  `同上，"content":"error" 里含未转义的 "error"`,
		},
		{
			name: "用户在问报错，模型复述了一段带 error 的 JSON",
			ct:   "text/event-stream",
			body: "event: content_block_delta\n" +
				`data: {"type":"content_block_delta","index":0,` +
				`"delta":{"type":"text_delta","text":"你这个 {\"error\":{\"code\":500}} 是因为…"}}` + "\n\n",
			why: "内容里的 error 是用户的对话，不是上游的错误。" +
				"（注意这一条**单靠子串匹配也不会**误判，因为 JSON 转义把引号变成了 \\\" —— " +
				"留着它是为了覆盖「内容含结构化错误」这个形状，真正卡住子串判据的是上面两条）",
		},
		{
			name: "正常的 message_start",
			ct:   "text/event-stream",
			body: "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\"}}\n\n",
			why:  "流刚开始，还看不出结论，必须放行",
		},
		{
			name: "OpenAI Chat 流式块",
			ct:   "text/event-stream",
			body: `data: {"choices":[{"delta":{"content":"hello"}}]}` + "\n\n",
			why:  "choices 说明已经在生成内容",
		},
		{
			name: "error 键显式为 null（不少实现会带这个字段）",
			ct:   "application/json",
			body: `{"error":null,"data":{"ok":true}}`,
			why:  "有 error 键不等于有错误，值为 null 是「没有错误」",
		},
		{
			name: "error 只出现在嵌套层",
			ct:   "application/json",
			body: `{"result":{"error":"这是内容里的字段"},"ok":true}`,
			why:  "只认顶层。嵌套层的 error 可能是模型返回的结构化数据",
		},
		{
			name: "被截断的半截 JSON",
			ct:   "text/event-stream",
			body: `data: {"type":"content_block_delta","delta":{"text":"未读完`,
			why:  "peek 的边界切在中间。解析不了就别猜，拿不准一律放行",
		},
		{
			name: "空响应前缀",
			ct:   "text/event-stream",
			body: "",
			why:  "还没读到任何东西",
		},
		{
			name: "纯文本非 JSON",
			ct:   "text/plain",
			body: "internal server error",
			why:  "这里只判 200 响应体。非 JSON 说不出结论，交给状态码那条路径",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyPayload([]byte(c.body), c.ct); got == payloadError {
				t.Errorf("不该判成错误载荷 —— %s", c.why)
			}
		})
	}
}

// 事件顺序：内容先出现，后面即使跟着 error 也不该重试。
//
// 这时字节已经在往客户端写了（§3.5：写出字节后禁止重试），
// 而且丢掉一个「生成到一半才出错」的响应比原样传给客户端更糟 ——
// 客户端至少能看到已经生成的部分。
func TestClassifyPayload_ContentBeforeErrorWins(t *testing.T) {
	body := "event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"开始回答"}}` + "\n\n" +
		"event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\"}}\n\n"

	if got := classifyPayload([]byte(body), "text/event-stream"); got != payloadContent {
		t.Errorf("内容先于错误出现时应判 payloadContent（不可重试），得到 %v", got)
	}
}

// 反过来：错误在最前面，就是可重试的那一类。
func TestClassifyPayload_ErrorBeforeContentIsRetryable(t *testing.T) {
	body := "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\"}\n\n"

	if got := classifyPayload([]byte(body), "text/event-stream"); got != payloadError {
		t.Errorf("错误先出现应判 payloadError，得到 %v", got)
	}
}
