package probe

import (
	"bufio"
	"bytes"
	"io"
)

// lifeMarkers 是「模型真的在生成内容」的证据。
//
// 三种协议的事件结构不同，但都能归结为「出现了一个内容增量」：
//   - Anthropic：text_delta / thinking_delta / input_json_delta
//   - OpenAI Chat：choices[].delta.content
//   - OpenAI Responses：response.output_text.delta
//
// 用子串匹配而不是完整反序列化：每个事件都解一次 JSON 既慢，又要为三种
// 协议各写一套结构体，而中转站的实现常有细微偏差（多一个字段、少一个字段），
// 严格解析会因为无关的差异而判失败。这里只需要一个是/否的答案。
var lifeMarkers = [][]byte{
	// Anthropic
	[]byte(`"text_delta"`),
	[]byte(`"thinking_delta"`),
	[]byte(`"input_json_delta"`),
	[]byte(`"content_block_delta"`),
	// OpenAI Responses
	[]byte(`"response.output_text.delta"`),
	[]byte(`"response.reasoning_summary_text.delta"`),
	// OpenAI Chat：delta 里带 content 或 reasoning_content
	[]byte(`"content":"`),
	[]byte(`"reasoning_content":"`),
	// 工具调用也是生成，只是内容不是文字
	[]byte(`"tool_calls"`),
	[]byte(`"function_call"`),
}

// usageMarkers 是「产生了 token」的旁证。
//
// 为什么需要它：探活用 max_tokens=1，个别站会在生成第一个 token 后
// 立刻收尾，把内容合并进结束事件而不单发 delta。只认 delta 的话，
// 这类站会被误判成假活 —— 而它其实完全可用。
var usageMarkers = [][]byte{
	[]byte(`"output_tokens"`),
	[]byte(`"completion_tokens"`),
}

// streamResult 是扫描 SSE 流得到的结论。
type streamResult struct {
	// alive 表示看到了内容增量（或 token 用量），可以立即断流。
	alive bool
	// errPayload 是 `event: error` 携带的 data。非空时由调用方再分类 ——
	// 流内错误可能是 overloaded（限流），也可能是真故障，两者处置相反。
	errPayload []byte
	// bytesRead 是已读取的字节数，用于区分「一个字节都没有」与「有内容但无效」。
	bytesRead int64
	// scanErr 是读流时的 I/O 错误（连接被切断、首 Token 超时导致的 ctx 取消）。
	//
	// 必须带出来：不带的话「读到 EOF 但没有有效内容」与「读的过程中出错了」
	// 两种情况在调用方看起来完全一样，于是都被报成「假活」。前者确实是假活，
	// 后者是超时或断流 —— 报错原因指错了方向，排查就会从「站为什么不吐内容」
	// 开始，而真正该看的是「连接为什么断了」。
	scanErr error
}

// maxStreamScan 是扫描上限。
//
// 探到结果就断流是常规路径（§4.1），这个上限防的是异常情况：
// 一个不断吐无效事件（心跳、ping）却永远不出内容的站，会让探活
// 一直读下去直到超时。读满上限就当假活处理。
const maxStreamScan = 256 << 10

// scanStream 读 SSE 流直到判定出结果，然后立即返回让调用方断流。
//
// 这是 §4.1「读到首个有效事件后立即 cancel + Body.Close 主动断流」的实现：
// 不断流的话每次探活都会把 max_tokens 耗完，探活成本翻倍 ——
// 而对一个每 30 秒探一次的死站来说，那是持续的浪费。
//
// onFirstByte 在收到第一个字节时回调一次，用于测 TTFT。
func scanStream(r io.Reader, onFirstByte func()) streamResult {
	var res streamResult
	sc := bufio.NewScanner(r)
	// SSE 的单行可能很长（一个 delta 事件里嵌完整的 JSON），
	// 默认 64KB 的行上限对 message_start 这类事件不够用。
	sc.Buffer(make([]byte, 0, 8<<10), 1<<20)

	var curEvent []byte
	firstByteSeen := false

	for sc.Scan() {
		line := sc.Bytes()
		res.bytesRead += int64(len(line)) + 1

		if !firstByteSeen && len(line) > 0 {
			firstByteSeen = true
			if onFirstByte != nil {
				onFirstByte()
			}
		}

		switch {
		case len(line) == 0:
			// 事件边界。event 名的作用域到此为止。
			curEvent = nil

		case bytes.HasPrefix(line, []byte("event:")):
			curEvent = bytes.TrimSpace(line[len("event:"):])

		case bytes.HasPrefix(line, []byte("data:")):
			data := bytes.TrimSpace(line[len("data:"):])

			// 错误事件：交给调用方分类，不在这里判死 ——
			// `overloaded_error` 是限流（冷却），`invalid_model` 是致命，
			// 两者的处置完全相反。
			if bytes.Equal(curEvent, []byte("error")) || isErrorPayload(data) {
				res.errPayload = append([]byte(nil), data...)
				return res
			}
			if hasAny(data, lifeMarkers) || hasAny(data, usageMarkers) {
				res.alive = true
				return res // 判定已出，立即断流，不再消耗上游 token
			}
		}

		if res.bytesRead > maxStreamScan {
			return res
		}
	}
	// Scanner 把读错误藏在 Err() 里：Scan() 只返回 false，与正常 EOF 无法区分。
	// 不取出来的话超时与断流都会被当成「读完了但没内容」。
	res.scanErr = sc.Err()
	return res
}

// isErrorPayload 识别没有 `event: error` 头、只在 data 里表达错误的实现。
//
// 必须容忍这种形态：New API / One API 在流中途出错时经常直接吐
// `data: {"error":{...}}` 而不带 event 行。只认 event 头的话，
// 这类失败会被读到 EOF 然后当成「无内容假活」—— 结论碰巧对了，
// 但错误原因丢了，UI 上只能显示「无有效内容」而不是上游给的真实原因。
func isErrorPayload(data []byte) bool {
	if !bytes.HasPrefix(data, []byte("{")) {
		return false
	}
	return bytes.Contains(data, []byte(`"error"`)) ||
		bytes.Contains(data, []byte(`"type":"error"`))
}

func hasAny(b []byte, markers [][]byte) bool {
	for _, m := range markers {
		if bytes.Contains(b, m) {
			return true
		}
	}
	return false
}
