package proxy

import (
	"bytes"
)

// maxSniffLine 是嗅探器单行上限。
//
// 与 §15 / 资源上限里的「单个 SSE 事件」同量级。超长行多半是异常或恶意输入，
// 为嗅探撑住整行会把内存交给上游；丢掉这一行最多漏判，假阳性更糟。
const maxSniffLine = 256 << 10

// streamErrorSniffer 在 2xx SSE 流上增量嗅探协议错误事件（§6.8 / §8.12）。
//
// 与 classifySSEPrefix 的差异：重试侧「先看到内容就收手」（字节已在写给
// 客户端，禁止换站）；健康侧必须继续扫 —— 语义输出之后的 error 事件是
// partial_failure，不得仅因 HTTP 200 判活并 piggyback。
//
// 判据与 errorpayload 一致：只认 `event: error` 与顶层结构化 error 载荷，
// 绝不子串匹配正文里的 "error"。Feed 放在客户端 flush 之后，不推迟写出。
type streamErrorSniffer struct {
	lineBuf  []byte
	curEvent []byte
	sample   []byte
	done     bool
}

// Feed 吞下一块已写出的响应字节。可跨 chunk 拼行；找到协议错误后不再处理。
func (s *streamErrorSniffer) Feed(chunk []byte) {
	if s == nil || s.done || len(chunk) == 0 {
		return
	}
	s.lineBuf = append(s.lineBuf, chunk...)
	for {
		i := bytes.IndexByte(s.lineBuf, '\n')
		if i < 0 {
			if len(s.lineBuf) > maxSniffLine {
				s.lineBuf = s.lineBuf[:0]
				s.curEvent = nil
			}
			return
		}
		line := s.lineBuf[:i]
		s.lineBuf = s.lineBuf[i+1:]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		s.consumeLine(line)
		if s.done {
			s.lineBuf = nil
			return
		}
	}
}

func (s *streamErrorSniffer) consumeLine(line []byte) {
	if len(bytes.TrimSpace(line)) == 0 {
		s.curEvent = nil
		return
	}
	switch {
	case bytes.HasPrefix(line, []byte("event:")):
		s.curEvent = append([]byte(nil), bytes.TrimSpace(line[len("event:"):])...)
	case bytes.HasPrefix(line, []byte("data:")):
		data := bytes.TrimSpace(line[len("data:"):])
		// Anthropic 显式错误事件：认事件名，仍要求 data 是 JSON 对象
		// （半截 data 说明 chunk 边界切在中间，等下一行）。
		if bytes.Equal(s.curEvent, []byte("error")) && looksLikeJSONObject(data) {
			s.captureErrorFrame(true, data)
			return
		}
		// OpenAI 等：无 event 行、data 顶层带非 null error / type=error。
		if classifyJSONObject(data) == payloadError {
			s.captureErrorFrame(false, data)
		}
	}
}

func (s *streamErrorSniffer) captureErrorFrame(anthropicEvent bool, data []byte) {
	var b bytes.Buffer
	if anthropicEvent {
		b.WriteString("event: error\ndata: ")
	} else {
		b.WriteString("data: ")
	}
	b.Write(data)
	b.WriteString("\n\n")
	sample := b.Bytes()
	if len(sample) > maxErrBodyCapture {
		sample = sample[:maxErrBodyCapture]
	}
	s.sample = append([]byte(nil), sample...)
	s.done = true
}

// Sample 返回供 classifyReal 使用的最小错误事件帧；未找到时为 nil。
func (s *streamErrorSniffer) Sample() []byte {
	if s == nil {
		return nil
	}
	return s.sample
}

// Found 报告是否已确认协议错误事件。
func (s *streamErrorSniffer) Found() bool {
	return s != nil && s.done && len(s.sample) > 0
}
