package sample

import (
	"bytes"
	"fmt"
)

// ellipsisFmt 是截断处的省略标记。
//
// 必须是**在 JSON 与 SSE 里都不会被误解**的形式：样本浏览器会尝试
// 按 JSON 高亮显示 body，一个裸的 "..." 会让它解析失败并显示成一团乱码。
// 用注释风格的标记，人一眼能看懂，机器也不会当成数据。
const ellipsisFmt = "\n/* …relay-gate: 省略 %d 字节… */\n"

// HeadTail 是「留头 + 留尾」的有界收集器，用于 SSE 响应体（§3.6.3c）。
//
// 为什么不能只留头：SSE 的诊断信息分布在两端 —— 头部有错误信息与首个 delta，
// 尾部有 message_stop 与 usage（真实 token 消耗）。只留头会丢掉「这次到底
// 花了多少 token」，而那正是公益站配额排查最需要的。
//
// 为什么不能先攒完再截：响应可达数 MB，攒完等于把内存上限交给上游决定。
// 这个类型的内存占用恒为 head+tail，与流的实际长度无关。
type HeadTail struct {
	head    []byte
	tail    []byte // 环形缓冲：只保留最后 tailMax 字节
	tailPos int    // 下一次写入的位置
	tailLen int    // 已填充长度（未绕回时 < len(tail)）

	headMax int
	total   int64
}

func NewHeadTail(headMax, tailMax int) *HeadTail {
	if headMax < 0 {
		headMax = 0
	}
	if tailMax < 0 {
		tailMax = 0
	}
	return &HeadTail{
		head:    make([]byte, 0, headMax),
		tail:    make([]byte, tailMax),
		headMax: headMax,
	}
}

// Write 收下一段字节。永不返回错误 —— 采集是旁路，
// 它的失败不该以任何形式传播到转发路径上。
func (h *HeadTail) Write(p []byte) (int, error) {
	h.total += int64(len(p))

	if n := h.headMax - len(h.head); n > 0 {
		if n > len(p) {
			n = len(p)
		}
		h.head = append(h.head, p[:n]...)
	}

	// 尾缓冲：只有最后 len(tail) 字节有意义，更早的直接丢
	if len(h.tail) > 0 {
		src := p
		if len(src) > len(h.tail) {
			src = src[len(src)-len(h.tail):]
		}
		// 按段 copy 而不是逐字节搬。这里在 SSE 的每个 chunk 上都会跑，
		// 逐字节版本对每个字节做一次取模和一次边界判断，把一个本该是
		// memmove 的操作变成了字节循环 —— 而这条路径的全部要求就是
		// 「别拖慢转发」。绕回最多切成两段，所以最多两次 copy。
		n := copy(h.tail[h.tailPos:], src)
		if n < len(src) {
			copy(h.tail, src[n:]) // 绕回，从头接着写
		}
		h.tailPos = (h.tailPos + len(src)) % len(h.tail)
		if h.tailLen += len(src); h.tailLen > len(h.tail) {
			h.tailLen = len(h.tail)
		}
	}
	return len(p), nil
}

// Total 返回流经的总字节数（不是保存的字节数）。
func (h *HeadTail) Total() int64 { return h.total }

// Truncated 表示是否真的丢了字节。
//
// 判据是「头 + 尾覆盖不住全长」。头尾**重叠**时不算截断：
// 那种情况下全文都在手上，只是分散在两个缓冲里（见 Bytes）。
func (h *HeadTail) Truncated() bool {
	return h.total > int64(len(h.head))+int64(h.tailLen)
}

// tailBytes 按写入顺序还原尾缓冲。
// 环形缓冲绕回后 tailPos 指向最老的字节，要从那里接起。
func (h *HeadTail) tailBytes() []byte {
	out := make([]byte, 0, h.tailLen)
	if h.tailLen == len(h.tail) {
		out = append(out, h.tail[h.tailPos:]...)
		out = append(out, h.tail[:h.tailPos]...)
	} else {
		out = append(out, h.tail[:h.tailLen]...)
	}
	return out
}

// Bytes 拼出最终留档内容。
//
// 三种情形，只有第三种插省略标记：
//  1. 头已含全文（total ≤ headMax）→ 直接返回头
//  2. 头尾重叠 → 去掉重叠段拼起来，**无损**还原全文。
//     这一支不是锦上添花：headMax 小而 tailMax 大时（例如 3 + 100），
//     一个 8 字节的响应其实被完整收下了，若只返回头就会静默丢 5 字节，
//     而样本的全部价值就在于「到底是哪些字节」。
//  3. 真的覆盖不住 → 头 + 省略标记 + 尾
//
// 前两种情形绝不插标记：否则短响应的样本也被污染，无法与真实字节比对。
func (h *HeadTail) Bytes() []byte {
	if int64(len(h.head)) >= h.total {
		return h.head
	}

	tail := h.tailBytes()
	if !h.Truncated() {
		overlap := int64(len(h.head)) + int64(len(tail)) - h.total
		out := make([]byte, 0, h.total)
		out = append(out, h.head...)
		return append(out, tail[overlap:]...)
	}

	omitted := h.total - int64(len(h.head)) - int64(len(tail))
	var buf bytes.Buffer
	buf.Grow(len(h.head) + len(tail) + 48)
	buf.Write(h.head)
	fmt.Fprintf(&buf, ellipsisFmt, omitted)
	buf.Write(tail)
	return buf.Bytes()
}

// PrepareBody 把一份 body 处理成可落库的形式：按上限截断 + 脱敏。
//
// 顺序是刻意的：**只脱敏会被留档的那一段**。反过来（先扫全量再截断）
// 要在最多 32MB 上逐 key 扫描，而其中除了前 limit 字节以外全部会被
// 立刻丢弃 —— 纯粹的浪费，且这段扫描跑在转发的收尾路径上，
// 与 §3.6.3a「采集绝不拖慢转发」直接冲突。默认 limit 是 256KB，
// 也就是说改这一处就把最坏情况的扫描量压到了原来的 1/128。
//
// 截断点可能落在一个 key 的中间，所以脱敏窗口比 limit 多留一个最长 key
// 的余量：这样任何会出现在留档里的 key 都完整落在窗口内、会被完整替换，
// 之后的截断至多切碎一个**掩码** —— 而掩码里没有秘密。
// 少了这个余量，一个恰好横跨截断点的 key 会有前半截以明文落库。
//
// limit <= 0 表示不限。
func PrepareBody(body []byte, keys []string, limit int) ([]byte, bool) {
	if limit <= 0 || len(body) <= limit {
		return RedactBodyKeys(body, keys), false
	}

	end := limit + longestKey(keys)
	if end > len(body) {
		end = len(body)
	}
	safe := RedactBodyKeys(body[:end], keys)
	if len(safe) > limit {
		safe = safe[:limit]
	}

	var buf bytes.Buffer
	buf.Grow(len(safe) + 48)
	buf.Write(safe)
	// 报的是被丢掉的**原始**字节数。脱敏是替换不是丢弃，不计入这里。
	fmt.Fprintf(&buf, ellipsisFmt, len(body)-limit)
	return buf.Bytes(), true
}

func longestKey(keys []string) int {
	max := 0
	for _, k := range keys {
		if len(k) > max {
			max = len(k)
		}
	}
	return max
}
