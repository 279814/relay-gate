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

// HeadTail 是响应体的收集器，用于 SSE 响应体（§3.6.3c）。有两种模式：
//
// **完整模式**（headMax 与 tailMax 都为 0，即当前默认）：一字不差地全收。
// 留档的价值就在「到底是哪些字节」—— 截断过的样本没法拿去与入站请求逐字段
// 比对，而那是 §3.6.1 给这个功能定的头号用途。代价是内存占用等于响应大小，
// 且**由上游决定**：每个在途请求都会在 RAM 里攒一份完整副本。
//
// **有界模式**（任一为正）：留头 + 留尾，中间省略。
// 为什么不能只留头：SSE 的诊断信息分布在两端 —— 头部有错误信息与首个 delta，
// 尾部有 message_stop 与 usage（真实 token 消耗）。只留头会丢掉「这次到底
// 花了多少 token」，而那正是公益站配额排查最需要的。
// 这个模式下内存占用恒为 head+tail，与流的实际长度无关。
//
// **磁盘配额**（§5.4）：完整模式下可经 LimitToRemaining 附上剩余配额。
// 一旦继续全收会超过剩余配额，当场改成留头留尾，而不是先把整段流
// 攒进内存再等 PruneSamples 事后删 —— 事后删救不了峰值 RAM。
type HeadTail struct {
	head    []byte
	tail    []byte // 环形缓冲：只保留最后 tailMax 字节
	tailPos int    // 下一次写入的位置
	tailLen int    // 已填充长度（未绕回时 < len(tail)）

	headMax int
	// full 表示完整模式。用一个显式字段而不是靠 headMax==0 现判：
	// headMax=0 且 tailMax>0 是有意义的有界配置（只留最后 N 字节），
	// 与「不限」是两回事。混为一谈的话，「只留尾」会静默变成「全留」。
	full  bool
	total int64

	// budgetOn / budget：完整模式下的剩余样本磁盘配额（§5.4）。
	// 超限时切到有界头尾；切过后 budgetOn 清掉，后续走普通有界路径。
	budgetOn      bool
	budget        int64
	overflowHead  int // 配置的头上限（SampleRespHeadBytes）；0 保持 0，不另造长度
	overflowTail  int
	quotaOverflow bool // 是否因配额从完整模式切到了头尾
}

// NewHeadTail 构造收集器。headMax 与 tailMax **同时为 0** 表示完整保留；
// 任一为正则是有界的留头留尾。负数按 0 处理。
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
		full:    headMax == 0 && tailMax == 0,
	}
}

// LimitToRemaining 给完整模式挂上 §5.4 剩余磁盘配额。
//
// remaining 是「本条响应体还能占用的字节」：总配额减去已用再减去本条
// 即将写入的 in/out body。负数按 0（已无空间）处理。
//
// overflowHead / overflowTail 是配置的 sample_resp_head/tail_bytes：
// 超限时切到这对头尾。两者仍为 0 时保持 0 —— 不另造魔法长度；
// 仍会标记截断并停止全收，只是头尾缓冲为空。
//
// 非完整模式（调用方已配置了正的头尾）原样返回 —— 内存本就有界。
func (h *HeadTail) LimitToRemaining(remaining int64, overflowHead, overflowTail int) *HeadTail {
	if h == nil || !h.full {
		return h
	}
	if remaining < 0 {
		remaining = 0
	}
	if overflowHead < 0 {
		overflowHead = 0
	}
	if overflowTail < 0 {
		overflowTail = 0
	}
	h.budgetOn = true
	h.budget = remaining
	h.overflowHead = overflowHead
	h.overflowTail = overflowTail
	if remaining == 0 {
		h.switchFromFull(nil)
	}
	return h
}

// QuotaOverflow 表示是否因剩余磁盘配额从完整模式切到了头尾（§5.4）。
func (h *HeadTail) QuotaOverflow() bool {
	return h != nil && h.quotaOverflow
}

// Write 收下一段字节。永不返回错误 —— 采集是旁路，
// 它的失败不该以任何形式传播到转发路径上。
func (h *HeadTail) Write(p []byte) (int, error) {
	if h.full && h.budgetOn && h.total+int64(len(p)) > h.budget {
		return h.writeOverBudget(p)
	}

	h.total += int64(len(p))

	// 完整模式：全部进 head，tail 不用。Bytes 与 Truncated 的既有公式
	// （head 已含全文 → 直接返回、不算截断）正好覆盖这一支，不需要特例。
	if h.full {
		h.head = append(h.head, p...)
		return len(p), nil
	}

	h.writeBounded(p)
	return len(p), nil
}

// writeOverBudget 在完整模式撞上剩余配额时切到头尾，再写入本段。
// 绝不先把超配额的字节 append 进 head —— 那正是本不变量要消灭的峰值。
func (h *HeadTail) writeOverBudget(p []byte) (int, error) {
	room := h.budget - h.total
	if room < 0 {
		room = 0
	}
	var fit []byte
	if room > 0 {
		if int64(len(p)) > room {
			fit = p[:room]
		} else {
			fit = p
		}
	}
	already := make([]byte, 0, len(h.head)+len(fit))
	already = append(already, h.head...)
	already = append(already, fit...)
	rest := p[len(fit):]

	h.switchFromFull(already)
	if len(rest) > 0 {
		h.total += int64(len(rest))
		h.writeBounded(rest)
	}
	return len(p), nil
}

// switchFromFull 丢掉完整缓冲，改成有界头尾并回放已收下的前缀。
func (h *HeadTail) switchFromFull(already []byte) {
	headMax, tailMax := h.overflowHead, h.overflowTail
	budget := len(already)
	if h.budgetOn && int(h.budget) < budget {
		budget = int(h.budget)
	}
	// 0/0 保持 0：§5.4 要的是「可配置的头尾」，未配置时不发明长度。
	if headMax > 0 || tailMax > 0 {
		if budget > 0 && headMax+tailMax > budget {
			// 配置头尾之和大于剩余配额时，按比例压进配额内。
			total := headMax + tailMax
			headMax = budget * headMax / total
			tailMax = budget - headMax
		}
	}

	h.quotaOverflow = true
	h.full = false
	h.budgetOn = false
	h.headMax = headMax
	h.head = make([]byte, 0, headMax)
	h.tail = make([]byte, tailMax)
	h.tailPos, h.tailLen = 0, 0
	h.total = 0
	if len(already) > 0 {
		h.total += int64(len(already))
		h.writeBounded(already)
	}
}

func (h *HeadTail) writeBounded(p []byte) {
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
