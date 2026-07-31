package sample

import (
	"bytes"
	"strings"
	"testing"
)

// 未超限时必须返回原文，不插入任何标记 ——
// 否则短响应的样本也会被污染，无法与真实字节比对。
func TestHeadTail_UntruncatedIsExact(t *testing.T) {
	ht := NewHeadTail(1024, 256)
	const data = "event: message_start\ndata: {}\n\n"
	ht.Write([]byte(data))

	if ht.Truncated() {
		t.Error("未超限不该标记为截断")
	}
	if string(ht.Bytes()) != data {
		t.Errorf("未截断时应逐字节返回原文，得到 %q", ht.Bytes())
	}
	if ht.Total() != int64(len(data)) {
		t.Errorf("Total 应为 %d，得到 %d", len(data), ht.Total())
	}
}

// 超限时留头 + 留尾。SSE 的诊断信息分布在两端：
// 头部有错误信息与首个 delta，尾部有 message_stop 与 usage。
func TestHeadTail_KeepsBothEnds(t *testing.T) {
	ht := NewHeadTail(20, 20)
	head := "HEAD-0123456789xxxxx"      // 恰好 20 字节
	tail := "yyyyyTAIL-0123456789"      // 恰好 20 字节
	middle := strings.Repeat("M", 5000) // 会被丢弃的中间部分
	ht.Write([]byte(head + middle + tail))

	if !ht.Truncated() {
		t.Fatal("应标记为截断")
	}
	got := ht.Bytes()
	if !bytes.HasPrefix(got, []byte(head)) {
		t.Errorf("应保留头部 %q，得到 %q", head, got)
	}
	if !bytes.HasSuffix(got, []byte(tail)) {
		t.Errorf("应保留尾部 %q，得到 %q", tail, got)
	}
	// 内存占用与流的长度无关，这是这个类型存在的理由
	if len(got) > 20+20+80 {
		t.Errorf("留档体积应恒定在 head+tail+标记，得到 %d 字节", len(got))
	}
	if !bytes.Contains(got, []byte("省略")) {
		t.Error("应插入省略标记，否则看不出中间被砍了")
	}
}

// 分多次写入的结果必须与一次性写入相同 —— SSE 正是逐块到达的。
func TestHeadTail_ChunkedWritesMatchSingleWrite(t *testing.T) {
	full := []byte(strings.Repeat("abcdefghij", 100)) // 1000 字节

	single := NewHeadTail(50, 30)
	single.Write(full)

	chunked := NewHeadTail(50, 30)
	for i := 0; i < len(full); i += 7 { // 7 字节一块，刻意不整除
		end := i + 7
		if end > len(full) {
			end = len(full)
		}
		chunked.Write(full[i:end])
	}

	if !bytes.Equal(single.Bytes(), chunked.Bytes()) {
		t.Errorf("分块写入结果应与一次性写入相同\n单次 %q\n分块 %q",
			single.Bytes(), chunked.Bytes())
	}
	if single.Total() != chunked.Total() {
		t.Errorf("Total 应相同：%d vs %d", single.Total(), chunked.Total())
	}
}

// 尾缓冲绕回后，字节顺序必须还原正确。这是环形缓冲最容易写错的地方。
func TestHeadTail_RingBufferOrderAfterWrap(t *testing.T) {
	ht := NewHeadTail(0, 10)
	// 分多次写，逼着尾缓冲绕好几圈
	for _, s := range []string{"AAAAA", "BBBBB", "CCCCC", "0123456789"} {
		ht.Write([]byte(s))
	}
	got := ht.Bytes()
	if !bytes.HasSuffix(got, []byte("0123456789")) {
		t.Errorf("绕回后尾部顺序错乱，得到 %q", got)
	}
}

// 单次写入超过尾缓冲容量时，只该留最后那一段。
func TestHeadTail_SingleWriteLargerThanTail(t *testing.T) {
	ht := NewHeadTail(5, 10)
	ht.Write([]byte("HEADxx" + strings.Repeat("z", 100) + "TAIL012345"))

	got := ht.Bytes()
	if !bytes.HasSuffix(got, []byte("TAIL012345")) {
		t.Errorf("应只保留最后 10 字节，得到 %q", got)
	}
}

// 尾缓冲未填满时（流比 tailMax 短）也要正确。
func TestHeadTail_TailNotFilled(t *testing.T) {
	ht := NewHeadTail(3, 100)
	ht.Write([]byte("abcdefgh")) // 8 字节，头 3 尾 100

	// 8 <= 3 + 8，未截断
	if ht.Truncated() {
		t.Error("总长小于 head+tail 时不该算截断")
	}
	if string(ht.Bytes()) != "abcdefgh" {
		t.Errorf("应返回原文，得到 %q", ht.Bytes())
	}
}

// 回归测试：头尾覆盖得住全文时必须**无损**还原，且不插省略标记。
//
// 曾经的 bug：Bytes() 未截断时直接返回 head，而 head 最长只有 headMax。
// headMax 小、tailMax 大时（生产默认是 64KB + 8KB，但配置可任意改），
// 中等长度的响应会被静默砍到 headMax 字节 —— 而样本的全部价值
// 就在于「到底是哪些字节」，静默丢字节等于这个功能白做。
func TestHeadTail_OverlappingHeadTailIsLossless(t *testing.T) {
	// 各种 head/tail 组合下，凡是 head+tail ≥ 总长的都必须无损
	cases := []struct{ head, tail, total int }{
		{3, 100, 8},  // 头远小于尾
		{100, 3, 8},  // 尾远小于头
		{10, 10, 15}, // 重叠 5 字节
		{10, 10, 20}, // 刚好拼满，零重叠
		{10, 10, 10}, // 头就是全文
		{1, 1, 2},    // 极小
		{50, 50, 1},  // 两边都富余
	}
	for _, c := range cases {
		data := make([]byte, c.total)
		for i := range data {
			data[i] = byte('a' + i%26)
		}
		ht := NewHeadTail(c.head, c.tail)
		ht.Write(data)

		got := ht.Bytes()
		if ht.Truncated() {
			t.Errorf("head=%d tail=%d total=%d：覆盖得住不该算截断",
				c.head, c.tail, c.total)
			continue
		}
		if !bytes.Equal(got, data) {
			t.Errorf("head=%d tail=%d total=%d：应无损还原\nwant %q\ngot  %q",
				c.head, c.tail, c.total, data, got)
		}
	}
}

// 重叠还原对分块写入同样成立（SSE 就是逐块到达的）。
func TestHeadTail_OverlapWithChunkedWrites(t *testing.T) {
	data := []byte("0123456789ABCDEFGHIJ") // 20 字节
	ht := NewHeadTail(6, 20)               // 6 + 20 ≥ 20，应无损
	for i := 0; i < len(data); i += 3 {
		end := i + 3
		if end > len(data) {
			end = len(data)
		}
		ht.Write(data[i:end])
	}
	if got := ht.Bytes(); !bytes.Equal(got, data) {
		t.Errorf("分块写入也应无损还原\nwant %q\ngot  %q", data, got)
	}
}

// 零配置不能 panic。head=0 是「只留尾」的合法配置。
func TestHeadTail_ZeroSizes(t *testing.T) {
	ht := NewHeadTail(0, 0)
	ht.Write([]byte("anything at all"))
	if got := ht.Bytes(); len(got) > 64 {
		t.Errorf("全零配置应几乎不留内容，得到 %d 字节", len(got))
	}
	if ht.Total() != 15 {
		t.Errorf("Total 仍应统计流经字节，得到 %d", ht.Total())
	}

	// 负数按 0 处理，不能 panic
	NewHeadTail(-1, -1).Write([]byte("x"))
}

// Write 永不返回错误：采集是旁路，它的失败不该以任何形式传播到转发路径。
func TestHeadTail_WriteNeverErrors(t *testing.T) {
	ht := NewHeadTail(4, 4)
	n, err := ht.Write([]byte("0123456789"))
	if err != nil {
		t.Errorf("Write 不该返回错误，得到 %v", err)
	}
	if n != 10 {
		t.Errorf("应报告收下了全部 10 字节，得到 %d", n)
	}
}

func TestTruncateBody(t *testing.T) {
	body := []byte(strings.Repeat("x", 1000))

	out, cut := TruncateBody(body, 100)
	if !cut {
		t.Error("超限应标记为截断")
	}
	if !bytes.HasPrefix(out, []byte(strings.Repeat("x", 100))) {
		t.Error("应保留头部 100 字节")
	}
	if !bytes.Contains(out, []byte("省略")) {
		t.Error("应插入省略标记")
	}
}

// 未超限时返回原 slice，不拷贝、不加标记。
func TestTruncateBody_UnderLimitIsUntouched(t *testing.T) {
	body := []byte(`{"model":"claude-opus-5"}`)

	out, cut := TruncateBody(body, 1024)
	if cut {
		t.Error("未超限不该标记截断")
	}
	if &out[0] != &body[0] {
		t.Error("未超限时应返回原 slice")
	}

	// 恰好等于上限也不该截断
	out, cut = TruncateBody(body, len(body))
	if cut || string(out) != string(body) {
		t.Error("恰好等于上限时不该截断")
	}
}

// limit <= 0 表示不限，不是「全砍掉」—— 反过来会静默丢掉所有 body。
func TestTruncateBody_ZeroLimitMeansUnlimited(t *testing.T) {
	body := []byte("some content here")
	out, cut := TruncateBody(body, 0)
	if cut || string(out) != string(body) {
		t.Errorf("limit=0 应表示不限，得到 cut=%v out=%q", cut, out)
	}
}
