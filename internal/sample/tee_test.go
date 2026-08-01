package sample

import (
	"bytes"
	"strings"
	"testing"
)

// naiveTail 是尾缓冲的朴素参照实现：直接留全量，取最后 n 字节。
// 生产实现是定长环形缓冲（内存不能随流长增长），两者结果必须一致。
func naiveTail(chunks [][]byte, n int) []byte {
	var all []byte
	for _, c := range chunks {
		all = append(all, c...)
	}
	if n <= 0 {
		return nil
	}
	if len(all) > n {
		all = all[len(all)-n:]
	}
	return all
}

// 环形缓冲按段 copy 之后，绕回边界是最容易出错的地方：
// 差一个字节就会让尾部错位，而错位的样本比没有样本更误导人
// —— 它看起来是一份完整留档，实际字节顺序是错的。
//
// 这里穷举「chunk 大小 × 缓冲大小」的组合与朴素实现对拍，
// 覆盖不绕回、正好绕回、跨多圈、单次写超过整个缓冲这几种情形。
func TestHeadTail_RingMatchesNaiveAcrossSizes(t *testing.T) {
	// 素数样的取值，让绕回位置落在各种偏移上，而不总是整齐对齐
	tailSizes := []int{1, 2, 3, 7, 8, 16, 31, 64}
	chunkSizes := []int{1, 3, 5, 8, 17, 64, 100}
	const streamLen = 257 // 与所有 tailSize 都不成整数倍

	stream := make([]byte, streamLen)
	for i := range stream {
		stream[i] = byte('a' + i%26)
	}

	for _, tailMax := range tailSizes {
		for _, chunk := range chunkSizes {
			// headMax=0：把 head 排除在外，单独盯住尾缓冲的正确性
			ht := NewHeadTail(0, tailMax)
			var chunks [][]byte
			for off := 0; off < len(stream); off += chunk {
				end := off + chunk
				if end > len(stream) {
					end = len(stream)
				}
				c := stream[off:end]
				chunks = append(chunks, c)
				ht.Write(c)
			}

			want := naiveTail(chunks, tailMax)
			if got := ht.tailBytes(); !bytes.Equal(got, want) {
				t.Errorf("tailMax=%d chunk=%d：尾部不一致\n got %q\nwant %q",
					tailMax, chunk, got, want)
			}
			if ht.Total() != int64(len(stream)) {
				t.Errorf("tailMax=%d chunk=%d：Total 应为 %d，得到 %d",
					tailMax, chunk, len(stream), ht.Total())
			}
		}
	}
}

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

// 两者同时为 0 = 完整保留（当前的默认配置）。
//
// 这条曾经断言的是相反的行为（「全零应几乎不留内容」）。语义是刻意改的：
// 默认值改成了完整留档，而 0 是它的表达方式。若这里仍按「不留」实现，
// 默认配置下 resp_body 会**恒为空** —— 样本表照常长出几百行，
// 每行的响应体都是空的，而且不报错。
func TestHeadTail_ZeroSizesMeansFull(t *testing.T) {
	ht := NewHeadTail(0, 0)
	const data = "event: message_start\ndata: {\"usage\":{\"output_tokens\":42}}\n\n"
	ht.Write([]byte(data))

	if string(ht.Bytes()) != data {
		t.Errorf("全零应完整保留，want %q got %q", data, ht.Bytes())
	}
	if ht.Truncated() {
		t.Error("完整保留时不该标记截断")
	}
	if ht.Total() != int64(len(data)) {
		t.Errorf("Total 应为 %d，得到 %d", len(data), ht.Total())
	}

	// 负数按 0 处理，等同完整保留，且不能 panic
	neg := NewHeadTail(-1, -1)
	neg.Write([]byte("xyz"))
	if string(neg.Bytes()) != "xyz" {
		t.Errorf("负数应按 0（完整）处理，得到 %q", neg.Bytes())
	}
}

// 完整模式下分块写入要按顺序拼回去，且大流不丢字节。
func TestHeadTail_FullModeAcrossChunks(t *testing.T) {
	ht := NewHeadTail(0, 0)
	var want []byte
	for i := 0; i < 500; i++ {
		chunk := []byte(strings.Repeat(string(rune('a'+i%26)), 300))
		ht.Write(chunk)
		want = append(want, chunk...)
	}
	if !bytes.Equal(ht.Bytes(), want) {
		t.Errorf("完整模式应无损，want %d 字节 got %d 字节", len(want), len(ht.Bytes()))
	}
	if ht.Truncated() {
		t.Error("完整模式永不截断")
	}
}

// head=0 但 tail>0 仍是**有界**的「只留尾」，不能被当成不限。
//
// 这条钉的是 full 标志为什么不能写成 headMax==0：混为一谈的话，
// 一个想「只留最后 8KB」的配置会静默变成「全留」，而症状是内存慢慢涨。
func TestHeadTail_HeadZeroWithTailIsStillBounded(t *testing.T) {
	ht := NewHeadTail(0, 16)
	ht.Write([]byte(strings.Repeat("A", 100) + "TAIL-0123456789x"))

	if !ht.Truncated() {
		t.Error("head=0 tail=16 是有界配置，超出应标记截断")
	}
	got := ht.Bytes()
	if !bytes.HasSuffix(got, []byte("TAIL-0123456789x")) {
		t.Errorf("应保留最后 16 字节，得到 %q", got)
	}
	// 省略标记之外不该有别的内容 —— head 是 0
	if bytes.Contains(got, bytes.Repeat([]byte("A"), 20)) {
		t.Errorf("head=0 不该留头部内容，得到 %q", got)
	}
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

func TestPrepareBody(t *testing.T) {
	body := []byte(strings.Repeat("x", 1000))

	out, cut := PrepareBody(body, nil, 100)
	if !cut {
		t.Error("超限应标记为截断")
	}
	if !bytes.HasPrefix(out, []byte(strings.Repeat("x", 100))) {
		t.Error("应保留头部 100 字节")
	}
	if !bytes.Contains(out, []byte("省略")) {
		t.Error("应插入省略标记")
	}
	// 省略标记里报的是被丢掉的原始字节数
	if !bytes.Contains(out, []byte("900")) {
		t.Errorf("应说明省略了 900 字节，得到 %q", out)
	}
}

// 未超限时返回原 slice，不拷贝、不加标记。
func TestPrepareBody_UnderLimitIsUntouched(t *testing.T) {
	body := []byte(`{"model":"claude-opus-5"}`)

	out, cut := PrepareBody(body, nil, 1024)
	if cut {
		t.Error("未超限不该标记截断")
	}
	if &out[0] != &body[0] {
		t.Error("未超限且无 key 命中时应返回原 slice")
	}

	// 恰好等于上限也不该截断
	out, cut = PrepareBody(body, nil, len(body))
	if cut || string(out) != string(body) {
		t.Error("恰好等于上限时不该截断")
	}
}

// limit <= 0 表示不限，不是「全砍掉」—— 反过来会静默丢掉所有 body。
func TestPrepareBody_ZeroLimitMeansUnlimited(t *testing.T) {
	body := []byte("some content here")
	out, cut := PrepareBody(body, nil, 0)
	if cut || string(out) != string(body) {
		t.Errorf("limit=0 应表示不限，得到 cut=%v out=%q", cut, out)
	}
}

// 不限长时也要脱敏 —— 否则「不限」就成了明文落库的后门。
func TestPrepareBody_RedactsWhenUnlimited(t *testing.T) {
	key := "sk-test-abcdefghijklmn"
	body := []byte(`{"api_key":"` + key + `"}`)

	for _, limit := range []int{0, -1, 4096} {
		out, cut := PrepareBody(body, []string{key}, limit)
		if cut {
			t.Errorf("limit=%d 不该截断", limit)
		}
		if bytes.Contains(out, []byte(key)) {
			t.Errorf("limit=%d 时明文 key 仍在：%q", limit, out)
		}
	}
}

// 截断点落在 key 中间时，绝不能让前半截以明文留下。
//
// 这是「先截断再脱敏」这个优化最容易出错的地方：截断窗口若不给
// key 长度留余量，一个横跨截断点的 key 会有前缀原样落库 ——
// 而 §9.4 的验收是「真 key 全表 grep 零命中」，半截也算命中。
func TestPrepareBody_KeyStraddlingTruncationPoint(t *testing.T) {
	key := "sk-secret-0123456789abcdef"

	// 让 key 的起点逐字节扫过截断边界，穷举所有相对位置
	for off := 0; off <= len(key)+2; off++ {
		limit := 40
		prefix := strings.Repeat("a", limit-off)
		body := []byte(prefix + key + strings.Repeat("b", 200))

		out, cut := PrepareBody(body, []string{key}, limit)
		if !cut {
			t.Fatalf("off=%d 应被截断", off)
		}
		if bytes.Contains(out, []byte(key)) {
			t.Errorf("off=%d：完整 key 明文留存\n%q", off, out)
		}
		// 半截也不行：检查 key 的任何长前缀都没留下
		for n := len(key); n >= minRedactableKey; n-- {
			if bytes.Contains(out, []byte(key[:n])) {
				t.Errorf("off=%d：key 的前 %d 字节明文留存\n%q", off, n, out)
				break
			}
		}
	}
}

// 留档长度必须守住上限：脱敏后的掩码比原 key 短，
// 但窗口余量不能让最终结果超出用户配置的 limit。
func TestPrepareBody_RespectsLimitAfterRedaction(t *testing.T) {
	key := "sk-secret-0123456789abcdef"
	body := []byte(strings.Repeat("a", 20) + key + strings.Repeat("b", 500))

	const limit = 30
	out, cut := PrepareBody(body, []string{key}, limit)
	if !cut {
		t.Fatal("应被截断")
	}
	// out = 内容(≤limit) + 省略标记
	idx := bytes.Index(out, []byte("\n/*"))
	if idx < 0 {
		t.Fatalf("应含省略标记：%q", out)
	}
	if idx > limit {
		t.Errorf("留档内容 %d 字节，超过 limit=%d：%q", idx, limit, out)
	}
}
