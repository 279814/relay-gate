package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/sample"
)

// handleCountTokens 处理 POST /v1/messages/count_tokens（§3.1）。
//
// Claude Code 启动时与每轮对话前都会调它做上下文预算，不实现会报错。
//
// 与三个透传端点的差异（§10.3 已定，都是刻意的）：
//   - **非流式**，超时独立（Settings.CountTokensSec，默认 60s）
//   - **失败不计入健康状态** —— 一个这么轻量的端点失败不该把站判死，
//     它的噪声会淹没真实请求给出的信号
//   - **上游不支持时本地粗算兜底**。M0 实测 4 个可用站只有 2 个支持
//     （另 2 个 404），而同一个 ModelName 下不同 Route 的支持情况不同，
//     所以兜底不能按站开关，只能统一本地兜底（§5.1e）
//
// 先转发后兜底而不是直接本地算：上游给的是真实 tokenizer 的结果，
// 本地粗算有 ±20% 误差。能拿到准确值时就不该用估算值。
//
// 不记样本：Claude Code 每轮都调它，而样本是 500 条的滚动窗口 ——
// 记进去会把真正有诊断价值的对话样本挤出去（§3.6.3c）。
func (h *Handler) handleCountTokens(w http.ResponseWriter, r *http.Request) {
	pre, ok := h.preamble(w, r, model.ProtoAnthropic)
	if !ok {
		return
	}

	// 选路失败不回错误，直接本地粗算 —— 本地兜底是设计要求（§5.1e）。
	// 这里也包括「模型没配」与「协议不是 anthropic」：客户端要的只是一个
	// token 数，为此回 404 会让 Claude Code 直接起不来。
	cand, selErr := router.Select(pre.snapshot, h.health, pre.inModel, model.ProtoAnthropic)
	if selErr != nil {
		h.log.Info("count_tokens 无可用上游，本地粗算",
			"model", pre.inModel, "err", selErr)
		h.localCountTokens(w, pre.body)
		return
	}
	defer cand.Release()

	if reason := h.proxyCountTokens(w, r, pre, cand); reason != "" {
		h.log.Info("count_tokens 转发未成功，本地粗算",
			"model", pre.inModel, "upstream", cand.Upstream.Name, "reason", reason)
		h.localCountTokens(w, pre.body)
	}
}

// proxyCountTokens 把 count_tokens 转发给上游。
//
// 返回空字符串表示**调用方无需再作答**（响应已写出，或客户端已经走了）；
// 返回非空的原因字符串表示应当降级到本地粗算。用原因字符串而不是 error：
// 这里的每一种「失败」都是预期内的（站不支持这个端点是常态），
// 日志里要的是可读的原因而不是错误链。
//
// **不得**在写出响应后再返回非空原因 —— 那会让调用方把兜底结果追加到
// 已经写出的响应后面，客户端拿到两个拼在一起的 JSON。
func (h *Handler) proxyCountTokens(w http.ResponseWriter, r *http.Request,
	pre *preambleResult, cand *router.Candidate) string {

	outBody, err := ReplaceModel(pre.body, cand.Route.UpstreamModel)
	if err != nil {
		return fmt.Sprintf("替换 model 失败: %v", err)
	}
	outHeader := PrepareOutboundHeaders(r.Header, cand.Upstream.APIKey,
		cand.Upstream.AuthStyle, model.ProtoAnthropic)

	// 路径与入站一致（/v1/messages/count_tokens）。count_tokens 不是第四种
	// 协议，只是 Anthropic 协议下的一个附加端点，所以不走 Protocol.Path()。
	outURL, err := BuildOutboundURL(cand.Upstream, r.URL.Path, r.URL.RawQuery)
	if err != nil {
		return fmt.Sprintf("拼接出站 URL 失败: %v", err)
	}

	tr, err := h.TransportFor(cand.Upstream, pre.settings)
	if err != nil {
		return fmt.Sprintf("构造 Transport 失败: %v", err)
	}

	ctx, cancel := context.WithTimeout(r.Context(),
		time.Duration(pre.settings.CountTokensSec)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, outURL, bytes.NewReader(outBody))
	if err != nil {
		return fmt.Sprintf("构造请求失败: %v", err)
	}
	req.Header = outHeader
	req.ContentLength = int64(len(outBody))

	resp, err := tr.RoundTrip(req)
	if err != nil {
		// 客户端自己走了就不该再兜底：连接已经没了，本地算完也写不出去，
		// 而且会白占一次 CPU。
		if r.Context().Err() != nil {
			return ""
		}
		return fmt.Sprintf("转发失败: %v", err)
	}
	defer resp.Body.Close()

	// 响应很小（Anthropic 的格式就是 {"input_tokens":N}），限长只为防异常站
	// 回一个巨大的错误页。
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxCountTokensResp))
	if err != nil {
		return fmt.Sprintf("读响应失败: %v", err)
	}

	// 4xx/5xx 一律视为「这个站不支持」并降级。不区分类别是刻意的：
	// 404（没这个端点）、400（参数要求不同）、401（这个端点单独鉴权）
	// 对客户端而言结果相同 —— 拿不到准确值，用估算值。
	// 而这些失败**不回写健康状态**，所以也不需要按 §4.3 分类。
	//
	// 原文进日志前**必须**脱敏：上游的鉴权错误经常把收到的 key 回显在消息里
	// （`{"error":"Invalid API key: sk-xxx"}` 是常见格式），而 401 恰好是这里
	// 最容易触发的分支。不脱敏的话日志就成了明文 key 的副本 —— §3.6.3b 对
	// 样本库的要求是无条件的，日志没有理由比它宽松。
	if resp.StatusCode >= 400 {
		safe := sample.RedactBodyKeys(respBody, h.logRedactKeys(r, cand))
		return fmt.Sprintf("上游返回 %d: %s", resp.StatusCode,
			collapseSpaces(string(safe), maxCountTokensLogBody))
	}

	// 成功。原样回传上游响应体。
	StripHopByHopResponse(resp.Header)
	dst := w.Header()
	for k, vs := range resp.Header {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
	// Content-Length 必须重算：上游可能用 chunked（没有这个头），
	// 而我们是一次性写出完整 body。照抄上游的值会与实际长度不符。
	dst.Set("Content-Length", strconv.Itoa(len(respBody)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
	return ""
}

// logRedactKeys 收齐这次请求里所有需要从日志中扫掉的凭据。
//
// 两处来源与样本记录完全一致（recordSample）：出站的上游 key 与入站的
// relay key。位置清单走 inboundCredentials（其内部读 model.AuthHeaders，
// 是唯一来源）—— 各列一份的话，新增一个鉴权位置时必然漏掉这里。
func (h *Handler) logRedactKeys(r *http.Request, cand *router.Candidate) []string {
	keys := []string{cand.Upstream.APIKey}
	return append(keys, inboundCredentials(r.Header)...)
}

const (
	// maxCountTokensResp 是 count_tokens 响应体的读取上限。
	// 正常响应只有几十字节，这个上限防的是异常站回整页 HTML。
	maxCountTokensResp = 64 << 10
	// maxCountTokensLogBody 是记进日志的上游错误原文长度上限。
	maxCountTokensLogBody = 200
)

// localCountTokens 本地粗算并按 Anthropic 的格式作答（降级路径）。
//
// 精度有限（见 estimateTokens），但**必须存在**：Claude Code 拿不到
// token 数就起不来，而 M0 实测半数站不支持这个端点（§5.1e）。
func (h *Handler) localCountTokens(w http.ResponseWriter, body []byte) {
	n, err := estimateInputTokens(body)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, model.ProtoAnthropic,
			"invalid_request_error", fmt.Sprintf("无法解析请求: %v", err))
		return
	}

	// 标出这是估算值。客户端不会读它，但排查「预算怎么算的」时，
	// 一眼能看出这次走的是兜底而不是上游的真实 tokenizer。
	w.Header().Set("X-Relay-Count-Tokens", "estimated")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]int{"input_tokens": n})
}

// countTokensRequest 只取估算需要的字段，其余忽略。
//
// 全部用 json.RawMessage 而不是具体类型：Anthropic 的 system 既可以是
// 字符串，也可以是 content block 数组（Claude Code 发的正是后者，带
// cache_control），messages[].content 同样两种形态都合法。声明成 string
// 会让 Unmarshal 直接报类型错误 —— 客户端为一个完全合法的请求拿到 400。
type countTokensRequest struct {
	System   json.RawMessage `json:"system"`
	Messages []struct {
		Content json.RawMessage `json:"content"`
	} `json:"messages"`
	Tools json.RawMessage `json:"tools"`
}

// perMessageOverhead 是每条消息的结构开销（role 分隔符等）。
// 真实 tokenizer 里每条消息约 3–4 个 token，取 4 偏保守。
const perMessageOverhead = 4

// estimateInputTokens 粗算一次 count_tokens 请求的输入 token 数。
func estimateInputTokens(body []byte) (int, error) {
	var req countTokensRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return 0, err
	}

	n := estimateJSONTokens(req.System)
	for _, m := range req.Messages {
		n += estimateJSONTokens(m.Content)
	}
	// 工具定义**必须**算进去：Claude Code 每轮都带完整的 tools schema，
	// 它常常比对话本身还长。漏掉它不是 ±20% 的误差，是数量级的误差。
	n += estimateJSONTokens(req.Tools)

	return n + perMessageOverhead*len(req.Messages), nil
}

// estimateJSONTokens 递归走一段 JSON，累加其中所有字符串的估算值。
//
// 不按字段名区分是刻意的：要算的文本散落在 text block 的 text、
// tool_use 的 input、tools 的 schema description 等处，形状各不相同。
// 走一遍所有字符串比为每种形态写一个分支更不容易漏 —— 代价是把
// "type"、"role" 这类结构性字段的值也算进去了，而那恰好粗粒度地
// 补上了真实 tokenizer 的结构开销。
func estimateJSONTokens(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 0
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		// 解不开就按原文长度粗算。偏高，但总好过算成 0 ——
		// 预算偏高只是让客户端早一点压缩上下文，偏低会导致上游 400。
		return estimateTokens(string(raw))
	}
	return walkJSONTokens(v)
}

func walkJSONTokens(v any) int {
	switch t := v.(type) {
	case string:
		return estimateTokens(t)
	case []any:
		n := 0
		for _, e := range t {
			n += walkJSONTokens(e)
		}
		return n
	case map[string]any:
		n := 0
		for _, e := range t {
			n += walkJSONTokens(e)
		}
		return n
	}
	// 数字、bool、null 在真实 tokenizer 里各占 1–2 个。
	// 相对于文本的量级可以忽略，不值得为此引入一堆 +1。
	return 0
}

// estimateTokens 粗算一段文本的 token 数。
//
// 算法：按空白与标点切词，英文词 ×1.3，CJK 字 ×1.5。
//
// 这是经验值，真实 tokenizer 是 BPE subword，行为复杂得多。误差约 ±20%，
// 且**刻意偏高**：Claude Code 用它做上下文预算，估高只是让它早一点压缩
// 上下文，估低会让请求超出上下文窗口而被上游 400 拒绝。
//
// 已知的最大偏差来源是 base64 图片：一张图在 Anthropic 侧按尺寸计费
// （约 (w×h)/750），而这里按它的 base64 文本切词。两者碰巧在同一量级，
// 但那是巧合，不是设计 —— 带图的请求估算值不可靠。
func estimateTokens(text string) int {
	if text == "" {
		return 0
	}
	words, cjk := 0, 0
	inWord := false

	for _, r := range text {
		switch {
		// CJK 每字单独算，它们之间没有空格，按词切会把一整句算成一个词。
		case unicode.In(r, unicode.Han, unicode.Hiragana, unicode.Katakana, unicode.Hangul):
			cjk++
			inWord = false
		case unicode.IsSpace(r), unicode.IsPunct(r), unicode.IsSymbol(r):
			inWord = false
		default:
			if !inWord {
				words++
				inWord = true
			}
		}
	}
	return int(float64(words)*1.3 + float64(cjk)*1.5)
}

// collapseSpaces 把连续空白压成单个空格并限长，让上游错误原文在单行日志里可读。
//
// 按 rune 而不是 byte 截断：中转站的错误信息常是中文，按字节切会把一个
// 汉字劈成两半，日志里出现乱码。
func collapseSpaces(s string, limit int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > limit {
		return string(r[:limit]) + "…"
	}
	return s
}
