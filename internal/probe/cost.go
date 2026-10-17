package probe

import (
	"github.com/279814/relay-gate/internal/model"
	"unicode"
)

// RouteCost 是单个 Route 的 L2 开销。
//
// 只有 L2 花 token：L1 是 GET /v1/models，零 token（§4.1）。
type RouteCost struct {
	RouteID int64 `json:"route_id"`
	L2Count int64 `json:"l2_count"`
	// EstTokens 是估算值，不是账单。见 estimateL2Tokens 的说明。
	EstTokens int64 `json:"est_tokens"`
	// L2Failed 单独计数：失败的探活同样花钱（请求已经发出去了），
	// 而「失败占比高」是策略过激的直接信号 —— 探一个死站 100 次，
	// 100 次都失败，那 100 次的 token 是纯浪费。
	L2Failed int64 `json:"l2_failed"`
	LastL2At int64 `json:"last_l2_at"`
}

// UpstreamCost 是单个 Upstream 的 L1 次数。
type UpstreamCost struct {
	UpstreamID int64 `json:"upstream_id"`
	L1Count    int64 `json:"l1_count"`
	L1Failed   int64 `json:"l1_failed"`
	LastL1At   int64 `json:"last_l1_at"`
}

// CostSnapshot 是成本视图的对外形状。
type CostSnapshot struct {
	Day string `json:"day"`
	// 汇总。§5.2d 的原话是「今日 L1/L2 次数、估算 token」。
	L1Count   int64 `json:"l1_count"`
	L1Failed  int64 `json:"l1_failed"`
	L2Count   int64 `json:"l2_count"`
	L2Failed  int64 `json:"l2_failed"`
	EstTokens int64 `json:"est_tokens"`

	Routes    []RouteCost    `json:"routes"`
	Upstreams []UpstreamCost `json:"upstreams"`
}

// estimateL2Tokens 按 ModelName 估算一次 L2 探活消耗的 token。
//
// **是估算，不是账单。** 用途是判断策略是否过激（探活次数 × 每次的量级），
// 那只需要正确的量级；要精确值得去看各站的计费页，而公益站多半也不提供。
//
// 这是**回落**路径。命中内置模板时用 manifest 里的声明值（见
// preparedProbe.estimatedTokens）—— 那是模板作者按它实际的 body 写的。
// 这里服务两种情况：用户自己配的 Recipe（manifest 之外，没有声明值），
// 以及探活根本没发出去（配置错误，那时没有内容可估）。
//
// 输出按 max_tokens 的上限计：实际生成通常更少（判定一出就断流，§4.1），
// 所以这是**上界**，用于成本估算时宁可高估。
//
// 固定开销那部分（协议骨架之类）用 perProbeOverhead 一个常数带过：探活 body
// 是我们自己构造的最小请求，除了 prompt 几乎没有别的内容。
//
// ── 与 count_tokens 的关系 ──
//
// 两者**不是**同一套算法，也不该假装是。proxy 的 estimateTokens 按词切分
// （英文词 ×1.3、CJK 字 ×1.5），它要处理的是几百 KB 的真实对话；这里只有
// 一个几个字的 prompt，量级差四五个数量级。
//
// 但 CJK 系数必须一致。早先这里写的是无条件 `len(rune)/4`，实测下来
// `"你好"` 被算成 **0 个 token** —— 整数除法在短 CJK 串上直接截断到零，
// 而 CJK 在真实 tokenizer 里恰恰是每字 1.5 个，方向正好错。
// probe_prompt 是 UI 可改的配置项（§4.7），中文 prompt 完全可达。
func estimateL2Tokens(mn *model.ModelName) int {
	if mn == nil {
		return 0
	}
	prompt := mn.ProbePrompt
	if prompt == "" {
		prompt = defaultProbePrompt
	}
	maxTok := mn.ProbeMaxTokens
	if maxTok <= 0 {
		maxTok = 1
	}
	return estimatePromptTokens(prompt) + perProbeOverhead + maxTok
}

// estimatePromptTokens 粗算探活 prompt 的 token 数。
//
// CJK 每字 1.5、其余每 4 字符 1 个，与 proxy 的 estimateTokens 在这两个
// 系数上保持一致。不共用那个函数是因为它在 proxy 包内未导出，而为了一个
// 几个字的 prompt 去导出它、或让 probe 依赖 proxy 的内部实现，都不划算 ——
// 这里只需要正确的量级。
//
// 至少返回 1：prompt 非空就一定会产生 token，返回 0 会让「今日估算 token」
// 在中文 prompt 下恒为一个偏小的数，而偏小恰恰是成本估算最不该出的方向。
func estimatePromptTokens(prompt string) int {
	var cjk, other int
	for _, r := range prompt {
		if unicode.In(r, unicode.Han, unicode.Hiragana, unicode.Katakana, unicode.Hangul) {
			cjk++
			continue
		}
		other++
	}
	n := int(float64(cjk)*1.5) + other/4
	if n < 1 {
		return 1
	}
	return n
}

// perProbeOverhead 是一次探活请求除 prompt 之外的结构性开销
// （role/content 的骨架等）。真实 tokenizer 里每条消息约 3–4 个，取 4 偏保守。
const perProbeOverhead = 4
