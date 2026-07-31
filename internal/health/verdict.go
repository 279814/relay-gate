package health

import "time"

// Verdict 是一次探测或一次真实请求的判定结果（§4.3）。
//
// 分成四类而不是简单的成功/失败，是因为它们对状态机的**动作**完全不同：
// 致命错误立即判死（重试没有意义，配置不改就永远错），服务不可用要累计
// （一次抖动不该踢掉一个站），限流则根本不算失败（站是好的，只是这会儿满了）。
// 混为一谈的话，要么 401 的站被反复重试，要么 429 的站被误判成死站。
type Verdict int

const (
	// VerdictOK 探测成功，或真实请求正常完成。
	VerdictOK Verdict = iota

	// VerdictFatal 配置或鉴权错误：401/403、模型不存在。
	//
	// 立即 dead，不累计。这类错误重试一万次也是同样的结果，
	// 唯一的出路是改配置 —— 所以要尽快从选路里剔除，并在 UI 上
	// 明确显示成「配置/鉴权错误」而不是「服务不可用」，否则用户
	// 会一直等它自己恢复。
	VerdictFatal

	// VerdictUnavailable 服务不可用：连不上、5xx、超时、假活。
	//
	// 累计到 FailThreshold 才判死。公益站抖动是常态，一次失败就判死
	// 会让池子反复空掉。
	VerdictUnavailable

	// VerdictRateLimited 限流：429，或 body 里含限流关键词。
	//
	// 进冷却但**不计入失败**，也不清零成功计数。站本身是好的，
	// 把它判死等于因为「太受欢迎」而拉黑一个可用的站。
	VerdictRateLimited

	// VerdictIgnore 与上游健康无关：客户端断开、请求被取消、服务暂停。
	//
	// 必须有这一类。没有的话，用户按 Ctrl-C 取消一次长对话就会给
	// 那个站记一次失败 —— 取消得够频繁就能把所有好站判死。
	VerdictIgnore
)

func (v Verdict) String() string {
	switch v {
	case VerdictOK:
		return "ok"
	case VerdictFatal:
		return "fatal"
	case VerdictUnavailable:
		return "unavailable"
	case VerdictRateLimited:
		return "rate_limited"
	case VerdictIgnore:
		return "ignore"
	}
	return "unknown"
}

// Report 是一次判定的完整输入。
type Report struct {
	RouteID int64
	Verdict Verdict

	// Source 标明这次判定来自哪里，决定两件事：
	// 真实请求成功可以让 unknown 直接升 alive（§4.4），
	// 且真实请求成功会刷新 piggyback 时间戳（§4.6）。
	Source Source

	// Err 是失败原因，原样存进 last_error 供 UI 展示。
	Err error

	// TTFT 首 Token 延迟。0 表示未测到。
	TTFT time.Duration

	// RetryAfter 是 429 响应里 Retry-After 头的值。
	// 0 表示上游没给，此时用 Settings.CooldownSec。
	RetryAfter time.Duration
}

// Source 标明判定的来源。
type Source int

const (
	SourceL1 Source = iota
	SourceL2
	// SourceReal 是真实用户请求的结果。它是**最快**的故障发现路径 ——
	// 探活有周期，真实请求没有延迟，站挂了的那一刻就有请求撞上去。
	SourceReal
)

func (s Source) String() string {
	switch s {
	case SourceL1:
		return "l1"
	case SourceL2:
		return "l2"
	case SourceReal:
		return "real"
	}
	return "?"
}
