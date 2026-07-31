package proxy

import (
	"net/http"
	"time"
)

// HealthReporter 接收真实请求的健康结论。由 probe 包适配到 health.Tracker。
//
// 为什么是接口而不是直接调 health.Tracker：判定要靠 probe 包的分类器
// （ClassifyHTTP / ClassifyTransportErr），而 probe 已经导入了 proxy
// （复用 BuildOutboundURL 与哨兵错误）。proxy 反向导入 probe 就成了循环。
// 接缝留在这里、实现放在 probe，依赖方向保持单向。
//
// **真实请求的回写是最快的故障发现路径**：探活有周期（dead 状态 20 秒），
// 真实请求没有延迟 —— 站挂掉的那一刻就有请求撞上去。§3.5 把它列为
// 「尽快发现故障的主路径」，比定时探活快得多。
type HealthReporter interface {
	// ReportResult 上报一次真实转发的结果。
	//
	// 实现必须是**非阻塞**的：它在转发的收尾路径上被调用，阻塞就等于
	// 让健康统计拖慢真实请求。
	ReportResult(routeID int64, res *ResultView)

	// TriggerProbe 请求对该 Route 立即探活一次（§4.5：真实请求失败即触发）。
	TriggerProbe(routeID int64)
}

// ResultView 是转发结果里与健康判定相关的部分。
//
// 单独一个类型而不是直接传 *Result：Result 还带着 SentAt/DoneAt/RespHeaders
// 这些只有样本记录关心的字段，而健康判定不该看到它们 —— 传整个 Result
// 会让「判定依据是什么」变得不明确，将来加字段时也说不清哪些是判定输入。
type ResultView struct {
	Status  int
	Err     error
	ErrBody []byte
	Header  http.Header
	// TTFT 首 Token 延迟，0 表示未测到。
	TTFT time.Duration
	// BytesWritten 用于识别假活：200 但一个字节都没吐（§4.3）。
	BytesWritten int64
}

// viewOf 从完整结果里摘出健康判定需要的部分。
func viewOf(res *Result) *ResultView {
	return &ResultView{
		Status:       res.Status,
		Err:          res.Err,
		ErrBody:      res.ErrBody,
		Header:       res.RespHeaders,
		TTFT:         res.TTFT(),
		BytesWritten: res.BytesWritten,
	}
}
