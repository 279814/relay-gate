package proxy

import (
	"net/http"
	"time"

	"github.com/279814/relay-gate/internal/sample"
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
//
// redactKeys 是本次请求涉及的凭据。**ErrBody 必须在这里脱敏**：它是上游
// 响应体的原文，而上游的鉴权错误经常把收到的 key 回显在消息里
// （`{"error":"Invalid API key: sk-xxx"}` 是常见格式）。
//
// 不脱敏的后果不止于日志：ErrBody 会经 probe.ClassifyHTTP → errFromBody
// 拼进 Outcome.Err → health.Report → 存成 route_health.last_error →
// 由 /admin/api/health 显示出来。也就是说一个明文 key 会**落库**，
// 并出现在管理界面上。
//
// 放在 viewOf 而不是各调用点：这是 ErrBody 进入健康判定的唯一入口，
// 在这里拦一次就覆盖全部路径；散到调用点则漏一处就是漏一个泄露口。
func viewOf(res *Result, redactKeys []string) *ResultView {
	return &ResultView{
		Status:       res.Status,
		Err:          res.Err,
		ErrBody:      sample.RedactDiagnostic(res.ErrBody, redactKeys),
		Header:       res.RespHeaders,
		TTFT:         res.TTFT(),
		BytesWritten: res.BytesWritten,
	}
}
