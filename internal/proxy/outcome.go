package proxy

import (
	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/sample"
)

type HealthReporter = health.ResultReporter
type ResultView = health.ResultView

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
func viewOf(res *Result, redactKeys []string, endpoint model.EndpointKind) *ResultView {
	return &ResultView{
		Status:       res.Status,
		Err:          redactErr(res.Err, redactKeys),
		ErrBody:      sample.RedactDiagnostic(res.ErrBody, redactKeys),
		Header:       res.RespHeaders,
		Endpoint:     endpoint,
		TTFT:         res.TTFT(),
		BytesWritten: res.BytesWritten,
		SemanticSeen: res.SemanticSeen,
	}
}

// redactErr 让 Err 的文本与 ErrBody 走同一条脱敏：上游回显请求行时，
// net/http 会把那一行（query 里可能有 key）拼进 res.Err，而 Tracker 把
// Err.Error() 原样存成 route_health.last_error。Unwrap 保留原错误链，
// IsUpstreamFault / errors.Is 分类不受影响。
func redactErr(err error, keys []string) error {
	if err == nil {
		return nil
	}
	return &redactedError{msg: sample.RedactDiagnosticText(err.Error(), keys), err: err}
}

type redactedError struct {
	msg string
	err error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.err }
