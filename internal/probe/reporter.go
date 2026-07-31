package probe

import (
	"fmt"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/proxy"
)

// Reporter 把真实请求的结果翻译成健康判定，是 proxy.HealthReporter 的实现。
//
// 与探活共用同一套分类器（ClassifyHTTP / ClassifyTransportErr）是刻意的：
// 两边各写一套的话，「429 是限流不是故障」「客户端断开不算上游的账」
// 这类规则迟早会在其中一边漏掉，而漏掉的表现是好站被判死 —— 静默、
// 不报错、只能靠翻状态才发现。
type Reporter struct {
	track Tracker
}

func NewReporter(track Tracker) *Reporter { return &Reporter{track: track} }

// ReportResult 上报一次真实转发的结果（§3.5）。
//
// 非阻塞：全程只做内存里的状态更新，没有 I/O。
func (r *Reporter) ReportResult(routeID int64, res *proxy.ResultView) {
	out := classifyReal(res)
	if out.Verdict == health.VerdictIgnore {
		return
	}

	r.track.Report(health.Report{
		RouteID: routeID, Verdict: out.Verdict, Source: health.SourceReal,
		Err: out.Err, TTFT: out.TTFT, RetryAfter: out.RetryAfter,
	})

	// §4.5：真实请求失败立即触发探活，不等定时周期。
	//
	// 为什么失败了还要探：真实请求的失败可能是偶发（一次网络抖动），
	// 也可能是站真挂了。探活能在几秒内给出第二个独立的判断，
	// 而不是等下一个用户请求撞上来 —— 那可能是几分钟之后。
	if out.Verdict != health.VerdictOK {
		r.track.TriggerL2(routeID)
	}
}

// TriggerProbe 请求立即探活一次。
func (r *Reporter) TriggerProbe(routeID int64) { r.track.TriggerL2(routeID) }

// classifyReal 把一次真实转发的结果归类。
//
// 判定顺序：先看传输层错误（连不上、超时、客户端断开），再看 HTTP 状态码，
// 最后才是「200 但没吐字节」的假活。顺序不能反 —— 传输层失败时 Status
// 可能是 0（连响应头都没拿到），按状态码判会当成「未知的成功」。
func classifyReal(res *proxy.ResultView) Outcome {
	if res == nil {
		return Outcome{Verdict: health.VerdictIgnore}
	}

	// 传输层错误优先。客户端断开在这里被挡掉，绝不能算上游的账。
	if res.Err != nil {
		out := ClassifyTransportErr(res.Err)
		out.TTFT = res.TTFT
		out.Status = res.Status
		return out
	}

	if res.Status >= 400 {
		out := ClassifyHTTP(res.Status, res.Header, res.ErrBody)
		out.TTFT = res.TTFT
		return out
	}

	// 200 但一个字节都没吐 —— 假活（§4.3）。这种站最容易被误判成好站：
	// 状态码正常、没有任何错误，但用户那边什么都没收到。
	//
	// 只在**确实完成**了转发时才这么判：Err 已在上面挡掉，所以走到这里
	// 说明流是正常结束的（EOF），那么零字节就是上游真的没生成任何内容。
	if res.BytesWritten == 0 {
		return Outcome{
			Verdict: health.VerdictUnavailable,
			Err:     fmt.Errorf("假活：HTTP %d 但未返回任何内容", res.Status),
			Status:  res.Status,
			TTFT:    res.TTFT,
		}
	}

	return Outcome{Verdict: health.VerdictOK, Status: res.Status, TTFT: res.TTFT}
}

// 确保 Reporter 满足 proxy 的接缝。放一个编译期断言而不是靠装配时
// 才发现：改了任一侧的签名，编译就会在这里失败，而不是在 main.go 里。
var _ proxy.HealthReporter = (*Reporter)(nil)
