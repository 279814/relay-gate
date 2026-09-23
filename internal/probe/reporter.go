package probe

import (
	"bytes"
	"fmt"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/proxy"
)

// Reporter 把真实请求的结果翻译成健康判定，是 proxy.HealthReporter 的实现。
//
// P0-10：Capability/Reachability 的权威写回走 ResultRecorder + CommitProbeObservation；
// 本 Reporter 仍是临时 adapter，只把真实流量结果喂给旧 RouteHealth Tracker
// （完整真实观察与 RecoveryGate 属 P0-13 / P1）。与探活共用分类器，避免
// 「429 / 客户端断开」规则在两边分叉。
type Reporter struct {
	track Tracker
}

func NewReporter(track Tracker) *Reporter { return &Reporter{track: track} }

// ReportResult 上报一次真实转发的结果（§3.5）。
//
// 非阻塞：全程只做内存里的状态更新，没有 I/O。
// generation 来自选路占位；与当前 RouteHealth 世代不一致则丢弃。
func (r *Reporter) ReportResult(routeID int64, generation uint64, res *proxy.ResultView) {
	out := classifyReal(res)
	if out.Verdict == health.VerdictIgnore {
		return
	}

	r.track.Report(health.Report{
		RouteID: routeID, Generation: generation,
		Verdict: out.Verdict, Source: health.SourceReal,
		Err: out.Err, TTFT: out.TTFT, RetryAfter: out.RetryAfter,
	})

	// §8.10：真实成功等价一次 L2 —— lastRealOKAt 已由上面 SourceReal+OK 写入；
	// CompleteL2 立即把下次到期推到窗口末尾。结构化 200 error 走不到这里。
	if out.Verdict == health.VerdictOK {
		if completer, ok := r.track.(interface {
			CompleteL2(routeID int64, completedAt time.Time, jitter float64)
		}); ok {
			completer.CompleteL2(routeID, time.Now(), 0)
		}
		return
	}

	// §4.5：真实请求失败立即触发探活，不等定时周期。
	//
	// 为什么失败了还要探：真实请求的失败可能是偶发（一次网络抖动），
	// 也可能是站真挂了。探活能在几秒内给出第二个独立的判断，
	// 而不是等下一个用户请求撞上来 —— 那可能是几分钟之后。
	r.track.TriggerL2(routeID)
}

// TriggerProbe 请求立即探活一次。
func (r *Reporter) TriggerProbe(routeID int64) { r.track.TriggerL2(routeID) }

// classifyReal 把一次真实转发的结果归类。
//
// 判定顺序：先看传输层错误（连不上、超时、客户端断开），再看 HTTP 状态码，
// 再看「200 结构化 error」（§6.8 / §8.12），再看「200 但没吐字节」的假活，
// 最后要求 SemanticSeen（§6.8 / §8.8）—— 有字节的 HTML/空壳流也不能 piggyback。
// 顺序不能反 —— 传输层失败时 Status 可能是 0（连响应头都没拿到），按状态码
// 判会当成「未知的成功」；结构化 error 若按 200 判活会跳过 L2 并把 Route 拉活。
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

	ct := ""
	if res.Header != nil {
		ct = res.Header.Get("Content-Type")
	}
	// §8.12：HTTP 200 结构化 error 按错误码细分，不得按 200 判活。
	if proxy.IsStructuredErrorPayload(res.ErrBody, ct) {
		out := classifyStructured200(res)
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

	// §6.8 / §8.8：2xx 结束但从未出现 Semantic Evidence 不得判活、不得
	// piggyback。空 200 已在上面挡住；这里挡住「有字节但无模型输出」
	//（HTML 错误页、只有 message_start/ping 的流等）。
	if !res.SemanticSeen {
		return Outcome{
			Verdict: health.VerdictUnavailable,
			Err:     fmt.Errorf("假活：HTTP %d 但未见语义证据", res.Status),
			Status:  res.Status,
			TTFT:    res.TTFT,
		}
	}

	return Outcome{Verdict: health.VerdictOK, Status: res.Status, TTFT: res.TTFT}
}

// classifyStructured200 把 HTTP 2xx 的结构化 error 载荷映射到 RouteHealth 判定。
//
// 与 ResponseClassifier.applyRemoteError 对齐限流特征；其余一律 Unavailable
// （累计失败，不按 200 拉活）。鉴权/形态类不走 VerdictFatal：§8.12 的
// config_error 不伪装成 dead，完整 Capability 回写另有路径。
func classifyStructured200(res *proxy.ResultView) Outcome {
	body := res.ErrBody
	if len(body) > maxClassifyBody {
		body = body[:maxClassifyBody]
	}
	lower := bytes.ToLower(body)
	if containsAny(lower, rateLimitMarkers) {
		return Outcome{
			Verdict:    health.VerdictRateLimited,
			Err:        errFromBody(res.Status, body),
			RetryAfter: parseRetryAfter(res.Header),
			Status:     res.Status,
		}
	}
	return Outcome{
		Verdict: health.VerdictUnavailable,
		Err:     errFromBody(res.Status, body),
		Status:  res.Status,
	}
}

// 确保 Reporter 满足 proxy 的接缝。放一个编译期断言而不是靠装配时
// 才发现：改了任一侧的签名，编译就会在这里失败，而不是在 main.go 里。
var _ proxy.HealthReporter = (*Reporter)(nil)
