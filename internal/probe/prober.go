package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/proxy"
)

// Prober 执行单次探测。Transport 由调用方按 Upstream 提供，
// 与转发路径共用连接池 —— 探活顺带把连接热着，真实请求就省了 TLS 握手。
type Prober struct {
	Transport http.RoundTripper
}

// L1 是传输层探测（§4.1）：GET {base_url}{l1_path}，零 token。
//
// 判定规则里最关键的一条是 **404/405 视为通过**：很多站不提供 /v1/models，
// 但 /v1/messages 完全正常。把 404 当失败会把这些站整站判死 ——
// 而 L1 是 Upstream 粒度的，一次误判会连坐它下面所有 Route。
//
// l1_path 为空时只做连接层探测（HEAD base_url），给那些连 /v1/models
// 都会报错的站留一条退路。
func (p *Prober) L1(ctx context.Context, up *model.Upstream, s model.Settings) Outcome {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(s.L1TotalSec)*time.Second)
	defer cancel()

	path := strings.TrimSpace(up.L1Path)
	method, target := http.MethodGet, strings.TrimRight(up.BaseURL, "/")
	if path == "" {
		// 只探连接层：HEAD 根地址，不关心状态码，能建立连接就算通。
		method = http.MethodHead
	} else {
		target += path
	}

	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return Outcome{Verdict: health.VerdictUnavailable,
			Err: fmt.Errorf("构造 L1 请求: %w", err)}
	}
	req.Header = buildHeaders(up, model.ProtoAnthropic, false)

	start := time.Now()
	resp, err := p.Transport.RoundTrip(req)
	if err != nil {
		if out, ok := ctxOutcome(ctx, err); ok {
			return out
		}
		return Outcome{Verdict: health.VerdictUnavailable,
			Err: fmt.Errorf("%w: %v", proxy.ErrConnect, err)}
	}
	defer resp.Body.Close()

	// 只读开头：L1 只需要状态码与少量错误特征，而 /v1/models 在
	// 模型多的站上能有几十 KB —— 全读一遍纯属浪费。
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxClassifyBody))
	ttft := time.Since(start)

	// 连接层探测：能拿到任何响应就算通。
	if path == "" {
		return Outcome{Verdict: health.VerdictOK, TTFT: ttft, Status: resp.StatusCode}
	}

	// 404/405 视为通过 —— 站不提供这个端点不等于站挂了。
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		return Outcome{Verdict: health.VerdictOK, TTFT: ttft, Status: resp.StatusCode}
	}

	out := ClassifyHTTP(resp.StatusCode, resp.Header, body)
	out.TTFT = ttft
	return out
}

// L2 是模型层探测（§4.1）：用 Route 的真实配置发一次最小的流式请求。
//
// 必须 stream:true —— 非流式只能测总时长，测不出首 Token 时间，
// 而「首 Token 慢」正是公益站最典型的劣化形态。
//
// 读到首个有效事件后立即返回并关闭响应体，不再消耗上游 token（§4.1）。
func (p *Prober) L2(ctx context.Context, up *model.Upstream, mn *model.ModelName,
	rt *model.Route, s model.Settings) Outcome {

	ctx, cancel := context.WithTimeout(ctx, time.Duration(s.L2TotalSec)*time.Second)
	defer cancel()

	body, err := buildProbeBody(mn, rt)
	if err != nil {
		return Outcome{Verdict: health.VerdictUnavailable, Err: err}
	}

	// 出站 URL 与真实转发走同一个函数：探活打的必须是真实请求会打的那个
	// 地址，包括 full_url_mode 这类逃生舱。两边各拼一套的话，
	// 探活成功不代表真实请求能通。
	target, err := proxy.BuildOutboundURL(up, mn.Protocol.Path(), "")
	if err != nil {
		return Outcome{Verdict: health.VerdictUnavailable, Err: err}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(string(body)))
	if err != nil {
		return Outcome{Verdict: health.VerdictUnavailable,
			Err: fmt.Errorf("构造 L2 请求: %w", err)}
	}
	req.Header = buildHeaders(up, mn.Protocol, true)
	req.ContentLength = int64(len(body))

	// 响应头阶段单独设时限，理由同转发路径（forward.go）：
	// 一个「收下请求但不回响应头」的站，只靠 Total 兜底会占满整个探测窗口。
	headerCtx, headerCancel := context.WithCancel(ctx)
	headerTimer := time.AfterFunc(time.Duration(s.L2FirstTokenSec)*time.Second, headerCancel)
	req = req.WithContext(headerCtx)

	start := time.Now()
	resp, err := p.Transport.RoundTrip(req)
	if err != nil {
		headerTimer.Stop()
		headerCancel()
		if out, ok := ctxOutcome(ctx, err); ok {
			return out
		}
		// headerCtx 到期但外层 ctx 还没到 —— 是首 Token 超时，算上游的账。
		if headerCtx.Err() != nil {
			return Outcome{Verdict: health.VerdictUnavailable,
				Err: fmt.Errorf("%w: 响应头超过 %ds 未返回",
					proxy.ErrFirstTokenTimeout, s.L2FirstTokenSec)}
		}
		return Outcome{Verdict: health.VerdictUnavailable,
			Err: fmt.Errorf("%w: %v", proxy.ErrConnect, err)}
	}
	// 判定一出就关流，停止消耗上游 token（§4.1）。cancel 也要调 ——
	// 只 Close 不 cancel 会让 headerCtx 泄漏到 GC 才回收。
	defer func() {
		headerTimer.Stop()
		resp.Body.Close()
		headerCancel()
	}()

	if resp.StatusCode >= 400 {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxClassifyBody))
		out := ClassifyHTTP(resp.StatusCode, resp.Header, errBody)
		out.TTFT = time.Since(start)
		return out
	}

	// 首 Token 计时从这里才停：响应头回来不代表模型开始生成，
	// 长思考的站会先回 200 再沉默几十秒。
	var ttft time.Duration
	sr := scanStream(resp.Body, func() { ttft = time.Since(start) })

	switch {
	case sr.alive:
		return Outcome{Verdict: health.VerdictOK, TTFT: ttft, Status: resp.StatusCode}

	case len(sr.errPayload) > 0:
		// 200 但流内报错。这是公益站最常见的假活之一，只看状态码会完全漏判。
		// 交给 ClassifyHTTP 按内容分类：overloaded 是限流，其余算不可用。
		out := ClassifyHTTP(streamErrStatus(sr.errPayload), resp.Header, sr.errPayload)
		out.TTFT = ttft
		out.Status = resp.StatusCode
		return out

	default:
		// 200 但没有任何有效 delta —— 另一种假活。
		return Outcome{
			Verdict: health.VerdictUnavailable,
			Err: fmt.Errorf("假活：HTTP %d 但流内无有效内容（读了 %d 字节）",
				resp.StatusCode, sr.bytesRead),
			TTFT:   ttft,
			Status: resp.StatusCode,
		}
	}
}

// streamErrStatus 给流内错误配一个用于分类的状态码。
//
// 流内错误没有自己的 HTTP 状态码（外层是 200），但 ClassifyHTTP 的
// 关键词分支要求 status >= 400 才生效。用 500 作为「有错误但不知道类别」
// 的占位：它会让 overloaded 之类的关键词正常命中限流分支，
// 其余落到「服务不可用」—— 与流内错误的实际语义一致。
func streamErrStatus(payload []byte) int {
	// 若上游在 payload 里自报了状态码就用它，能让 401 之类的
	// 流内鉴权错误也走到 Fatal 分支。
	var probe struct {
		Error struct {
			Code   int    `json:"code"`
			Status int    `json:"status"`
			Type   string `json:"type"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &probe); err == nil {
		if c := probe.Error.Code; c >= 400 && c < 600 {
			return c
		}
		if c := probe.Error.Status; c >= 400 && c < 600 {
			return c
		}
	}
	return http.StatusInternalServerError
}

// buildProbeBody 按协议构造最小探活请求（§4.1）。
//
// 三种协议的参数名不同（§3.3.1），且 Responses 协议的 max_output_tokens
// 不能给 1 —— 实测部分站直接拒绝，默认值里已按协议区分（model.Defaults）。
func buildProbeBody(mn *model.ModelName, rt *model.Route) ([]byte, error) {
	// 上游模型名：配了映射用映射后的，没配就用 ModelName 原名。
	// 这与转发路径的规则一致（§3.3.2），否则探的模型和真实请求打的
	// 不是同一个 —— 探活通过但真实请求 model_not_found。
	name := mn.Name
	if rt != nil && rt.UpstreamModel != "" {
		name = rt.UpstreamModel
	}

	prompt := mn.ProbePrompt
	if prompt == "" {
		prompt = "1+1=?"
	}
	maxTok := mn.ProbeMaxTokens
	if maxTok <= 0 {
		maxTok = 1
	}

	var payload map[string]any
	switch mn.Protocol {
	case model.ProtoAnthropic:
		payload = map[string]any{
			"model":      name,
			"max_tokens": maxTok,
			"stream":     true,
			"messages": []map[string]any{
				{"role": "user", "content": prompt},
			},
		}
	case model.ProtoOpenAIChat:
		payload = map[string]any{
			"model":      name,
			"max_tokens": maxTok,
			"stream":     true,
			"messages": []map[string]any{
				{"role": "user", "content": prompt},
			},
		}
	case model.ProtoOpenAIResponses:
		if maxTok < 16 {
			// 实测 max_output_tokens=1 会被部分站直接拒绝
			maxTok = 16
		}
		payload = map[string]any{
			"model":             name,
			"max_output_tokens": maxTok,
			"stream":            true,
			"input":             prompt,
		}
	default:
		return nil, fmt.Errorf("未知协议 %q", mn.Protocol)
	}

	return json.Marshal(payload)
}
