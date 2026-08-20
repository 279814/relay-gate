package probe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/proxy"
	"github.com/279814/relay-gate/internal/sample"
)

// Prober 执行单次探测。Transport 由调用方按 Upstream 提供，
// 与转发路径共用连接池 —— 探活顺带把连接热着，真实请求就省了 TLS 握手。
type Prober struct {
	Transport http.RoundTripper

	// Targets 是唯一的出站 URL 来源（§7.1），与真实转发共用。
	//
	// 为 nil 时探活直接失败而**不是**自己拼一个：探活打的地址必须与真实请求
	// 完全一致，各拼一套的话「探活通过」不代表真实请求能通 —— 而这个差异
	// 只在生产流量上显形。
	Targets outbound.TargetProvider

	// Secrets 提供固定 query 里的 Probe Secret。可为 nil。
	Secrets outbound.SecretSource
}

// resolve 解析一次探活的出站目标。
//
// use 必须由调用方明确给出：同一条 legacy 记录对真实流量与合成探活的处理
// 完全不同（后者 fail closed），默认值会让这个区别静默消失。
func (p *Prober) resolve(ctx context.Context, up *model.Upstream,
	kind model.EndpointKind) (outbound.ResolvedTarget, error) {

	if p.Targets == nil {
		return outbound.ResolvedTarget{}, errors.New("探活未装配出站目标解析器")
	}
	return p.Targets.ResolveTarget(ctx, outbound.TargetInput{
		Upstream: up.ProbeConfig(),
		Endpoint: kind,
		Values: outbound.Values{
			UpstreamAPIKey:     []byte(up.APIKey),
			CredentialRevision: up.CredentialRevision,
			Secrets:            p.Secrets,
		},
		Use: outbound.ResolveSyntheticProbe,
	})
}

// probeConfigOutcome 把解析失败翻译成 Outcome。
//
// legacy 待审核与普通配置错误分开：前者是「这个站的 URL 还没人审核过」，
// 动作是提示用户去审核；后者是配置写错了。混成一类会让用户对着一个
// 「配置错误」找不到该改什么。
func probeConfigOutcome(err error) Outcome {
	if errors.Is(err, outbound.ErrLegacyNeedsReview) {
		return Outcome{Verdict: health.VerdictIgnore, Err: err}
	}
	return Outcome{Verdict: health.VerdictUnavailable, Err: err}
}

// redactOutcome 脱敏一个 Outcome 里可能含上游原文的错误。
//
// **必须做**：ClassifyHTTP 经 errFromBody 把上游响应体原文拼进了 Err，
// 而上游的鉴权错误经常把收到的 key 回显在消息里
// （`{"error":"Invalid API key: sk-xxx"}` 是常见格式）。
//
// 泄露面比日志更大：这个 Err 会流进 health.Report → 存成
// route_health.last_error（**落库**）→ 由 /admin/api/health 显示在管理界面上。
// 也就是说一个明文上游 key 会同时出现在数据库和 UI 里。
//
// 放在这里而不是 errFromBody：那个函数只收 status 与 body，拿不到 key。
// 而 Prober 的每个方法都持有 up，是能同时看到「原文」与「key」的最内层。
func redactOutcome(out Outcome, up *model.Upstream) Outcome {
	if out.Err == nil || up == nil || up.APIKey == "" {
		return out
	}
	safe := sample.RedactDiagnosticText(out.Err.Error(), []string{up.APIKey})
	if safe != out.Err.Error() {
		out.Err = errors.New(safe)
	}
	return out
}

// L1 是传输层探测（§4.1）：GET {base_url}{l1_path}，零 token。
//
// 判定规则里最关键的一条是 **404/405 视为通过**：很多站不提供 /v1/models，
// 但 /v1/messages 完全正常。把 404 当失败会把这些站整站判死 ——
// 而 L1 是 Upstream 粒度的，一次误判会连坐它下面所有 Route。
//
// l1_path 为空时只做连接层探测（HEAD base_url），给那些连 /v1/models
// 都会报错的站留一条退路。
func (p *Prober) L1(ctx context.Context, up *model.Upstream, s model.Settings) (out Outcome) {
	// 统一在出口脱敏，覆盖下面所有 return 路径（含 ClassifyHTTP 拼的上游原文）。
	// 逐个 return 包一层的话，六条返回路径漏掉任何一条就是一个泄露口，
	// 而漏掉的表现是明文 key 静默落库 —— 不报错、不失败，只有翻库才发现。
	defer func() { out = redactOutcome(out, up) }()

	ctx, cancel := context.WithTimeout(ctx, time.Duration(s.L1TotalSec)*time.Second)
	defer cancel()

	// L1 的地址由 models Endpoint 解析（迁移已把 l1_path 落成它的 url_override）。
	// 方法仍按 l1_path 决定：为空表示只探连接层（HEAD base_url），那是给
	// 「连 /v1/models 都会报错的站」留的退路，而 URL 层表达不了这个区别。
	target, err := p.resolve(ctx, up, model.EndpointModels)
	if err != nil {
		return probeConfigOutcome(err)
	}

	path := strings.TrimSpace(up.L1Path)
	method := http.MethodGet
	if path == "" {
		method = http.MethodHead
	}

	req, err := http.NewRequestWithContext(ctx, method, target.RawURL, nil)
	if err != nil {
		return Outcome{Verdict: health.VerdictUnavailable,
			Err: fmt.Errorf("构造 L1 请求: %w", err)}
	}
	req.Header = buildHeaders(up, model.ProtoAnthropic, false)
	if target.RequestHost != "" {
		req.Host = target.RequestHost
	}

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

	out = ClassifyHTTP(resp.StatusCode, resp.Header, body)
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
	rt *model.Route, s model.Settings) (out Outcome) {

	// 同 L1：统一在出口脱敏。L2 的返回路径更多（含流内错误 payload
	// 与假活分支自己拼的错误），逐个包更容易漏。
	defer func() { out = redactOutcome(out, up) }()

	ctx, cancel := context.WithTimeout(ctx, time.Duration(s.L2TotalSec)*time.Second)
	defer cancel()

	body, err := buildProbeBody(mn, rt)
	if err != nil {
		return Outcome{Verdict: health.VerdictUnavailable, Err: err}
	}

	// 出站 URL 与真实转发走同一个 Resolver：探活打的必须是真实请求会打的
	// 那个地址，包括 legacy 兼容记录这类逃生舱。两边各拼一套的话，
	// 探活成功不代表真实请求能通。
	kind, ok := mn.Protocol.Endpoint()
	if !ok {
		return Outcome{Verdict: health.VerdictUnavailable,
			Err: fmt.Errorf("协议 %q 没有对应的 Endpoint", mn.Protocol)}
	}
	target, err := p.resolve(ctx, up, kind)
	if err != nil {
		return probeConfigOutcome(err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.RawURL, strings.NewReader(string(body)))
	if err != nil {
		return Outcome{Verdict: health.VerdictUnavailable,
			Err: fmt.Errorf("构造 L2 请求: %w", err)}
	}
	req.Header = buildHeaders(up, mn.Protocol, true)
	if target.RequestHost != "" {
		req.Host = target.RequestHost
	}
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

	// 读流出错：必须在假活之前判。两者的表征相同（都是「没读到有效内容」），
	// 但原因完全不同 —— 假活是站回了 200 却不生成，读错误是超时或连接断了。
	// 报错原因指错方向的话，排查会从「站为什么不吐内容」开始，
	// 而真正该看的是「连接为什么断了」。
	case sr.scanErr != nil:
		// 探活被取消（服务暂停、进程关闭）不算上游的账。
		if out, ok := ctxOutcome(ctx, sr.scanErr); ok {
			out.TTFT = ttft
			out.Status = resp.StatusCode
			return out
		}
		// headerCtx 到期但外层 ctx 还没到 —— 首 Token 超时。
		// 响应头虽然回来了，但流内迟迟不出内容，本质上还是首 Token 没等到。
		if headerCtx.Err() != nil {
			return Outcome{
				Verdict: health.VerdictUnavailable,
				Err: fmt.Errorf("%w: 响应头已返回但 %ds 内无有效内容",
					proxy.ErrFirstTokenTimeout, s.L2FirstTokenSec),
				TTFT:   ttft,
				Status: resp.StatusCode,
			}
		}
		return Outcome{
			Verdict: health.VerdictUnavailable,
			Err:     fmt.Errorf("%w: %v", proxy.ErrStreamBroke, sr.scanErr),
			TTFT:    ttft,
			Status:  resp.StatusCode,
		}

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
