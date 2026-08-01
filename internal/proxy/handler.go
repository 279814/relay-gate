package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/sample"
	"github.com/279814/relay-gate/internal/store"
)

// MaxRequestBody 是入站 body 上限。
//
// Claude Code 的请求含完整对话历史、工具定义与可能的图片，几 MB 是常态。
// 给 32MB 是宽松的上限，防的是异常请求打爆内存，不是限制正常使用。
const MaxRequestBody = 32 << 20

// ConfigSource 提供选路所需的配置快照与设置。
// 定义为接口便于测试替换，也为将来加缓存留出位置。
type ConfigSource interface {
	Snapshot() (*router.Snapshot, error)
	Settings() (model.Settings, error)
	RunState() (store.RunState, error)
}

// SampleSink 接收样本。由 sample.Recorder 实现，可为 nil（关闭样本记录）。
//
// Record 必须是**非阻塞**的：它在转发路径上被调用，阻塞就等于让
// 「记日志」拖慢真实请求（§3.6.3a）。
type SampleSink interface {
	Record(*model.Sample)
}

// Handler 处理三个透传端点。
type Handler struct {
	cfg     ConfigSource
	health  router.HealthView
	samples SampleSink
	log     *slog.Logger

	// reporter 接收真实请求的健康结论。可为 nil（不做健康回写）。
	reporter HealthReporter

	// relayKeys 是入站合法凭据集合。
	relayKeys map[string]bool

	// transports 按 Upstream 缓存，避免每请求新建（那会丢掉连接复用，
	// 每次都要重新 TLS 握手 —— 对高延迟的公益站代价很大）。
	// 存 key 是为了在配置变更后能发现缓存已过期，见 TransportFor。
	mu         sync.RWMutex
	transports map[int64]transportEntry
}

// transportEntry 是一个缓存的 Transport 及其对应的配置指纹。
type transportEntry struct {
	key string
	tr  *http.Transport
}

// NewHandler 组装透传处理器。
//
// samples 可为 nil，表示不记录样本。
func NewHandler(cfg ConfigSource, health router.HealthView,
	samples SampleSink, relayKeys []string, log *slog.Logger) *Handler {

	keys := make(map[string]bool, len(relayKeys))
	for _, k := range relayKeys {
		if k = strings.TrimSpace(k); k != "" {
			keys[k] = true
		}
	}
	return &Handler{
		cfg: cfg, health: health, samples: samples, log: log,
		relayKeys:  keys,
		transports: map[int64]transportEntry{},
	}
}

// WithHealthReporter 接上真实请求的健康回写（§3.5）。
//
// 分成单独的 setter 而不是加构造参数：健康回写是可选的（M2 的测试与
// 冒烟脚本都不需要它），而 NewHandler 的参数已经有五个了。
func (h *Handler) WithHealthReporter(r HealthReporter) *Handler {
	h.reporter = r
	return h
}

// Routes 注册透传端点。三个协议路径 1:1 对应上游同名路径（§3.1）。
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/messages", h.handle(model.ProtoAnthropic))
	mux.HandleFunc("POST /v1/responses", h.handle(model.ProtoOpenAIResponses))
	mux.HandleFunc("POST /v1/chat/completions", h.handle(model.ProtoOpenAIChat))

	// M4: 附加端点（§3.1）
	mux.HandleFunc("POST /v1/messages/count_tokens", h.handleCountTokens)
	mux.HandleFunc("GET /v1/models", h.handleModels)
}

func (h *Handler) handle(proto model.Protocol) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.serve(w, r, proto)
	}
}

// preambleResult 是 preamble 已经完成的那几步的产物。
type preambleResult struct {
	settings model.Settings
	body     []byte
	inModel  string
	snapshot *router.Snapshot
}

// preamble 跑完所有端点共用的前半段：鉴权 → 总闸 → 设置 → 读 body →
// 取 model → 读快照。任何一步失败都已经写好了错误响应，此时返回 ok=false，
// 调用方直接 return 即可。
//
// 抽出来是给 count_tokens 用的（§10.3）：它与 serve 的前半段完全相同，
// 但后半段差别很大（非流式、超时独立、失败不计健康、要本地兜底）。
// 整个复用 serve 会让它长出一堆 if；各写一份则迟早在一边漏掉总闸或鉴权 ——
// 而漏掉鉴权就是把所有上游 key 公开（§5.2f）。
func (h *Handler) preamble(w http.ResponseWriter, r *http.Request,
	proto model.Protocol) (*preambleResult, bool) {

	// 1. 入站鉴权。服务暴露公网时这是唯一屏障 —— 缺了它等于把所有
	//    上游 key 免费公开（§5.2f）。
	if !h.authOK(r) {
		writeAPIError(w, http.StatusUnauthorized, proto,
			"authentication_error", "无效的 API key")
		return nil, false
	}

	// 2. 服务总闸（§4.8）。暂停时拒绝新请求，但不影响已建立的流。
	state, err := h.cfg.RunState()
	if err != nil {
		h.log.Error("读取运行状态失败", "err", err)
		writeAPIError(w, http.StatusInternalServerError, proto, "api_error", "内部错误")
		return nil, false
	}
	if state == store.StatePaused {
		w.Header().Set("X-Relay-State", "paused")
		writeAPIError(w, http.StatusServiceUnavailable, proto, "overloaded_error",
			"服务已暂停。在管理界面点「启动」后恢复")
		return nil, false
	}

	settings, err := h.cfg.Settings()
	if err != nil {
		h.log.Error("读取设置失败", "err", err)
		writeAPIError(w, http.StatusInternalServerError, proto, "api_error", "内部错误")
		return nil, false
	}

	// 3. 读 body。必须整体读入：改 model 要定位偏移量，重试要能重放。
	body, err := ReadBodyLimited(r.Body, MaxRequestBody)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, proto, "invalid_request_error",
			fmt.Sprintf("读取请求体失败: %v", err))
		return nil, false
	}

	// 4. 取出 model 值用于选路。只读不改。
	inModel, err := ExtractModel(body)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, proto, "invalid_request_error",
			fmt.Sprintf("无法确定请求的 model: %v", err))
		return nil, false
	}

	// 5. 读配置快照
	snap, err := h.cfg.Snapshot()
	if err != nil {
		h.log.Error("读取配置快照失败", "err", err)
		writeAPIError(w, http.StatusInternalServerError, proto, "api_error", "内部错误")
		return nil, false
	}

	return &preambleResult{
		settings: settings, body: body, inModel: inModel, snapshot: snap,
	}, true
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request, proto model.Protocol) {
	recvAt := time.Now()

	pre, ok := h.preamble(w, r, proto)
	if !ok {
		return
	}
	// 6~8. 选路 → 改两处 → 转发，失败时按 §3.5 换站重试。
	//
	// 并发额度由 forwardWithRetry 全程持有并归还：重试会依次占用多个 Route
	// 的额度，而被丢弃的那次必须**立刻**还 —— 攒到函数出口统一还的话，
	// 一次三连重试就会同时占住三个站的额度，把并发上限当场翻三倍。
	oc, ok := h.forwardWithRetry(w, r, proto, pre)
	if !ok {
		return // 错误响应已写好（选路失败或配置错误）
	}
	res, keys := oc.res, oc.keys

	h.logResult(oc.cand, pre.inModel, oc.outURL, res, oc.attempts)

	// 9. 健康回写。**这是最快的故障发现路径** —— 探活有周期（dead 状态
	//    20 秒），真实请求没有延迟，站挂掉那一刻就有请求撞上去（§3.5）。
	//    放在写错误响应之前：客户端已经在等了，先把状态记下来，
	//    下一个请求就能绕开这个站。
	//
	//    这里回写的是**最终**那次尝试。被丢弃的尝试已经在重试循环里各自
	//    回写过了（那是 §3.5 要求的「任何失败都立刻回写」）。
	//
	//    传 key 是为了脱敏 ErrBody：它会一路流进 route_health.last_error
	//    并显示在管理界面上，而上游的鉴权错误常把 key 回显在里面（见 viewOf）。
	if h.reporter != nil {
		h.reporter.ReportResult(oc.cand.Route.ID, viewOf(res, keys))
	}

	// 转发在写出响应头之前失败时，**必须**由我们回一个错误响应。
	// 不写的话 net/http 会在 handler 返回时补一个 HTTP 200 空 body ——
	// 客户端拿到「成功但没内容」，既看不到原因也不会重试。
	if res.Err != nil && !res.HeadersSent {
		h.writeForwardError(w, res.Err, proto, oc.cand, keys)
	}

	if oc.respTee != nil {
		h.recordSample(r, proto, oc.cand, recvAt, pre.inModel, pre.body, oc.outBody,
			oc.outHeader, oc.outURL, oc.respTee, res, pre.settings, keys)
	}
}

// halfOpen 在「全部 Route 都 dead」时放行一次试探（§4.4c）。
//
// 为什么需要它：所有站都被判死之后，若直接回 503，就只能干等下一轮探活
// （dead 状态 L2 是 30 秒）。而站可能刚刚恢复 —— 那 30 秒里的每个请求都
// 白白失败了。半开让真实流量自己去试，成功则立即转 unknown（可用）。
//
// 只在 ErrNoRouteAvailable 时尝试。模型没配（404）或协议不匹配（400）
// 是配置错误，放行多少次都不会好，试探只是把一个明确的错误变成一次超时。
//
// 返回 nil 表示不该半开，调用方按原错误作答。
func (h *Handler) halfOpen(snap *router.Snapshot, inModel string,
	proto model.Protocol, settings model.Settings, selErr error) *router.Candidate {

	if !settings.HalfOpenEnabled || !errors.Is(selErr, router.ErrNoRouteAvailable) {
		return nil
	}
	mn, err := router.MatchModelName(snap, inModel, proto)
	if err != nil || mn.Protocol != proto {
		return nil
	}

	// DeadRoutesFor 已按优先级升序排好，取第一个能占到额度的。
	// 它返回 *model.Route 而不是 Candidate，所以并发额度要自己占 ——
	// 不占的话半开会绕过 max_concurrency，而一个刚恢复的站最不该被打爆。
	for _, rt := range router.DeadRoutesFor(snap, h.health, mn) {
		up := snap.Upstreams[rt.UpstreamID]
		if up == nil {
			continue
		}
		release, ok := h.health.TryAcquire(rt.ID, rt.MaxConcurrency)
		if !ok {
			continue
		}
		h.log.Info("全部 Route 均 dead，半开放行一次试探",
			"model", inModel, "upstream", up.Name, "route", rt.ID)
		return router.NewCandidate(rt, up, mn, release)
	}
	return nil
}

// writeForwardError 把转发失败翻译成客户端能理解的 HTTP 错误。
//
// 只在响应头尚未发出时可用 —— 已经发出后状态码就定死了，
// 再往流里写错误结构只会破坏客户端的 SSE 解析。
//
// redactKeys 是本次请求涉及的凭据。**必须脱敏**：err 的文本里可能带出站
// URL，而 full_url_mode 的 base_url 允许把 key 放在 query 里（§3.2）。
// 客户端是外部的 —— 持有 relay key 不等于有资格看到上游 key。
//
// 当前标准库恰好不会把 URL 放进错误里（forward.go 直接调 Transport.RoundTrip，
// 而带 URL 的 *url.Error 是 http.Client.Do 包的），所以这层脱敏此刻扫不到
// 东西。留着是因为那条性质**不由我们控制**：改用 *http.Client 是个完全自然
// 的重构，而它会让上游 key 静默出现在客户端的错误响应里。
// 有 TestErrorResponse_NeverEchoesUpstreamKeyFromURL 钉着这条不变量。
func (h *Handler) writeForwardError(w http.ResponseWriter, err error,
	proto model.Protocol, cand *router.Candidate, redactKeys []string) {

	// 客户端自己走了就别再写了：连接多半已经没了，写也是白写。
	if !IsUpstreamFault(err) {
		return
	}

	safeErr := sample.RedactDiagnosticText(err.Error(), redactKeys)

	// X-Relay-Reason 让 502/504 可诊断：不带它的话，客户端只看到
	// 「网关错误」，分不清是站连不上、超时，还是我们自己配错了。
	w.Header().Set("X-Relay-Reason", safeErr)
	w.Header().Set("X-Relay-Upstream", cand.Upstream.Name)

	code, msg := http.StatusBadGateway, "上游站点不可用"
	switch {
	case errors.Is(err, ErrFirstTokenTimeout):
		code, msg = http.StatusGatewayTimeout, "上游站点未在时限内开始响应"
	case errors.Is(err, ErrStreamStalled):
		code, msg = http.StatusGatewayTimeout, "上游站点响应中断"
	case errors.Is(err, ErrTotalTimeout):
		code, msg = http.StatusGatewayTimeout, "请求超过总时限"
	}
	writeAPIError(w, code, proto, "api_error",
		fmt.Sprintf("%s（%s）：%s", msg, cand.Upstream.Name, safeErr))
}

// recordSample 组装并投递一条样本（§3.6）。
//
// 全程只读转发路径产生的数据，绝不回写；投递是非阻塞的，
// 队列满就丢。任何在这里发生的问题都不该影响已经完成的转发。
//
// settings 由调用方传入而不是在这里重读：serve 开头已经读过一次，
// 重读一次既多一次 livecfg 加锁，又可能拿到与转发时不同的值 ——
// 样本描述的是**这次**转发，用的必须是它当时那份配置。
//
// keys 同样由调用方传入（它只有两处来源：入站 relay key 与出站上游 key）。
// 与健康回写、出站错误响应共用同一份，避免各算一遍时漏掉某个凭据位置。
func (h *Handler) recordSample(r *http.Request, proto model.Protocol,
	cand *router.Candidate, recvAt time.Time, inModel string,
	inBody, outBody []byte, outHeader http.Header, outURL string,
	respTee *sample.HeadTail, res *Result, settings model.Settings,
	keys []string) {

	// 先截断再脱敏（PrepareBody 内部保证顺序安全）：body 上限 32MB，
	// 而留档上限默认 256KB，先扫全量等于为了丢掉的 99% 白扫一遍。
	inTrunc, inCut := sample.PrepareBody(inBody, keys, settings.SampleMaxBodyBytes)
	outTrunc, outCut := sample.PrepareBody(outBody, keys, settings.SampleMaxBodyBytes)
	// 响应体同样要扫。上游的鉴权错误经常把 key 回显在消息里
	// （`{"error":"Invalid API key: sk-xxx"}` 是常见格式），
	// 漏掉这一处，样本库里就会躺着明文 key —— §3.6.3b 的要求是无条件的。
	// 它已被 HeadTail 限长，不需要再截。
	respSafe := sample.RedactBodyKeys(respTee.Bytes(), keys)

	var flags model.TruncFlags
	if inCut {
		flags |= model.TruncInBody
	}
	if outCut {
		flags |= model.TruncOutBody
	}
	if respTee.Truncated() {
		flags |= model.TruncRespBody
	}

	modelOut := inModel
	if cand.Route.UpstreamModel != "" {
		modelOut = cand.Route.UpstreamModel
	}

	smp := &model.Sample{
		TSRecv:      recvAt.UnixMilli(),
		TSSent:      msOrZero(res.SentAt),
		TSFirstByte: msOrZero(res.FirstByteAt),
		TSDone:      msOrZero(res.DoneAt),

		Endpoint:    proto.Path(),
		ModelIn:     inModel,
		ModelOut:    modelOut,
		ModelNameID: cand.ModelName.ID,
		RouteID:     cand.Route.ID,
		UpstreamID:  cand.Upstream.ID,

		InMethod: r.Method,
		InPath:   r.URL.Path,
		// query 与 URL 也要脱敏：§3.2 提到少数站接受 ?key=<key>，
		// 而 full_url_mode 的 base_url 会被整段存进 out_url。
		// 只清头和 body 满足不了 §9.4 的「真 key 全表 grep 零命中」。
		InQuery:   sample.RedactText(r.URL.RawQuery, keys),
		InHeaders: sample.RedactHeaders(r.Header),
		InBody:    inTrunc,

		OutURL:     sample.RedactText(outURL, keys),
		OutHeaders: sample.RedactHeaders(outHeader),
		OutBody:    outTrunc,

		RespStatus: res.Status,
		// 响应头也要过脱敏：上游可能回 Set-Cookie，也可能把 key 回显在
		// 自定义头里。三组头走同一条规则，不留例外。
		RespHeaders: sample.RedactHeaders(res.RespHeaders),
		RespBody:    respSafe,

		Outcome:   classifyOutcome(res),
		Truncated: flags,
	}
	if res.Err != nil {
		smp.Error = res.Err.Error()
	}
	h.samples.Record(smp)
}

func msOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

// classifyOutcome 把转发结果映射到 §3.6.2 的 outcome 分类。
func classifyOutcome(res *Result) model.Outcome {
	switch {
	case errors.Is(res.Err, ErrFirstTokenTimeout), errors.Is(res.Err, ErrStreamStalled):
		return model.OutcomeTimeout
	case errors.Is(res.Err, ErrClientGone), errors.Is(res.Err, ErrCanceled):
		return model.OutcomeClientAbort
	case res.Err != nil:
		return model.OutcomeUpstreamError
	case res.Status >= 400:
		return model.OutcomeUpstreamError
	case res.BytesWritten == 0:
		// 200 但一个字节都没吐。这种站最容易被误判成好站 ——
		// 状态码正常，实际完全不可用（§4.3）。
		return model.OutcomeFakeAlive
	}
	return model.OutcomeOK
}

// credentialsOf 收齐这次请求涉及的全部凭据，供脱敏使用。
//
// 两处来源：出站的上游 key 与入站的 relay key。位置清单走
// inboundCredentials（其内部读 model.AuthHeaders，是唯一来源）——
// 各列一份的话，新增一个鉴权位置时必然漏掉其中之一，而漏掉的表现是
// 明文 key 静默落库或进日志，不报错、不失败。
//
// 三个消费方共用它：样本落库（recordSample）、健康回写的 ErrBody
// （viewOf）、count_tokens 的降级日志。
func (h *Handler) credentialsOf(r *http.Request, cand *router.Candidate) []string {
	keys := make([]string, 0, len(model.AuthHeaders)+1)
	keys = append(keys, cand.Upstream.APIKey)
	return append(keys, inboundCredentials(r.Header)...)
}

// inboundCredentials 取出入站请求里所有位置上的凭据值。
//
// 位置清单来自 model.AuthHeaders（唯一来源）。鉴权与样本脱敏都用它：
// 两者必须看同一组位置 —— 某个位置能过鉴权却不被脱敏，就等于让一个
// 有效的 relay key 明文落库。
func inboundCredentials(h http.Header) []string {
	out := make([]string, 0, len(model.AuthHeaders))
	for _, name := range model.AuthHeaders {
		v := strings.TrimSpace(h.Get(name))
		// scheme 前缀不是凭据本身。Bearer 最常见，Basic 在中转站上没见过，
		// 但剥掉任何 "<scheme> <cred>" 形式的前缀总是对的。
		if i := strings.IndexByte(v, ' '); i > 0 {
			v = strings.TrimSpace(v[i+1:])
		}
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// authOK 三个位置都认，因为不同协议的客户端习惯不同（§3.2）。
func (h *Handler) authOK(r *http.Request) bool {
	if len(h.relayKeys) == 0 {
		return false // 未配置 key 时一律拒绝，绝不放开
	}
	for _, c := range inboundCredentials(r.Header) {
		if h.relayKeys[c] {
			return true
		}
	}
	return false
}

// TransportFor 按 Upstream 缓存 Transport，保住连接复用。
//
// 导出是为了让探活共用同一个连接池（probe.TransportSource）：探活顺带
// 把连接热着，真实请求就省掉一次 TLS 握手 —— 对高延迟的公益站，
// 握手占首字节的可观比例。各建一套连接池的话这份收益就没了，
// 还会多出一倍空闲连接。
//
// 缓存键必须包含**所有影响 Transport 行为的配置**，不能只用 upstream ID：
// 只按 ID 缓存的话，用户在管理界面改了 proxy_url，配置确实存进去了、
// API 也回显了新值，但出站流量还是绕过代理 —— 直到重启为止。
// 这类「看起来生效了其实没有」的问题排查成本极高。
//
// 旧 Transport 在被顶替时要关掉空闲连接，否则改一次配置就漏一批连接。
func (h *Handler) TransportFor(up *model.Upstream, s model.Settings) (*http.Transport, error) {
	key := transportKey(up, s)

	h.mu.RLock()
	ent, ok := h.transports[up.ID]
	h.mu.RUnlock()
	if ok && ent.key == key {
		return ent.tr, nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if ent, ok := h.transports[up.ID]; ok {
		if ent.key == key {
			return ent.tr, nil // 双检：可能在等锁期间已被别的请求建好
		}
		// 配置变了。关掉旧的空闲连接再丢弃 —— 在途请求持有自己的引用，
		// 不受影响；空闲连接不关就永远漏在那里。
		ent.tr.CloseIdleConnections()
	}
	tr, err := NewTransport(up.ProxyURL, time.Duration(s.RealConnectSec)*time.Second)
	if err != nil {
		return nil, err
	}
	h.transports[up.ID] = transportEntry{key: key, tr: tr}
	return tr, nil
}

// transportKey 把影响 Transport 构造的配置拼成一个可比较的键。
// 加字段到 NewTransport 时**必须**同步加到这里，否则该配置就是死的。
func transportKey(up *model.Upstream, s model.Settings) string {
	return up.ProxyURL + "\x00" + strconv.Itoa(s.RealConnectSec)
}

// CloseIdleConnections 关闭所有缓存 Transport 的空闲连接，供优雅关闭调用。
func (h *Handler) CloseIdleConnections() {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, ent := range h.transports {
		ent.tr.CloseIdleConnections()
	}
}

// InvalidateTransport 丢弃某个 Upstream 的 Transport。
//
// 常规的配置变更不需要调它 —— TransportFor 的缓存键已经包含了
// proxy_url 与连接超时，改了会自动重建。这个方法留给「配置没变但连接池
// 本身要重置」的场景（例如探活判定整站不可用后主动断开所有连接）。
func (h *Handler) InvalidateTransport(upstreamID int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ent, ok := h.transports[upstreamID]; ok {
		ent.tr.CloseIdleConnections()
		delete(h.transports, upstreamID)
	}
}

func (h *Handler) writeSelectError(w http.ResponseWriter, err error,
	proto model.Protocol, inModel string) {

	// X-Relay-Reason 让 503 可诊断：不带它的话，客户端只看到「服务不可用」，
	// 分不清是配置错了还是所有站都挂了。
	w.Header().Set("X-Relay-Reason", err.Error())

	switch {
	case errors.Is(err, router.ErrModelNotFound):
		writeAPIError(w, http.StatusNotFound, proto, "not_found_error",
			fmt.Sprintf("模型 %q 未配置。请在管理界面添加对应的 ModelName", inModel))
	case errors.Is(err, router.ErrProtocolMismatch):
		writeAPIError(w, http.StatusBadRequest, proto, "invalid_request_error", err.Error())
	case errors.Is(err, router.ErrNoRouteAvailable):
		h.log.Warn("无可用 Route", "model", inModel, "err", err)
		writeAPIError(w, http.StatusServiceUnavailable, proto, "overloaded_error", err.Error())
	default:
		h.log.Error("选路失败", "model", inModel, "err", err)
		writeAPIError(w, http.StatusInternalServerError, proto, "api_error", "内部错误")
	}
}

func (h *Handler) logResult(cand *router.Candidate, inModel, outURL string,
	res *Result, attempts int) {

	attrs := []any{
		"model", inModel,
		"upstream", cand.Upstream.Name,
		"route", cand.Route.ID,
		"status", res.Status,
		"bytes", res.BytesWritten,
	}
	// 只在真的重试过时才记。恒定的 attempts=1 是噪音，而它出现在**每一条**
	// 转发日志上 —— 那样反而会让真正重试过的那几条不显眼。
	if attempts > 1 {
		attrs = append(attrs, "attempts", attempts)
	}
	if ttft := res.TTFT(); ttft > 0 {
		attrs = append(attrs, "ttft_ms", ttft.Milliseconds())
	}
	if cand.Route.UpstreamModel != "" {
		attrs = append(attrs, "mapped_to", cand.Route.UpstreamModel)
	}
	if res.Err != nil {
		attrs = append(attrs, "err", res.Err)
		if IsUpstreamFault(res.Err) {
			h.log.Warn("转发失败", attrs...)
		} else {
			h.log.Info("请求中断（非上游故障）", attrs...)
		}
		return
	}
	h.log.Info("转发完成", attrs...)
}

// writeAPIError 按入站协议的错误格式作答。
//
// 格式必须匹配协议：Claude Code 会解析 Anthropic 的错误结构，
// 给它一个 OpenAI 格式的错误会导致它报解析失败而不是显示真正的原因。
func writeAPIError(w http.ResponseWriter, code int, proto model.Protocol,
	errType, msg string) {

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	var payload any
	switch proto {
	case model.ProtoAnthropic:
		payload = map[string]any{
			"type":  "error",
			"error": map[string]string{"type": errType, "message": msg},
		}
	default: // OpenAI 两种协议共用同一错误结构
		payload = map[string]any{
			"error": map[string]any{
				"message": msg,
				"type":    errType,
				"code":    nil,
			},
		}
	}
	_ = json.NewEncoder(w).Encode(payload)
}
