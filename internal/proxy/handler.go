package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
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

// InFlightTracker 登记在途请求，供选路的并发上限判定使用。
//
// 返回闭包而不是配对的 Begin/End：调用方 defer 一下就不可能漏掉减一。
// 漏掉的后果隐蔽且永久 —— 计数只增不减，配了 max_concurrency 的 Route
// 会被永远排除在选路之外。
type InFlightTracker interface {
	Begin(routeID int64) (done func())
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
	cfg      ConfigSource
	health   router.HealthView
	inFlight InFlightTracker
	samples  SampleSink
	log      *slog.Logger

	// relayKeys 是入站合法凭据集合。
	relayKeys map[string]bool

	// transports 按 Upstream 缓存，避免每请求新建（那会丢掉连接复用，
	// 每次都要重新 TLS 握手 —— 对高延迟的公益站代价很大）。
	mu         sync.RWMutex
	transports map[int64]*http.Transport
}

// NewHandler 组装透传处理器。health 与 inFlight 通常是同一个 *health.Tracker，
// 分成两个参数是因为它们的职责不同（读状态 vs 记在途），也便于测试各自替换。
//
// samples 可为 nil，表示不记录样本。
func NewHandler(cfg ConfigSource, health router.HealthView, inFlight InFlightTracker,
	samples SampleSink, relayKeys []string, log *slog.Logger) *Handler {

	keys := make(map[string]bool, len(relayKeys))
	for _, k := range relayKeys {
		if k = strings.TrimSpace(k); k != "" {
			keys[k] = true
		}
	}
	return &Handler{
		cfg: cfg, health: health, inFlight: inFlight, samples: samples, log: log,
		relayKeys:  keys,
		transports: map[int64]*http.Transport{},
	}
}

// Routes 注册透传端点。三个协议路径 1:1 对应上游同名路径（§3.1）。
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/messages", h.handle(model.ProtoAnthropic))
	mux.HandleFunc("POST /v1/responses", h.handle(model.ProtoOpenAIResponses))
	mux.HandleFunc("POST /v1/chat/completions", h.handle(model.ProtoOpenAIChat))
}

func (h *Handler) handle(proto model.Protocol) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.serve(w, r, proto)
	}
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request, proto model.Protocol) {
	recvAt := time.Now()

	// 1. 入站鉴权。服务暴露公网时这是唯一屏障 —— 缺了它等于把所有
	//    上游 key 免费公开（§5.2f）。
	if !h.authOK(r) {
		writeAPIError(w, http.StatusUnauthorized, proto,
			"authentication_error", "无效的 API key")
		return
	}

	// 2. 服务总闸（§4.8）。暂停时拒绝新请求，但不影响已建立的流。
	state, err := h.cfg.RunState()
	if err != nil {
		h.log.Error("读取运行状态失败", "err", err)
		writeAPIError(w, http.StatusInternalServerError, proto, "api_error", "内部错误")
		return
	}
	if state == store.StatePaused {
		w.Header().Set("X-Relay-State", "paused")
		writeAPIError(w, http.StatusServiceUnavailable, proto, "overloaded_error",
			"服务已暂停。在管理界面点「启动」后恢复")
		return
	}

	settings, err := h.cfg.Settings()
	if err != nil {
		h.log.Error("读取设置失败", "err", err)
		writeAPIError(w, http.StatusInternalServerError, proto, "api_error", "内部错误")
		return
	}

	// 3. 读 body。必须整体读入：改 model 要定位偏移量，重试要能重放。
	body, err := ReadBodyLimited(r.Body, MaxRequestBody)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, proto, "invalid_request_error",
			fmt.Sprintf("读取请求体失败: %v", err))
		return
	}

	// 4. 取出 model 值用于选路。只读不改。
	inModel, err := ExtractModel(body)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, proto, "invalid_request_error",
			fmt.Sprintf("无法确定请求的 model: %v", err))
		return
	}

	// 5. 选路
	snap, err := h.cfg.Snapshot()
	if err != nil {
		h.log.Error("读取配置快照失败", "err", err)
		writeAPIError(w, http.StatusInternalServerError, proto, "api_error", "内部错误")
		return
	}
	cand, err := router.Select(snap, h.health, inModel, proto)
	if err != nil {
		h.writeSelectError(w, err, proto, inModel)
		return
	}

	// 选中后立刻登记在途，defer 保证任何返回路径都会减一。
	// 必须在这里而不是 Forward 内部：并发上限是选路的输入，
	// 而选路已经发生了 —— 计数窗口要覆盖从选中到收尾的全过程。
	defer h.inFlight.Begin(cand.Route.ID)()

	// 6. 改两处：body 顶层 model（配了映射才改）+ 鉴权头（必改）
	outBody, err := ReplaceModel(body, cand.Route.UpstreamModel)
	if err != nil {
		h.log.Error("替换 model 失败", "err", err, "route", cand.Route.ID)
		writeAPIError(w, http.StatusInternalServerError, proto, "api_error",
			fmt.Sprintf("改写请求失败: %v", err))
		return
	}
	outHeader := PrepareOutboundHeaders(r.Header, cand.Upstream.APIKey,
		cand.Upstream.AuthStyle, proto)

	outURL, err := BuildOutboundURL(cand.Upstream, r.URL.Path, r.URL.RawQuery)
	if err != nil {
		h.log.Error("拼接出站 URL 失败", "err", err, "upstream", cand.Upstream.ID)
		writeAPIError(w, http.StatusInternalServerError, proto, "api_error", "配置错误")
		return
	}

	// 7. 转发
	tr, err := h.transportFor(cand.Upstream, settings)
	if err != nil {
		h.log.Error("构造 Transport 失败", "err", err, "upstream", cand.Upstream.ID)
		writeAPIError(w, http.StatusInternalServerError, proto, "api_error", "配置错误")
		return
	}
	fwd := &Forwarder{Transport: tr, Timeouts: RealTimeouts(settings)}

	// 8. 挂上样本采集的 tee。只有开关打开时才有开销 ——
	//    关掉时 RespTee 为 nil，读循环里连一次判空之外的成本都没有。
	var respTee *sample.HeadTail
	if h.samples != nil && settings.SampleEnabled {
		respTee = sample.NewHeadTail(settings.SampleRespHeadBytes, settings.SampleRespTailBytes)
		fwd.RespTee = respTee
	}

	res := fwd.Forward(r.Context(), w, r.Method, outURL, outHeader, outBody)

	h.logResult(cand, inModel, outURL, res)

	if respTee != nil {
		h.recordSample(r, proto, cand, recvAt, inModel, body, outBody,
			outHeader, outURL, respTee, res)
	}
}

// recordSample 组装并投递一条样本（§3.6）。
//
// 全程只读转发路径产生的数据，绝不回写；投递是非阻塞的，
// 队列满就丢。任何在这里发生的问题都不该影响已经完成的转发。
func (h *Handler) recordSample(r *http.Request, proto model.Protocol,
	cand *router.Candidate, recvAt time.Time, inModel string,
	inBody, outBody []byte, outHeader http.Header, outURL string,
	respTee *sample.HeadTail, res *Result) {

	settings, err := h.cfg.Settings()
	if err != nil {
		return // 配置读不到就不记样本，绝不因此影响任何东西
	}

	// 落库的 key 只有两处来源：入站的 relay key 与出站的上游 key。
	// 两者都要从 body 里扫掉（§9.4 要求真 key 全表 grep 零命中）。
	keys := []string{cand.Upstream.APIKey}
	for _, k := range []string{
		r.Header.Get("X-Api-Key"),
		strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "),
		r.Header.Get("Api-Key"),
	} {
		if k = strings.TrimSpace(k); k != "" {
			keys = append(keys, k)
		}
	}

	inSafe := sample.RedactBodyKeys(inBody, keys)
	outSafe := sample.RedactBodyKeys(outBody, keys)
	// 响应体同样要扫。上游的鉴权错误经常把 key 回显在消息里
	// （`{"error":"Invalid API key: sk-xxx"}` 是常见格式），
	// 漏掉这一处，样本库里就会躺着明文 key —— §3.6.3b 的要求是无条件的。
	respSafe := sample.RedactBodyKeys(respTee.Bytes(), keys)

	inTrunc, inCut := sample.TruncateBody(inSafe, settings.SampleMaxBodyBytes)
	outTrunc, outCut := sample.TruncateBody(outSafe, settings.SampleMaxBodyBytes)

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

		InMethod:  r.Method,
		InPath:    r.URL.Path,
		InQuery:   r.URL.RawQuery,
		InHeaders: sample.RedactHeaders(r.Header),
		InBody:    inTrunc,

		OutURL:     outURL,
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

// authOK 三个位置都认，因为不同协议的客户端习惯不同（§3.2）。
func (h *Handler) authOK(r *http.Request) bool {
	if len(h.relayKeys) == 0 {
		return false // 未配置 key 时一律拒绝，绝不放开
	}
	candidates := []string{
		r.Header.Get("X-Api-Key"),
		strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "),
		r.Header.Get("Api-Key"),
	}
	for _, c := range candidates {
		if c != "" && h.relayKeys[strings.TrimSpace(c)] {
			return true
		}
	}
	return false
}

// transportFor 按 Upstream 缓存 Transport，保住连接复用。
func (h *Handler) transportFor(up *model.Upstream, s model.Settings) (*http.Transport, error) {
	h.mu.RLock()
	tr, ok := h.transports[up.ID]
	h.mu.RUnlock()
	if ok {
		return tr, nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if tr, ok := h.transports[up.ID]; ok {
		return tr, nil // 双检：可能在等锁期间已被别的请求建好
	}
	tr, err := NewTransport(up.ProxyURL, time.Duration(s.RealConnectSec)*time.Second)
	if err != nil {
		return nil, err
	}
	h.transports[up.ID] = tr
	return tr, nil
}

// CloseIdleConnections 关闭所有缓存 Transport 的空闲连接，供优雅关闭调用。
func (h *Handler) CloseIdleConnections() {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, tr := range h.transports {
		tr.CloseIdleConnections()
	}
}

// InvalidateTransport 在 Upstream 配置变更（尤其改了 proxy_url）后丢弃旧 Transport。
func (h *Handler) InvalidateTransport(upstreamID int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if tr, ok := h.transports[upstreamID]; ok {
		tr.CloseIdleConnections()
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

func (h *Handler) logResult(cand *router.Candidate, inModel, outURL string, res *Result) {
	attrs := []any{
		"model", inModel,
		"upstream", cand.Upstream.Name,
		"route", cand.Route.ID,
		"status", res.Status,
		"bytes", res.BytesWritten,
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
