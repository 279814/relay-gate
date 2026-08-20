package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// Timeouts 是三段独立超时（§4.2）。
//
// 必须分开：只设一个总超时会杀掉 Opus 5 高 effort 的正常长思考。
// FirstToken 由调用方保证 ≥ 300s（model.MinRealFirstTokenSec）。
type Timeouts struct {
	Connect    time.Duration
	FirstToken time.Duration
	Idle       time.Duration // 流内两个 chunk 之间的静默上限
	Total      time.Duration
}

// TimeoutsFromSettings 按场景取值。
func RealTimeouts(s model.Settings) Timeouts {
	return Timeouts{
		Connect:    time.Duration(s.RealConnectSec) * time.Second,
		FirstToken: time.Duration(s.RealFirstTokenSec) * time.Second,
		Idle:       time.Duration(s.RealIdleSec) * time.Second,
		Total:      time.Duration(s.RealTotalSec) * time.Second,
	}
}

// NewTransport 构造出站 Transport。
//
// DisableCompression=true 是硬要求（§3.3.4）：Go 默认会偷偷加
// Accept-Encoding: gzip 并自动解压响应。那样就必须删 Content-Encoding，
// 等于改动了响应 —— 违反「响应完全不碰」。关掉后客户端的
// Accept-Encoding 原样转发，响应体字节流原样回传，零解压零重压。
func NewTransport(proxyURL string, connectTimeout time.Duration) (*http.Transport, error) {
	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   connectTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: connectTimeout,
		DisableCompression:  true,

		// 公益站延迟高，连接复用能省掉每次 TLS 握手（实测握手占首字节的可观比例）
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,

		// 不设 ResponseHeaderTimeout：首 Token 超时由 context 控制，
		// 这里设了会与三段超时打架（它管的是响应头，而长思考期间
		// 响应头早就回来了，卡住的是 body 的第一个 chunk）
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
	}

	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("解析 proxy_url %q: %w", proxyURL, err)
		}
		tr.Proxy = http.ProxyURL(u)
	}
	return tr, nil
}

// Result 是一次转发的结果，供健康判定与样本记录使用。
type Result struct {
	Status      int
	RespHeaders http.Header
	// FirstByteAt 是收到响应体首字节的时刻（近似 TTFT）。零值表示始终没收到。
	FirstByteAt time.Time
	SentAt      time.Time
	DoneAt      time.Time
	// BytesWritten 是已写给客户端的字节数。> 0 时禁止重试（§3.5）。
	BytesWritten int64
	// HeadersSent 表示是否已经调用过 w.WriteHeader。
	//
	// 调用方**必须**据此决定失败时如何回应：为 false 时还能写一个正常的
	// 错误响应；为 true 时状态码已经发出去了，只能断流。
	// 不暴露这个标志的话，调用方要么不敢写（于是 net/http 补一个 200 空 body），
	// 要么盲目写（于是把错误 JSON 塞进已经开始的 SSE 流里）。
	HeadersSent bool
	Err         error

	// ErrBody 是响应体的开头若干字节，**仅在 Status >= 400 时**填充。
	//
	// 健康判定需要它：401 与 500 都是「失败」，但一个要立即判死并提示用户
	// 改配置，另一个等它自己恢复（§4.3）。而「模型不存在」与「参数不合法」
	// 同为 400，区别只在 body 里的那几个关键词 —— 没有 body 就只能一律
	// 按最保守的方式处理，等于放弃了致命类的快速判定。
	//
	// 只在错误时收集是刻意的：正常响应可能是几 MB 的 SSE 流，为了健康判定
	// 攒一份副本纯属浪费；而错误响应通常只有几百字节。
	ErrBody []byte
}

// maxErrBodyCapture 是 ErrBody 的上限。
//
// 错误响应通常几百字节，但公益站背后的 nginx 出错时会回整页 HTML。
// 8KB 足够容纳任何结构化错误信息，又不会因为一个巨大的错误页而占住内存。
const maxErrBodyCapture = 8 << 10

// TTFT 返回首 Token 延迟。未收到首字节时返回 0。
func (r *Result) TTFT() time.Duration {
	if r.FirstByteAt.IsZero() || r.SentAt.IsZero() {
		return 0
	}
	return r.FirstByteAt.Sub(r.SentAt)
}

// Forwarder 执行单次转发。
//
// 手写而非用 httputil.ReverseProxy：三段超时（尤其「首字节前后用不同超时」）
// 需要在读 body 的循环里切换 deadline，ReverseProxy 的 io.Copy 拿不到这个控制点。
// 逐跳头与 Host 由 PrepareOutboundHeaders 处理，不依赖 ReverseProxy 的实现。
type Forwarder struct {
	Transport *http.Transport
	Timeouts  Timeouts
	// OnFirstByte 在收到首字节时回调（用于记录 TTFT、结束探活等）。可为 nil。
	OnFirstByte func()

	// RespTee 收一份响应体副本，供样本记录用（§3.6.3a）。可为 nil。
	//
	// 写入发生在「已写给客户端并 flush 之后」，所以它既不改变字节，
	// 也不改变 flush 时序 —— 采集是旁路，不是管线的一环。
	// 它的写入错误一律忽略：丢一份样本远好过中断一次真实转发。
	RespTee io.Writer

	// RequestHost 覆盖 Host 头。空表示用 URL 自己的 host。
	//
	// 必须走 http.Request.Host 而不是 Header["Host"]：net/http 在写请求行时
	// **只读 req.Host**，塞进 Header 的 Host 会被静默丢弃 —— 那正是
	// 「配了 host_override 却完全没生效」这类问题的来源。
	RequestHost string
}

// Attempt 是一次**尚未提交**的转发：请求已发出、响应头已拿到，
// 但一个字节都还没写给客户端。
//
// 为什么需要这个中间状态：§3.5 要求「仅在尚未向客户端写出任何字节时才能
// 重试」，而原先的 Forward 一拿到响应头就 WriteHeader —— 状态码一旦发出，
// 5xx 与 429 就再没法换站重试了，而那两类恰好是 §3.5 明确列为可重试的。
// 把「拿到响应」与「提交给客户端」拆成两步，重试才有可能。
//
// 调用方**必须**恰好调用 Commit 或 Discard 之一。两者都负责释放这次尝试
// 占用的 context 与连接：漏掉就是泄一个 goroutine 加一条连接，而这种泄漏
// 只在压力下才显形（连接池耗尽），届时很难回溯到这里。
type Attempt struct {
	f         *Forwarder
	resp      *http.Response
	res       *Result
	cancel    context.CancelFunc
	ctx       context.Context // 带 Total 超时
	clientCtx context.Context // 客户端原始 ctx，用于区分「谁的时限到了」
	done      bool

	// peeked 是 Peek 预读到的响应体前缀，Commit 时原样重放给客户端。
	peeked   []byte
	peekDone bool
	// peekBroke 表示预读阶段就确定这次响应没有可提交的内容
	// （首 Token 超时，或上游一个字节都没吐就断开）。
	peekBroke bool
}

// Failed 表示这次尝试没有可用的响应。
//
// 两种情形：连响应头都没拿到，或者 Peek 发现响应体根本没开始。
// 两者都只能 Discard。
func (at *Attempt) Failed() bool { return at.res.Err != nil }

// CanCommit 表示这次尝试还有东西可以交给客户端。
//
// 与 Failed 不是简单的反面：一个 HTTP 500、甚至一个「200 但载荷是错误」
// 都是**可以提交**的 —— 上游的错误原文对客户端有用，§3.3 也要求响应
// 方向原样透传。只有连响应体都没开始的那种失败才没有可提交的内容。
func (at *Attempt) CanCommit() bool { return at.resp != nil && !at.peekBroke }

// Status 是上游响应状态码。Failed 时为 0。
func (at *Attempt) Status() int { return at.res.Status }

// Result 取这次尝试的结果。Commit 之前它只填到响应头那一层，
// 供重试判定使用（判定只看状态码与错误，不看 body）。
func (at *Attempt) Result() *Result { return at.res }

// Forward 把请求投递到 cand 指定的上游，响应流式写回 w。
//
// body 必须是已经过 ReplaceModel 处理的字节。header 必须是
// PrepareOutboundHeaders 的产物。
//
// 这是 Send + Commit 的薄封装。保留它是因为「不重试」的调用方
// （count_tokens、既有测试、重试关闭时的转发）不需要关心提交时机 ——
// 让它们跟着一起改成两步调用，只会把一个内部细节摊给所有人。
func (f *Forwarder) Forward(ctx context.Context, w http.ResponseWriter,
	method, outURL string, header http.Header, body []byte) *Result {

	at := f.Send(ctx, method, outURL, header, body)
	if at.Failed() {
		at.Discard()
		return at.res
	}
	return at.Commit(w)
}

// Send 发出请求并等到响应头，**不**写任何东西给客户端。
//
// 返回的 Attempt 一定非 nil，即使失败 —— 失败时 Failed() 为 true，
// 调用方照样要 Discard（它负责释放 context）。
func (f *Forwarder) Send(ctx context.Context, method, outURL string,
	header http.Header, body []byte) *Attempt {

	res := &Result{}

	// 保留客户端原始的 ctx。加了超时之后就分不清「客户端断开」与
	// 「我们自己的超时到期」了，而这两者对健康状态的含义完全相反。
	clientCtx := ctx

	// 总超时是最外层的兜底。首 Token 与 Idle 在读循环里单独控制。
	//
	// cancel 不在这里 defer：它要活到 Commit/Discard —— 提交之后响应体
	// 还在读，提前取消会把一个正常的流掐断。
	ctx, cancel := context.WithTimeout(ctx, f.Timeouts.Total)
	at := &Attempt{f: f, res: res, cancel: cancel, ctx: ctx, clientCtx: clientCtx}

	// bytes.NewReader 而不是 strings.NewReader(string(body))：
	// 后者会把整个 body 复制一遍，而 body 可能有几百 KB 到 MB。
	req, err := http.NewRequestWithContext(ctx, method, outURL, bytes.NewReader(body))
	if err != nil {
		res.Err = fmt.Errorf("构造出站请求: %w", err)
		return at
	}
	req.Header = header
	// Host 覆盖必须写 req.Host：写进 Header 会被 net/http 静默忽略。
	if f.RequestHost != "" {
		req.Host = f.RequestHost
	}
	// ContentLength 显式设置，避免 http 库改用 chunked ——
	// 部分上游对 chunked 的 POST 处理不一致。
	req.ContentLength = int64(len(body))
	// GetBody 让 http 库能在重定向/HTTP2 重试时重放 body。
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}

	// 响应头阶段单独设一个时限。
	//
	// 没有它的话，一个卡在「收下请求但不回响应头」的站只能等 Total 兜底
	// （默认 30 分钟），而首 Token 超时形同虚设 —— 它只在读 body 时才起作用。
	// 这种站在公益站里并不罕见：连接建立、请求收下，然后就没有然后了。
	//
	// 用 timer 而不是给请求套一个更短的 context：请求的 context 一旦到期，
	// 连带取消的是**整个响应体的读取** —— 长思考流会在首 Token 那一刻
	// 被拦腰砍断，而那正是 5 分钟下限要保护的场景。timer 在拿到响应头后
	// 立刻 Stop，之后的时限交给 streamBody 自己的 timer。
	var headerTimedOut atomic.Bool
	headerTimer := time.AfterFunc(f.Timeouts.FirstToken, func() {
		headerTimedOut.Store(true)
		cancel()
	})
	defer headerTimer.Stop()

	res.SentAt = time.Now()
	// 直接用 Transport.RoundTrip 而不是 http.Client。除了「不要自动跟随
	// 重定向」之外还有一条不显然的理由：Client.Do 会把错误包成 *url.Error，
	// 而它的 Error() 带上**完整 URL** —— full_url_mode 的 base_url 允许把
	// key 放在 query 里（§3.2），那就等于把上游 key 拼进错误文本。
	// writeForwardError 已对此做了脱敏兜底，两层都在。
	resp, err := f.Transport.RoundTrip(req)
	headerTimer.Stop()
	if err != nil {
		res.Err = classifyTransportErr(err, clientCtx, headerTimedOut.Load(), f.Timeouts.FirstToken)
		res.DoneAt = time.Now()
		return at
	}

	res.Status = resp.StatusCode
	res.RespHeaders = resp.Header.Clone()
	at.resp = resp
	return at
}

// peekLimit 是预读缓冲的上限。
//
// 32KB 与 streamBody 的读缓冲同大小：预读拿的是「上游已经 flush 出来的
// 那一段」，不该比一次正常的读多要。
const peekLimit = 32 << 10

// Peek 预读响应体开头的一段，让调用方能在提交前判断这是不是错误载荷
// （§3.5 的「200 但流内立刻 error」）。返回已读到的前缀。
//
// **只做一次 Read**，不循环凑满 peekLimit。这一条是硬要求：SSE 的下一个
// chunk 可能在几十秒之后（模型正在思考），凑满缓冲就等于把这段思考时间
// 累加成客户端的首字节延迟 —— 而首字节延迟正是这个项目要优化的东西。
//
// 但要说清代价：这次 Read 是**阻塞**的。流上还没有数据时它就是要等，
// 等到上游吐出首字节为止。所以 Peek 不是「零等待」，它换来的是
// 「不比一次正常的读多等」—— 首字节的**内容**到达客户端的时刻没有变
// （预读的字节由 Commit 立刻重放并 flush），变的是**响应头**：
// 它被压到首字节之后才发出，而按 §4.2 的实测，长思考的首字节是 22–32s。
//
// 由此带来一处目前接受的浪费：nextCandidate 把 retryable（也就是这次
// 阻塞的预读）排在 selectFor 之前，而后者是纯内存查询。于是只绑了一个
// Route 时，仍会先阻塞预读、之后才发现没有备选站可换。把 selectFor 提前
// 就能免掉，但它内部会 TryAcquire 占并发额度，提前调用就必须在判定不
// 重试时把额度还掉 —— 那是另一处要小心的资源账，暂不动。
//
// 代价是前缀可能被 TCP 分段切在半截。classifyPayload 对切碎的处理是
// 「解析不了就放行」，所以最坏结果是退化成不重试，不会误判。
//
// 预读的字节由 Commit 原样重放，不会丢。多次调用只读一次。
func (at *Attempt) Peek() []byte {
	if at.peekDone || at.resp == nil {
		return at.peeked
	}
	at.peekDone = true
	res, f := at.res, at.f

	// 首 Token 时限与断流唤醒，与 streamBody 用同一套手段：关响应体来
	// 解开阻塞的 Read（拿不到底层 net.Conn，设不了 ReadDeadline）。
	var timedOut atomic.Bool
	timer := time.AfterFunc(f.Timeouts.FirstToken, func() {
		timedOut.Store(true)
		_ = at.resp.Body.Close()
	})
	defer timer.Stop()

	peekDone := make(chan struct{})
	defer close(peekDone)
	go func() {
		select {
		case <-at.ctx.Done():
			_ = at.resp.Body.Close()
		case <-peekDone:
		}
	}()

	buf := make([]byte, peekLimit)
	n, err := at.resp.Body.Read(buf)
	if n > 0 {
		at.peeked = buf[:n]
		res.FirstByteAt = time.Now()
		if f.OnFirstByte != nil {
			f.OnFirstByte()
		}
	}

	// n > 0 时一律算拿到了内容，即使同时带回 EOF —— 那是「短响应一次读完」
	// 的正常形态，Commit 重放前缀后再读一次拿到 EOF 即可。
	if n > 0 || err == nil {
		return at.peeked
	}

	// EOF 且零字节：200 但 body 为空。这是「假活」（§4.3），不是断流 ——
	// 它不在 §3.5 的可重试清单里，所以照常提交，由 classifyOutcome
	// 归成 fake_alive。不在这里判错，否则会把一个已有分类的情形
	// 悄悄改成 upstream_error。
	if errors.Is(err, io.EOF) {
		return at.peeked
	}

	// 走到这里：一个字节都没读到就出错了，没有任何可提交的内容。
	// 分类与 streamBody 保持一致 —— 两处判据不同的话，同一个故障
	// 在「有没有预读」两条路径上会得到不同的健康结论。
	at.peekBroke = true
	res.DoneAt = time.Now()
	switch {
	case timedOut.Load():
		res.Err = fmt.Errorf("%w: 首 Token 超过 %v", ErrFirstTokenTimeout, f.Timeouts.FirstToken)
	case at.clientCtx.Err() != nil:
		res.Err = fmt.Errorf("%w: %v", ErrCanceled, err)
	case at.ctx.Err() != nil:
		res.Err = fmt.Errorf("%w: 超过总时限 %v", ErrTotalTimeout, f.Timeouts.Total)
	default:
		res.Err = fmt.Errorf("%w: %v", ErrUpstreamBroke, err)
	}
	return nil
}

// Commit 把这次尝试的响应头与响应体写给客户端。
//
// 一旦调用就再也不能重试了 —— 状态码已经发出去。
func (at *Attempt) Commit(w http.ResponseWriter) *Result {
	if at.done {
		return at.res // 防御：重复提交，不该发生
	}
	at.done = true
	defer at.cancel()
	defer at.resp.Body.Close()

	res, f := at.res, at.f

	// 响应头原样回传。ReverseProxy 会做的逐跳清理这里手动做一次。
	dst := w.Header()
	for k, vs := range at.resp.Header {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
	StripHopByHopResponse(dst)
	w.WriteHeader(at.resp.StatusCode)
	res.HeadersSent = true

	// 预读走的字节要接回流的最前面。漏掉它就是**静默吞掉响应的开头** ——
	// 客户端收到的 SSE 少了 message_start，或 JSON 少了左半边。
	var src io.Reader = at.resp.Body
	if len(at.peeked) > 0 {
		src = io.MultiReader(bytes.NewReader(at.peeked), at.resp.Body)
	}

	n, err := f.streamBody(at.ctx, at.clientCtx, w, src, at.resp.Body, res)
	res.BytesWritten = n
	res.DoneAt = time.Now()
	if err != nil && res.Err == nil {
		res.Err = err
	}
	return res
}

// Discard 放弃这次尝试：不向客户端写任何东西，释放连接与 context。
//
// 失败的尝试（连响应头都没拿到）也要走这里 —— context 是在 Send 里建的，
// 不 cancel 就会留到 Total 超时才回收。
//
// 主动读掉一小段 body 再关：不读就关会让这条 TCP 连接被丢弃而不是还回
// 连接池（net/http 只在 body 读到 EOF 后才复用连接）。重试场景下这个差别
// 是实际的 —— 每次换站重试都白扔一条连接，握手成本翻倍。
// 上限 4KB：错误响应通常只有几百字节，读满还没结束就说明这不是一个错误
// 响应体，那就直接关，别为了复用连接去读一个可能很长的流。
func (at *Attempt) Discard() {
	if at.done {
		return
	}
	at.done = true
	defer at.cancel()
	if at.resp == nil {
		return // Send 就失败了，没有 body 可关
	}

	// 排水读到的字节**不能真的丢掉** —— 被丢弃的错误响应，它的 body 正是
	// 健康判定要看的东西。
	//
	// 正常路径上 ErrBody 由 streamBody 填，但重试丢弃的尝试永远走不到那里。
	// 少了这份 body，ClassifyHTTP 只能看状态码 —— 而「500 + body 里写着
	// rate limit」（Anthropic 的 529 overloaded 就是这个形态）会因此被判成
	// Unavailable 而累计判死，本该只是冷却 60 秒。一个热门的好站会就这样
	// 被踢出池子。
	//
	// 这里**不会多读一个字节**：为了让连接还回池子，这段排水本来就要做。
	// 只是把目的地从 io.Discard 换成一个缓冲区，所以阻塞行为与之前完全一致。
	at.captureDrain()
	at.resp.Body.Close()
	if at.res.DoneAt.IsZero() {
		at.res.DoneAt = time.Now()
	}
}

const discardDrainLimit = 4 << 10

// captureDrain 排掉剩余 body（让连接能还回池子），顺带把错误响应的开头
// 留给健康判定。
//
// 上限与正常路径共用 maxErrBodyCapture：两处不一致的话，同一个上游错误
// 在「有没有走重试」两条路径上会给出不同长度的 last_error，
// 而那正是 UI 上用来比对的字段。
func (at *Attempt) captureDrain() {
	// 只有错误响应才留。被丢弃的 200（载荷是 error）走不到健康判定的
	// ErrBody 分支，攒了也没人看。
	if at.res.Status < 400 || len(at.res.ErrBody) > 0 {
		io.CopyN(io.Discard, at.resp.Body, discardDrainLimit)
		return
	}

	// 预读已经拿到的部分先接上。4xx/5xx 通常没走 Peek —— 为一个注定不重试
	// 的 4xx 等一次首 Token 超时是白等，所以那条路径上 peeked 是空的。
	at.res.ErrBody = at.peeked

	var buf bytes.Buffer
	io.CopyN(&buf, at.resp.Body, discardDrainLimit)
	room := maxErrBodyCapture - len(at.res.ErrBody)
	if b := buf.Bytes(); room > 0 && len(b) > 0 {
		if len(b) > room {
			b = b[:room]
		}
		at.res.ErrBody = append(at.res.ErrBody, b...)
	}
}

// streamBody 逐块拷贝响应体，并在首字节前后应用不同的超时。
//
// 每次 Write 后立即 Flush：任何缓冲都会破坏 SSE 语义，表现为
// 「长时间无输出后一次性刷出」。
//
// closer 是中断阻塞 Read 的手段，传 resp.Body。
// 不能用 Transport.CloseIdleConnections()：正在读的连接不是「空闲」的，
// 对它无效；而且会误伤共享同一 Transport 的其他在途请求。
// 也不能用 SetReadDeadline：Transport 管着连接，拿不到底层 net.Conn。
//
// 超时用一个可重置的 timer，而不是「每次迭代新建 goroutine + WithDeadline」。
// 后者有个致命缺陷：主循环读成功后要同时关 done 与 cancel readCtx，看门狗的
// select 两个 case 同时就绪时会随机挑一个，挑到 ctx 分支就会**关掉一个正常的流**
// （Err 是 Canceled 而非 DeadlineExceeded，超时标志还不置位，于是被误判成上游断流）。
// 表现为长 SSE 回复被随机截断在某个 chunk。timer 只在真到期时开火，没有这个歧义。
func (f *Forwarder) streamBody(ctx, clientCtx context.Context, w http.ResponseWriter,
	src io.Reader, closer io.Closer, res *Result) (int64, error) {

	flusher, canFlush := w.(http.Flusher)
	buf := make([]byte, 32*1024)

	// 只有错误响应才攒副本供健康判定用。正常响应可能是几 MB 的 SSE 流，
	// 为了判定攒一份纯属浪费 —— 而正常响应的判定根本不需要看 body。
	captureErr := res.Status >= 400

	var total int64
	// timer 回调写、主循环读，必须用原子操作（-race 会抓这个）
	var timedOut atomic.Bool

	// 关响应体以解开阻塞的 Read，同时停止继续消耗上游 token
	// （§4.1 要求探到结果就主动断流，真实请求超时同理）。
	timer := time.AfterFunc(f.Timeouts.FirstToken, func() {
		timedOut.Store(true)
		_ = closer.Close()
	})
	defer timer.Stop()

	// 客户端断开或总超时也要解开阻塞的 Read。这个 goroutine 只在 ctx 真的
	// 结束时关流；与 streamDone 竞争到也无妨 —— 那时函数已在返回，
	// Forward 的 defer 本来就要关响应体，重复 Close 是幂等的。
	streamDone := make(chan struct{})
	defer close(streamDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = closer.Close()
		case <-streamDone:
		}
	}()

	for {
		n, err := src.Read(buf)

		if n > 0 {
			// FirstByteAt 可能已由 Peek 填过。不能覆盖：Commit 重放的是
			// **早先**读到的字节，用此刻的时间会把 TTFT 记成「预读到提交」
			// 的间隔（几微秒），于是所有经过预读的请求都报出一个假的超快
			// TTFT —— 而它会经 last_ttft_ms 显示在管理界面上。
			if res.FirstByteAt.IsZero() {
				res.FirstByteAt = time.Now()
				if f.OnFirstByte != nil {
					f.OnFirstByte()
				}
			}
			wn, werr := w.Write(buf[:n])
			total += int64(wn)
			if canFlush {
				flusher.Flush()
			}
			// 采集放在 flush 之后：放前面会把「攒副本」的耗时插进
			// 客户端可感知的延迟里，违反「不改变 flush 时序」。
			if f.RespTee != nil {
				_, _ = f.RespTee.Write(buf[:n])
			}
			// 错误响应额外留一份给健康判定用（区分 401/model_not_found
			// 这类致命错误与普通 5xx）。同样在 flush 之后，且只在错误时攒。
			if captureErr && len(res.ErrBody) < maxErrBodyCapture {
				room := maxErrBodyCapture - len(res.ErrBody)
				if room > n {
					room = n
				}
				res.ErrBody = append(res.ErrBody, buf[:room]...)
			}
			if werr != nil {
				// 客户端断开。不是上游的问题，不该计入健康失败。
				return total, fmt.Errorf("%w: %v", ErrClientGone, werr)
			}
			// 首字节之后改用 Idle 超时。每收到数据就重置，
			// 计的是「两个 chunk 之间的静默」而不是流的总时长。
			timer.Reset(f.Timeouts.Idle)
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				return total, nil
			}
			// 区分「首 Token 超时」与「流内静默超时」：前者说明站没响应，
			// 后者说明流中断了。两者对健康状态的含义不同（§4.3）。
			switch {
			case timedOut.Load() && total == 0:
				return total, fmt.Errorf("%w: 首 Token 超过 %v", ErrFirstTokenTimeout, f.Timeouts.FirstToken)
			case timedOut.Load():
				return total, fmt.Errorf("%w: 流内静默超过 %v", ErrStreamStalled, f.Timeouts.Idle)
			}
			// 只有**客户端**取消才是非上游故障。必须先判 clientCtx：
			// 客户端断开会连带取消 ctx，先判 ctx 会把两者混为一谈。
			if clientCtx.Err() != nil {
				return total, fmt.Errorf("%w: %v", ErrCanceled, err)
			}
			// 走到这里说明是我们自己的总超时到期 —— 上游拖过了 Total，
			// 算上游的账（默认 30 分钟，正常长思考远到不了）。
			if ctx.Err() != nil {
				return total, fmt.Errorf("%w: 超过总时限 %v", ErrTotalTimeout, f.Timeouts.Total)
			}
			if total == 0 {
				return total, fmt.Errorf("%w: %v", ErrUpstreamBroke, err)
			}
			// 已写出字节后断流：无法重试，原样传给客户端，但计入失败（§5.2b）
			return total, fmt.Errorf("%w: %v", ErrStreamBroke, err)
		}
	}
}

// 转发失败的分类哨兵错误。健康状态机（§4.3）按这些类别决定动作。
//
// 分这么细是因为它们对健康状态的含义完全不同：
// 上游连不上要标 dead，客户端断开则完全不该影响健康状态。
var (
	ErrConnect           = errors.New("连接上游失败")
	ErrFirstTokenTimeout = errors.New("首 Token 超时")
	ErrStreamStalled     = errors.New("流内静默超时")
	ErrTotalTimeout      = errors.New("超过总时限")
	ErrUpstreamBroke     = errors.New("上游未返回任何数据即断开")
	ErrStreamBroke       = errors.New("流式传输中途断开")
	ErrClientGone        = errors.New("客户端已断开")
	ErrCanceled          = errors.New("请求被取消")
)

// IsUpstreamFault 判断该错误是否应计入上游的健康失败。
//
// 只有客户端断开与客户端取消不算 —— 它们是客户端的行为，
// 绝不能因此把好站标成 dead。其余一律算上游的账，**包括我们自己设的超时**：
// 那些超时到期正是「这个站太慢/已死」的证据，不算进去的话
// 一个真死的站永远攒不够失败次数，主动探活就失去了意义。
func IsUpstreamFault(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrClientGone) || errors.Is(err, ErrCanceled) {
		return false
	}
	return true
}

// classifyTransportErr 判断响应头阶段的失败该算谁的账。
//
// 关键在于分清**是谁的时限到期了**。只看 ctx.Err() != nil 就判 ErrCanceled
// 是错的：Total 与响应头时限都是**我们自己**设的，是上游太慢的证据，
// 却会被 IsUpstreamFault 判成「非上游故障」—— 于是一个真死的站永远攒不够
// 失败次数，永远不会被标 dead，正好废掉这个项目的核心价值。
//
// clientCtx 是加超时之前的 ctx（客户端的）。
func classifyTransportErr(err error, clientCtx context.Context,
	headerTimedOut bool, firstToken time.Duration) error {

	// 只有**客户端**取消才是非上游故障。这个判断必须在最前面：
	// 客户端断开会连带取消内层 context，先判内层会误伤。
	if clientCtx.Err() != nil {
		return fmt.Errorf("%w: %v", ErrCanceled, err)
	}
	if headerTimedOut {
		return fmt.Errorf("%w: 响应头超过 %v 未返回", ErrFirstTokenTimeout, firstToken)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return fmt.Errorf("%w: 超时 %v", ErrConnect, err)
	}
	return fmt.Errorf("%w: %v", ErrConnect, err)
}
