package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
)

// Timeouts 是转发路径用到的四段超时。
//
// 它是 outbound.Budget 的投影，只取 forward.go 实际用得到的那几段：
// Connect 由连接池承载（不在这里用），Total 是最外层硬上限，FirstToken 管
// 「响应头 / 首字节 / 首事件 / 首语义」投影成的单一截止（§7.4），Idle 在
// §8.8 首语义证据出现之后才启用（流内静默）。
//
// 为什么不直接用 outbound.Budget：Budget 的四个观察点（response_header /
// first_byte / first_event / first_semantic）要到阶段计时器拆开之后才分得开
// —— 现阶段用 SemanticSeen 决定何时结束 FirstToken、何时启用 Idle，
// 而不另起一套计时器。TimeoutsFrom 是投影入口。
type Timeouts struct {
	Connect    time.Duration
	FirstToken time.Duration
	// PeekWait is the pre-commit first-body-byte window (§11.5).
	// Safe/Balanced use a short bound (2s); Aggressive uses real_first_byte_sec.
	// Zero means fall back to FirstToken.
	PeekWait time.Duration
	// Safe/Balanced commit an undecided response when the short peek window
	// expires. Aggressive may instead treat its expanded window as a failure.
	CommitOnPeekTimeout bool
	Idle                time.Duration // 首语义之后，原始语义事件之间的静默上限
	Total               time.Duration
}

// TimeoutsFrom 把 outbound.Budget 投影成转发路径用的四段。
//
// 各阶段上限取**最小的那个**：Budget 的四个观察点都从 SentAt 起算，而
// forward.go 现在只有一个「首字节前」的计时器，能表达的只有其中最紧的那条。
// 取最大值会让配得更紧的那个阶段静默失效。
//
// 投影后再抬到 MinRealFirstSemanticSec：配置层只卡 real_first_semantic_sec，
// 但这里 FirstToken 兼管响应头 / 首字节 / 首语义，任一阶段配短都会经 min
// 把长思考砍到五分钟以下（与探活侧 PR #93 同类）。Total 已被 CapTotal 夹到
// 低于该下限时不抬，否则会越过一次客户端请求共享的总预算。
func TimeoutsFrom(budget outbound.Budget) Timeouts {
	firstToken := budget.Total
	for _, stage := range []time.Duration{
		budget.ResponseHead, budget.FirstByte, budget.FirstEvent, budget.FirstSemantic,
	} {
		if stage > 0 && stage < firstToken {
			firstToken = stage
		}
	}
	floor := time.Duration(model.MinRealFirstSemanticSec) * time.Second
	if firstToken > 0 && firstToken < floor && (budget.Total <= 0 || budget.Total >= floor) {
		firstToken = floor
	}
	return Timeouts{
		Connect:             budget.Connect,
		FirstToken:          firstToken,
		PeekWait:            2 * time.Second, // §11.5 Safe/Balanced default bound
		CommitOnPeekTimeout: true,
		Idle:                budget.IdleTimeout(),
		Total:               budget.Total,
	}
}

// WithAggressivePeek expands the pre-commit first-byte wait to real_first_byte_sec (§11.5).
func (to Timeouts) WithAggressivePeek(realFirstByte time.Duration) Timeouts {
	to.CommitOnPeekTimeout = false
	if realFirstByte > 0 {
		to.PeekWait = realFirstByte
	}
	return to
}

func (to Timeouts) peekWaitOrFirstToken() time.Duration {
	if to.PeekWait > 0 {
		return to.PeekWait
	}
	return to.FirstToken
}

// RealTimeouts 是真实请求的四段超时。
func RealTimeouts(s model.Settings) Timeouts {
	return TimeoutsFrom(outbound.RealBudget(s))
}

// Result 是一次转发的结果，供健康判定与样本记录使用。
type Result struct {
	Status      int
	RespHeaders http.Header
	// FirstByteAt 是收到响应体首字节的时刻。零值表示始终没收到。
	// 样本 TSFirstByte 用它；不等同于 TTFT（见 FirstSemanticAt）。
	FirstByteAt time.Time
	// FirstSemanticAt 是首次见到 §8.8 语义证据的时刻（与 SemanticSeen 同源）。
	// message_start / ping / SSE 注释单独到达时不置位。TTFT 用它。
	FirstSemanticAt time.Time
	SentAt          time.Time
	DoneAt          time.Time
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
	// Raw transport failure remains distinguishable from a local transform error.
	upstreamReadErr error

	ObserverIncomplete model.ObserverIncompleteReason

	// SemanticSeen and FirstSemanticAt come only from original upstream wire.
	SemanticSeen bool
}

// TTFT 返回首语义 Token 延迟（§8.8）。未见语义证据时返回 0。
// 时钟回拨或乱序时间戳导致负间隔时同样归零，避免 TTFTMs 写入负数。
func (r *Result) TTFT() time.Duration {
	if r.FirstSemanticAt.IsZero() || r.SentAt.IsZero() {
		return 0
	}
	d := r.FirstSemanticAt.Sub(r.SentAt)
	if d < 0 {
		return 0
	}
	return d
}

// Forwarder 执行单次转发。
//
// 手写而非用 httputil.ReverseProxy：三段超时（尤其「首字节前后用不同超时」）
// 需要在读 body 的循环里切换 deadline，ReverseProxy 的 io.Copy 拿不到这个控制点。
// 逐跳头与 Host 由 PrepareOutboundHeaders 处理，不依赖 ReverseProxy 的实现。
type Forwarder struct {
	Protocol model.Protocol
	// Transport 是这次转发用的连接池。由 outbound.Manager 按网络身份提供 ——
	// 各建一套的话，探活与真实请求就各有一份空闲连接，而共享连接池正是
	// 「探活顺带把连接热着」这份收益的来源。
	Transport http.RoundTripper
	Timeouts  Timeouts
	// OnFirstByte 在首次 §8.8 语义证据时回调（用于记录 TTFT 等）。可为 nil。
	OnFirstByte func()

	// RespTee 收一份响应体副本，供样本记录用（§3.6.3a）。可为 nil。
	//
	// 写入发生在「已写给客户端并 flush 之后」，所以它既不改变字节，
	// 也不改变 flush 时序 —— 采集是旁路，不是管线的一环。
	// 它的写入错误一律忽略：丢一份样本远好过中断一次真实转发。
	RespTee io.Writer
	// RespObserver consumes upstream bytes, independently of client transforms.
	RespObserver health.AttemptObserver

	// RequestHost 覆盖 Host 头。空表示用 URL 自己的 host。
	//
	// 必须走 http.Request.Host 而不是 Header["Host"]：net/http 在写请求行时
	// **只读 req.Host**，塞进 Header 的 Host 会被静默丢弃 —— 那正是
	// 「配了 host_override 却完全没生效」这类问题的来源。
	RequestHost string

	// RedactSecrets 是写给客户端前脱敏 Location 等 URL 头用的已知凭据。
	// 由 Handler 在每次尝试时填入 credentialsOf（含 transform taint）。
	// 为空时 URL 头原样透传（低层 Forward 测试不必关心）。
	RedactSecrets []string
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
	peekBroke    bool
	wire         *wireEvidence
	stageTimeout atomic.Int32
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
	// 而它的 Error() 带上**完整 URL** —— FixedQueryTemplate / legacy_exact
	// 可能把 key 放在 query 里（§7.1），那就等于把上游 key 拼进错误文本。
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
	resp.Body = &onceCloseBody{ReadCloser: resp.Body}
	at.resp = resp
	at.wire = newWireEvidence(f.Protocol, resp.Header, f.RespObserver)
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
// 前缀可能被 TCP 分段切在半截；共享 RetryDecider 对证据不足一律 Keep。
//
// 预读的字节由 Commit 原样重放，不会丢。多次调用只读一次。
func (at *Attempt) Peek() []byte {
	if at.peekDone || at.resp == nil {
		return at.peeked
	}
	at.peekDone = true
	res, f := at.res, at.f

	peekWait := f.Timeouts.peekWaitOrFirstToken()
	timer := time.NewTimer(peekWait)
	defer timer.Stop()
	// One bounded read replaces the old cancellation watcher. If Safe/Balanced
	// reach their short window, Commit owns this very read; no byte is lost and
	// no second reader races the upstream body.
	ready := make(chan peekRead, 1)
	body := at.resp.Body
	go func() {
		buf := make([]byte, peekLimit)
		n, err := body.Read(buf)
		ready <- peekRead{body: buf[:n], err: err, at: time.Now()}
	}()
	var read peekRead
	var timedOut bool
	select {
	case read = <-ready:
	case <-timer.C:
		if f.Timeouts.CommitOnPeekTimeout {
			at.resp.Body = &pendingPeekBody{ReadCloser: body, ready: ready, ctx: at.ctx}
			return nil
		}
		timedOut = true
		_ = body.Close()
		read.err = context.DeadlineExceeded
	case <-at.ctx.Done():
		_ = body.Close()
		read.err = at.ctx.Err()
	}
	n, err := len(read.body), read.err
	if n > 0 {
		at.peeked = read.body
		// 只记首字节时刻；TTFT / OnFirstByte 等 §8.8 语义证据（streamBody）。
		res.FirstByteAt = read.at
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
	var bodyTimeout net.Error
	switch {
	case at.clientCtx.Err() != nil:
		res.Err = fmt.Errorf("%w: %v", ErrCanceled, err)
	case timedOut:
		res.Err = fmt.Errorf("%w: 首 Token 超过 %v", ErrFirstTokenTimeout, f.Timeouts.peekWaitOrFirstToken())
	case at.ctx.Err() != nil:
		res.Err = fmt.Errorf("%w: 超过总时限 %v", ErrTotalTimeout, f.Timeouts.Total)
	case errors.As(err, &bodyTimeout) && bodyTimeout.Timeout():
		res.Err = fmt.Errorf("%w: %v", ErrFirstTokenTimeout, err)
	default:
		res.Err = fmt.Errorf("%w: %v", ErrUpstreamBroke, err)
	}
	return nil
}

type peekRead struct {
	body []byte
	err  error
	at   time.Time
}

// Timers, cancellation and the terminal owner may all close the same Attempt.
// Close reaches the transport once; a pending pre-commit read has the same owner.
type onceCloseBody struct {
	io.ReadCloser
	once sync.Once
	err  error
}

func (body *onceCloseBody) Close() error {
	body.once.Do(func() { body.err = body.ReadCloser.Close() })
	return body.err
}

type pendingPeekBody struct {
	io.ReadCloser
	ready   <-chan peekRead
	ctx     context.Context
	pending []byte
	readErr error
	read    bool
}

func (body *pendingPeekBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if !body.read {
		select {
		case result := <-body.ready:
			body.pending, body.readErr, body.read = result.body, result.err, true
		case <-body.ctx.Done():
			return 0, body.ctx.Err()
		}
	}
	if len(body.pending) > 0 {
		n := copy(p, body.pending)
		body.pending = body.pending[n:]
		return n, nil
	}
	if body.readErr != nil {
		return 0, body.readErr
	}
	return body.ReadCloser.Read(p)
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
	stop := at.watchResponse()
	defer stop()

	// 响应头原样回传。ReverseProxy 会做的逐跳清理这里手动做一次；
	// 同时丢掉上游试图覆盖管理会话的 Set-Cookie: relay_session。
	dst := w.Header()
	for k, vs := range at.resp.Header {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
	FinalizeClientResponseHeaders(dst, f.RedactSecrets)
	w.WriteHeader(at.resp.StatusCode)
	res.HeadersSent = true
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	// 预读走的字节要接回流的最前面。漏掉它就是**静默吞掉响应的开头** ——
	// 客户端收到的 SSE 少了 message_start，或 JSON 少了左半边。
	var src io.Reader = at.resp.Body
	if len(at.peeked) > 0 {
		src = io.MultiReader(bytes.NewReader(at.peeked), at.resp.Body)
	}

	n, err := at.streamBody(w, src, false)
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
	if _, pending := at.resp.Body.(*pendingPeekBody); pending {
		// An undecided window has no reusable complete response yet. Do not
		// wait for another byte while discarding its still-owned first read.
		_ = at.resp.Body.Close()
	}

	// Discarded attempts still deliver the original prefix/drain to the same
	// bounded observer and sample sink. There is no second error-body parser.
	if tee := at.respTee(); tee != nil && len(at.peeked) > 0 {
		_, _ = tee.Write(at.peeked)
	}
	at.captureDrain()
	at.resp.Body.Close()
	if at.res.DoneAt.IsZero() {
		at.res.DoneAt = time.Now()
	}
}

const discardDrainLimit = 4 << 10

// captureDrain reuses only the existing bounded connection-reuse drain.
func (at *Attempt) captureDrain() {
	var body io.Reader = at.resp.Body
	if tee := at.respTee(); tee != nil {
		body = io.TeeReader(body, lenientWriter{tee})
	}
	_, _ = io.CopyN(io.Discard, body, discardDrainLimit)
}

func (at *Attempt) respTee() io.Writer {
	if at.f == nil {
		return nil
	}
	if at.f.RespObserver != nil {
		if at.f.RespTee == nil {
			return observerTee{at.f.RespObserver}
		}
		return io.MultiWriter(at.f.RespTee, observerTee{at.f.RespObserver})
	}
	return at.f.RespTee
}

// lenientWriter 吞掉旁路副本的写入错误：采集失败不得截断排水。
type lenientWriter struct{ w io.Writer }

func (l lenientWriter) Write(p []byte) (int, error) {
	_, _ = l.w.Write(p)
	return len(p), nil
}

// streamBody flushes original bytes before bounded observation. Transformed
// paths already observe the upstream reader and must never feed client output
// back into the wire decoder. watchResponse owns cancellation and timing.
func (at *Attempt) streamBody(w http.ResponseWriter, src io.Reader, inputObserved bool) (int64, error) {
	f, res := at.f, at.res
	flusher, canFlush := w.(http.Flusher)
	buf := make([]byte, 32<<10)
	var total int64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if res.FirstByteAt.IsZero() {
				res.FirstByteAt = time.Now()
			}
			wn, werr := w.Write(buf[:n])
			total += int64(wn)
			if canFlush {
				flusher.Flush()
			}
			if !inputObserved {
				if f.RespObserver != nil {
					_, _ = (observerTee{f.RespObserver}).Write(buf[:n])
				}
				at.wire.feed(buf[:n], time.Now())
			}
			if f.RespTee != nil {
				_, _ = f.RespTee.Write(buf[:n])
			}
			at.projectWire()
			if werr != nil {
				return total, fmt.Errorf("%w: %v", ErrClientGone, werr)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) && !inputObserved {
				at.wire.finish()
			}
			at.projectWire()
			return total, at.readFailure(err, total)
		}
	}
}

// 转发失败的分类哨兵错误。健康状态机（§4.3）按这些类别决定动作。
//
// 分这么细是因为它们对健康状态的含义完全不同：
// 上游连不上要标 dead，客户端断开则完全不该影响健康状态。
var (
	ErrConnect           = health.ErrConnect
	ErrFirstTokenTimeout = health.ErrFirstTokenTimeout
	ErrStreamStalled     = health.ErrStreamStalled
	ErrTotalTimeout      = health.ErrTotalTimeout
	ErrUpstreamBroke     = health.ErrUpstreamBroke
	ErrStreamBroke       = health.ErrStreamBroke
	ErrClientGone        = health.ErrClientGone
	ErrCanceled          = health.ErrCanceled
)

// IsUpstreamFault 判断该错误是否应计入上游的健康失败。
//
// 只有客户端断开与客户端取消不算 —— 它们是客户端的行为，
// 绝不能因此把好站标成 dead。其余一律算上游的账，**包括我们自己设的超时**：
// 那些超时到期正是「这个站太慢/已死」的证据，不算进去的话
// 一个真死的站永远攒不够失败次数，主动探活就失去了意义。
func IsUpstreamFault(err error) bool {
	return health.IsUpstreamFault(err)
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
	// GotConn 已到：请求可能已写出。不得再标成 ErrConnect，否则 Balanced
	// 会按 Safe 建连失败换站并可能双写 POST（§11.2）。
	if errors.Is(err, outbound.ErrAfterGotConn) {
		return fmt.Errorf("%w: %v", ErrUpstreamBroke, err)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return fmt.Errorf("%w: 超时 %v", ErrConnect, err)
	}
	return fmt.Errorf("%w: %v", ErrConnect, err)
}
