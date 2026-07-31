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
	"strings"
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

// BuildOutboundURL 拼出站 URL（§3.1）。
//
// 规则：base_url（去尾斜杠）+ 入站 path + 原样带上 RawQuery。
// query 必须带：真实 Claude Code 打的是 /v1/messages?beta=true，
// 丢掉 ?beta=true 会改变上游行为。
//
// full_url_mode 下 base_url 自己可能已经带了 query（`...?key=xxx` 是
// 非标准站的常见形态，而这个开关正是为它们准备的）。这时必须用 `&` 续接，
// 用 `?` 会拼出 `?key=xxx?beta=true` —— 两个问号是非法 URL，上游要么整个
// 拒掉、要么把后半段当成 key 值的一部分，症状是「配了 key 却一直 401」。
func BuildOutboundURL(up *model.Upstream, inPath, rawQuery string) (string, error) {
	base := strings.TrimRight(up.BaseURL, "/")
	var full string
	if up.FullURLMode {
		// 逃生舱：base_url 即完整端点，不拼路径（应对非标准路径的站）
		full = base
	} else {
		full = base + inPath
	}
	if rawQuery != "" {
		sep := "?"
		if strings.Contains(full, "?") {
			sep = "&"
		}
		full += sep + rawQuery
	}
	if _, err := url.Parse(full); err != nil {
		return "", fmt.Errorf("拼接出站 URL 失败: %w", err)
	}
	return full, nil
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
}

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
}

// Forward 把请求投递到 cand 指定的上游，响应流式写回 w。
//
// body 必须是已经过 ReplaceModel 处理的字节。header 必须是
// PrepareOutboundHeaders 的产物。
func (f *Forwarder) Forward(ctx context.Context, w http.ResponseWriter,
	method, outURL string, header http.Header, body []byte) *Result {

	res := &Result{}

	// 保留客户端原始的 ctx。加了超时之后就分不清「客户端断开」与
	// 「我们自己的超时到期」了，而这两者对健康状态的含义完全相反。
	clientCtx := ctx

	// 总超时是最外层的兜底。首 Token 与 Idle 在读循环里单独控制。
	ctx, cancel := context.WithTimeout(ctx, f.Timeouts.Total)
	defer cancel()

	// bytes.NewReader 而不是 strings.NewReader(string(body))：
	// 后者会把整个 body 复制一遍，而 body 可能有几百 KB 到 MB。
	req, err := http.NewRequestWithContext(ctx, method, outURL, bytes.NewReader(body))
	if err != nil {
		res.Err = fmt.Errorf("构造出站请求: %w", err)
		return res
	}
	req.Header = header
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
	resp, err := f.Transport.RoundTrip(req)
	headerTimer.Stop()
	if err != nil {
		res.Err = classifyTransportErr(err, clientCtx, headerTimedOut.Load(), f.Timeouts.FirstToken)
		res.DoneAt = time.Now()
		return res
	}
	defer resp.Body.Close()

	res.Status = resp.StatusCode
	res.RespHeaders = resp.Header.Clone()

	// 响应头原样回传。ReverseProxy 会做的逐跳清理这里手动做一次。
	dst := w.Header()
	for k, vs := range resp.Header {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
	StripHopByHopResponse(dst)
	w.WriteHeader(resp.StatusCode)
	res.HeadersSent = true

	n, err := f.streamBody(ctx, clientCtx, w, resp.Body, resp.Body, res)
	res.BytesWritten = n
	res.DoneAt = time.Now()
	if err != nil && res.Err == nil {
		res.Err = err
	}
	return res
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
			if total == 0 {
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
