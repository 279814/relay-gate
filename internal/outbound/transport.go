package outbound

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// ErrConnectTimeout 表示建连阶段超过了该场景的 connect 预算。
//
// 单独一个哨兵：健康分类要把「连不上」与「连上了但慢」分开，而前者是
// 站级 Reachability 的证据，后者只是这次请求的问题。
var ErrConnectTimeout = errors.New("建立连接超时")

// dialFunc 是 NetworkConfig 可替换的拨号面，只给测试用。
type dialFunc interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// NetworkConfig 是一个连接池的完整身份（§7.3）。
//
// 它刻意**不含** base_url：改 base_url 会让 store 把 network_revision +1，
// 由那一个字段统一承载。而 http.Transport 自己就按 host 分组连接，
// 一个池服务同一个站的多个 host 是正确的，拆开只会多一批空闲连接。
//
// 也刻意不含 priority / weight / 显示名：它们不改变网络目标，换池等于
// 把一批已建好的连接白扔掉 —— 对高延迟公益站，重建的代价是完整 TLS 握手。
type NetworkConfig struct {
	UpstreamID int64
	ProxyURL   string
	// TLSServerName 覆盖 SNI。空表示用 URL 的 host。
	TLSServerName string
	// RequestHost 是要写进 Host 头的值，来自 HostOverride。
	//
	// 它进池键是因为「同一个 IP、不同 Host 头」在上游侧往往是两个不同的
	// 虚拟站，共享连接会让 keep-alive 把请求投到错的那一个。
	RequestHost string
	// NetworkRevision 是 store 侧对「网络配置变了」的唯一表达。
	NetworkRevision int64
	// ConnectTimeout 是这次用途的建连预算。真实请求、L1、L2、count_tokens
	// 各传自己的值，值不同必须不同池（§7.3）。
	ConnectTimeout time.Duration

	// dialer、tlsRoots 与 tlsHandshakeTimeout 只给测试注入用，不来自配置。
	//
	// tlsHandshakeTimeout 存在的唯一理由是让「内层那块表先响」变成可复现的：
	// 生产里它与 ConnectTimeout 同值，谁先响看调度（那正是 CI 上的 flaky），
	// 而测试要能稳定地构造出内层赢的那一半。
	dialer              dialFunc
	tlsRoots            *x509.CertPool
	tlsHandshakeTimeout time.Duration
}

// NetworkFor 从 Upstream 的网络字段与本次用途的 connect 预算组出池身份。
//
// 只有这一个构造函数：各处自己填 NetworkConfig 的话，漏填 NetworkRevision
// 就意味着改了代理却继续用旧池 —— 表现为「配置存进去了，出站流量没变」。
func NetworkFor(upstream *model.ProbeUpstreamConfig, connect time.Duration) NetworkConfig {
	if upstream == nil {
		return NetworkConfig{ConnectTimeout: connect}
	}
	return NetworkConfig{
		UpstreamID:      upstream.ID,
		ProxyURL:        upstream.ProxyURL,
		TLSServerName:   upstream.TLSServerName,
		RequestHost:     upstream.HostOverride,
		NetworkRevision: upstream.NetworkRevision,
		ConnectTimeout:  connect,
	}
}

// poolKey 是池的比较键。
//
// proxy_url 只取 scheme://host 与凭据的**摘要**，不取原文：这个键会出现在
// 诊断输出与日志里，而 proxy_url 可以带 user:password。既要「改了密码就换池」
// 又不能把密码写进键，所以凭据走一层 hash。
func (network NetworkConfig) poolKey() string {
	parts := []string{
		strconv.FormatInt(network.UpstreamID, 10),
		maskProxyForKey(network.ProxyURL),
		network.TLSServerName,
		network.RequestHost,
		strconv.FormatInt(network.NetworkRevision, 10),
		network.ConnectTimeout.String(),
	}
	return strings.Join(parts, "\x00")
}

// maskProxyForKey 把 proxy_url 压成「可比较但不泄密」的形式。
func maskProxyForKey(raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User == nil {
		// 解析不了就原样参与比较：这类值会在 Transport 构造时被拒，
		// 而在那之前它必须能与别的值区分开（否则一个坏值会复用好值的池）。
		return raw
	}
	credentials := parsed.User.String()
	parsed.User = nil
	return parsed.String() + "#" + requestKeyDigest(credentials)
}

// requestKeyDigest 给一段凭据算一个短摘要，只用于池键去重。
//
// 用 FNV 而不是 SHA：这不是安全用途（键本来就不能反推），它只需要
// 「不同凭据几乎必然不同键」，而短一些让日志里的键还能读。
func requestKeyDigest(value string) string {
	const offset64, prime64 = uint64(14695981039346656037), uint64(1099511628211)
	hash := offset64
	for index := 0; index < len(value); index++ {
		hash ^= uint64(value[index])
		hash *= prime64
	}
	return strconv.FormatUint(hash, 16)
}

// Transport 是一个连接池，外加它的 connect 预算。
//
// 包一层而不是直接暴露 *http.Transport：connect timeout 不能只靠
// net.Dialer.Timeout + TLSHandshakeTimeout —— 那两个加起来仍漏掉
// **HTTP 代理的 CONNECT 往返**（代理接受 TCP 后不回响应，两个 timeout
// 都不管这一段）。所以要在 RoundTrip 外面再套一层，从发起到 GotConn 为止
// 计一个总表。
type Transport struct {
	base    *http.Transport
	connect time.Duration
}

func (transport *Transport) ConnectTimeout() time.Duration { return transport.connect }

func (transport *Transport) CloseIdleConnections() { transport.base.CloseIdleConnections() }

// RoundTrip 在建连阶段施加 connect 预算，连接建立后立刻解除。
//
// 「连接建立后解除」是这里的全部要点：把预算做成整个请求的超时会把正常的
// 长思考砍断（首语义可达数百秒，real_first_semantic_sec 有 300s 硬下限），
// 而不施加任何约束则让一个「TCP 通了但握手不完成」的站占住整份总预算。
//
// 手段是 httptrace 的 GotConn 回调 + 一个 timer：timer 到期就 cancel 这次请求
// 的 context，GotConn 一到就 Stop timer。
func (transport *Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	if transport.connect <= 0 {
		return transport.base.RoundTrip(request)
	}

	ctx, cancel := context.WithCancel(request.Context())
	// gotConn 与 timedOut 一起把「失败发生在建连阶段」这件事变成可判定的，
	// 而不依赖谁先响 —— 见 connectPhaseTimeout。
	var gotConn atomic.Bool
	timedOut := make(chan struct{})
	timer := time.AfterFunc(transport.connect, func() {
		close(timedOut)
		cancel()
	})

	// 已有的 trace（调用方装的观测）必须保留：httptrace.WithClientTrace 会
	// 把两个 trace 合并（同名回调都调用），所以这里叠加而不是替换。
	traced := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) {
			gotConn.Store(true)
			timer.Stop()
		},
	})
	response, err := transport.base.RoundTrip(request.WithContext(traced))
	timer.Stop()

	if err != nil {
		cancel()
		// 区分「我们的 connect 预算到期」与「别的失败」：前者是站级
		// Reachability 的证据，后者可能只是这一次的问题。
		if transport.connectPhaseTimeout(request, err, gotConn.Load(), timedOut) {
			return nil, fmt.Errorf("%w: 超过 %v", ErrConnectTimeout, transport.connect)
		}
		return nil, err
	}
	// 拿到响应了就**不能**在这里 cancel：响应体还没读，cancel 会掐断流 ——
	// 表现为「所有流式响应立刻断开」。释放挂到 body 关闭上。
	response.Body = &bodyWithCancel{ReadCloser: response.Body, cancel: cancel}
	return response, nil
}

// connectPhaseTimeout 判断这次失败是不是「建连阶段超了预算」。
//
// 为什么不能只看外层 timer 有没有开火：同一份 connect 预算有三个执行者 ——
// 外层的 timer、http.Transport.TLSHandshakeTimeout、net.Dialer.Timeout。
// 三块表几乎同时到期，谁先响看调度，而内层两条的路径都比外层短（外层要走
// cancel → ctx.Done → 监听 goroutine 被调度 → 关连接 → 阻塞的 read 返回）。
// 内层赢的那些次，错误是 net/http 的 "TLS handshake timeout" 或 net.DNSError，
// 只看 timedOut 就会把它们判成「别的失败」—— 健康分类因此拿不到
// 「是我们的预算截断了它」这个判据。这正是 CI 上那次 flaky 的根因：
// 本机 Windows 的 loopback 稍慢，外层总是赢；CI 的共享 runner 上内层会赢。
//
// 判据换成三条，前两条任一成立且第三条不成立：
//
//  1. 外层 timer 开了火（timedOut 已关）—— 确定是我们发的 cancel。
//  2. **连接还没建立**（GotConn 没到）且错误是个超时。此时无论哪块表赢，
//     语义都是同一个：连接没建起来，而且是被时间限制截断的。
//  3. 但**调用方自己的 ctx 先到期**时一律不算：那是「客户端不等了」或
//     「上层的总预算用完了」，与「这个站连不上」完全是两件事。
//
// 第 2 条用 GotConn 而不是错误文本匹配：文本会随 Go 版本变，而「有没有拿到
// 连接」是这个判断真正要问的东西。GotConn 之后的超时属于响应头/首字节阶段，
// 由 Budget 管，绝不能归到 connect —— 那会把一个慢站误报成连不上。
//
// 第 3 条不能省。context.DeadlineExceeded 自己就满足 net.Error（Timeout()
// 返回 true），而真实转发路径给的 ctx 带着 CapTotal 算出的总预算 ——
// 少了这条，一次「客户端总预算在建连期间用完」会被报成站级不可达，
// 而站级不可达会让该 Upstream 下**所有** Route 一并判死（§4.1）。
func (transport *Transport) connectPhaseTimeout(request *http.Request,
	err error, gotConn bool, timedOut <-chan struct{}) bool {

	// 调用方的 ctx 先到期就不是我们的账。必须先判：它到期会连带取消
	// 我们派生的 ctx，后判就把两者混为一谈了（与 classifyTransportErr
	// 里「必须先判 clientCtx」是同一条理由）。
	if request.Context().Err() != nil {
		return false
	}
	select {
	case <-timedOut:
		return true
	default:
	}
	if gotConn {
		return false
	}
	var timeout net.Error
	return errors.As(err, &timeout) && timeout.Timeout()
}

// bodyWithCancel 把 context 的释放挂到响应体关闭上。
//
// 不这么做的话，为了不泄漏 context 就得在 RoundTrip 返回前 cancel，
// 而那会在读第一个 chunk 之前掐断流 —— 表现为「所有流式响应立刻断开」。
type bodyWithCancel struct {
	io.ReadCloser
	cancel context.CancelFunc
	once   sync.Once
}

func (body *bodyWithCancel) Close() error {
	err := body.ReadCloser.Close()
	body.once.Do(body.cancel)
	return err
}

// Manager 按网络身份缓存连接池（§7.3）。
type Manager struct {
	mu sync.RWMutex
	// pools 的键是 poolKey()。一个 Upstream 会有多个池（每种 connect 预算
	// 一个），所以还要按 upstream 反查才能实现 Invalidate。
	pools map[string]*Transport
	// byUpstream 让 Invalidate 能一次清掉某站的**全部**池。
	// 只清其中一个的话，「整站重置连接」就只对真实请求生效，探活还在用旧连接。
	byUpstream map[int64]map[string]struct{}
}

func NewManager() *Manager {
	return &Manager{
		pools:      map[string]*Transport{},
		byUpstream: map[int64]map[string]struct{}{},
	}
}

// Transport 取（或建）这份网络配置对应的连接池。
//
// 返回 error 而不是静默回落到一个默认池：唯一的失败原因是 proxy_url 解析
// 不了，而那时静默忽略代理意味着流量直接发往上游 —— 一个配了代理的用户
// 会以为流量在走代理。
func (manager *Manager) Transport(network NetworkConfig) (*Transport, error) {
	key := network.poolKey()

	manager.mu.RLock()
	existing, ok := manager.pools[key]
	manager.mu.RUnlock()
	if ok {
		return existing, nil
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()
	// 双检：可能在等锁期间已被别的请求建好。
	if existing, ok := manager.pools[key]; ok {
		return existing, nil
	}
	transport, err := newTransport(network)
	if err != nil {
		return nil, err
	}
	manager.pools[key] = transport
	keys := manager.byUpstream[network.UpstreamID]
	if keys == nil {
		keys = map[string]struct{}{}
		manager.byUpstream[network.UpstreamID] = keys
	}
	keys[key] = struct{}{}
	return transport, nil
}

// Invalidate 丢弃某个 Upstream 的全部连接池。
//
// 关空闲连接、不取消在途请求：在途请求持有自己的 *Transport 引用，
// 读到底为止都用它。取消它们等于「改一次配置就断掉正在传输的对话」。
//
// 常规配置变更**不需要**调它：池键已经含 network_revision，改了会自然换池。
// 这个方法留给「配置没变但连接池本身要重置」的场景（探活判定整站不可用）。
func (manager *Manager) Invalidate(upstreamID int64) {
	manager.mu.Lock()
	keys := manager.byUpstream[upstreamID]
	delete(manager.byUpstream, upstreamID)
	stale := make([]*Transport, 0, len(keys))
	for key := range keys {
		if transport, ok := manager.pools[key]; ok {
			stale = append(stale, transport)
			delete(manager.pools, key)
		}
	}
	manager.mu.Unlock()

	// 在锁外关：CloseIdleConnections 会去动连接，没有理由让别的
	// Transport 调用等它。
	for _, transport := range stale {
		transport.CloseIdleConnections()
	}
}

// PoolCount 返回当前缓存的连接池数量。
//
// 供测试断言「并发请求没有重复建池」用：那个 bug 不会报错，只表现为
// 「每次请求都重新 TLS 握手」，而握手耗时对高延迟公益站是可观的。
func (manager *Manager) PoolCount() int {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	return len(manager.pools)
}

// CloseIdleConnections 关闭所有池的空闲连接，供优雅关闭调用。
func (manager *Manager) CloseIdleConnections() {
	manager.mu.RLock()
	pools := make([]*Transport, 0, len(manager.pools))
	for _, transport := range manager.pools {
		pools = append(pools, transport)
	}
	manager.mu.RUnlock()

	for _, transport := range pools {
		transport.CloseIdleConnections()
	}
}

// newTransport 构造一个连接池。
//
// DisableCompression=true 是硬要求（§6.7）：Go 默认会偷偷加
// Accept-Encoding: gzip 并自动解压响应，而自动解压会删掉 Content-Encoding ——
// 等于改动了响应，违反「响应完全不碰」。关掉后客户端的 Accept-Encoding
// 原样转发，响应体字节流原样回传。
func newTransport(network NetworkConfig) (*Transport, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: network.TLSServerName,
		RootCAs:    network.tlsRoots,
	}

	base := &http.Transport{
		DialContext:        dialContextFor(network),
		TLSClientConfig:    tlsConfig,
		DisableCompression: true,

		// TLSHandshakeTimeout 与外层 timer 是同一份预算的两个执行者，两块表
		// 几乎同时到期，谁先响看调度 —— 内层赢时错误是 net/http 自己的
		// "TLS handshake timeout"，不带我们的哨兵。
		//
		// 但**不能**靠删掉它来消除这个竞争：留着它，「握手卡住」在两条路径上
		// 都会被截断；而 RoundTrip 的分类已改成不依赖谁先响（见那里的
		// connectPhaseTimeout），所以两块表同时在反而更稳 —— 外层那条链
		// （cancel → ctx.Done → 关连接）比内层长，多一道内层的保险没有坏处。
		TLSHandshakeTimeout: handshakeTimeoutFor(network),

		// 公益站延迟高，连接复用能省掉每次 TLS 握手（实测握手占首字节的
		// 可观比例）。
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,

		// 不设 ResponseHeaderTimeout：响应头时限由 Budget 在调用侧控制。
		// 设在这里会与 Budget 打架，且它管不到「响应头回来了但 body 不吐」
		// 这个更常见的挂法。
		ForceAttemptHTTP2: true,
	}

	if network.ProxyURL != "" {
		parsed, err := url.Parse(network.ProxyURL)
		if err != nil {
			// 不带 err 文本：net/url 的错误会附上完整 URL，而 proxy_url
			// 可以带 user:password。这条错误会落进 last_error 并显示在 UI 上。
			return nil, model.WrapValidation("proxy_url 不是合法 URL")
		}
		if parsed.Scheme == "" || parsed.Host == "" {
			return nil, model.WrapValidation("proxy_url 必须形如 scheme://host[:port]")
		}
		base.Proxy = http.ProxyURL(parsed)
	}

	return &Transport{base: base, connect: network.ConnectTimeout}, nil
}

// handshakeTimeoutFor 取 TLS 握手的内层时限。
//
// 生产里恒等于 ConnectTimeout。只有测试会给一个更短的值，用来稳定地构造
// 「内层那块表先响」—— 生产中那一半靠调度决定，本机复现不出来。
func handshakeTimeoutFor(network NetworkConfig) time.Duration {
	if network.tlsHandshakeTimeout > 0 {
		return network.tlsHandshakeTimeout
	}
	return network.ConnectTimeout
}

// dialContextFor 造拨号函数。
//
// net.Dialer.Timeout 仍然设上：它覆盖 DNS + TCP，是最内层的那道约束，
// 而外层 RoundTrip 的 timer 覆盖包含代理 CONNECT 与 TLS 握手的全程。
// 两层都在 —— 只留外层的话，一次拨号失败要等整份 connect 预算才报错，
// 而 net.Dialer 本可以更早给出准确的错误。
func dialContextFor(network NetworkConfig) func(context.Context, string, string) (net.Conn, error) {
	if network.dialer != nil {
		return network.dialer.DialContext
	}
	dialer := &net.Dialer{
		Timeout:   network.ConnectTimeout,
		KeepAlive: 30 * time.Second,
	}
	return dialer.DialContext
}

// Trace 是一次请求的建连观测点。
//
// 字段与 probe_execution 的列一一对应（tls_handshake_start_at_ms 等）：
// 各记一套的话，「握手占了多久」在探活与真实流量两边会有不同定义。
type Trace struct {
	TLSHandshakeStart time.Time
	TLSHandshakeDone  time.Time
	GotConn           time.Time
	// Reused 为 true 表示这次没有新建连接，也就没有握手时间。
	Reused bool
}

// WithTrace 给请求装上观测回调，返回装好的请求。
//
// 每次请求各一个 *Trace：共享 Transport 的并发请求若共享一个 Trace，
// 就会互相串写（-race 会抓到），而串写的后果是 last_tls_ms 记的是
// 另一个请求的握手。
func WithTrace(request *http.Request, trace *Trace) *http.Request {
	if trace == nil {
		return request
	}
	ctx := httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
		TLSHandshakeStart: func() { trace.TLSHandshakeStart = time.Now() },
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			trace.TLSHandshakeDone = time.Now()
		},
		GotConn: func(info httptrace.GotConnInfo) {
			trace.GotConn = time.Now()
			trace.Reused = info.Reused
		},
	})
	return request.WithContext(ctx)
}
