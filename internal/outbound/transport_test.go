package outbound

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// serverRoots 取 httptest TLS server 的自签根证书。
func serverRoots(t *testing.T, server *httptest.Server) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	return pool
}

func netUpstream() *model.Upstream {
	return &model.Upstream{
		ID: 7, Name: "s", BaseURL: "https://example.com", Enabled: true,
		NetworkRevision: 1,
	}
}

func netFor(upstream *model.Upstream, connect time.Duration) NetworkConfig {
	return NetworkFor(upstream.ProbeConfig(), connect)
}

func mustTransport(t *testing.T, manager *Manager, network NetworkConfig) *Transport {
	t.Helper()
	transport, err := manager.Transport(network)
	if err != nil {
		t.Fatalf("构造 Transport: %v", err)
	}
	return transport
}

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	manager := NewManager()
	t.Cleanup(manager.CloseIdleConnections)
	return manager
}

// ── 池分组（计划第 1、10 条）─────────────────────────────────

func TestManager_DifferentConnectTimeoutsGetDifferentPools(t *testing.T) {
	manager := newTestManager(t)
	upstream := netUpstream()

	l1 := mustTransport(t, manager, netFor(upstream, time.Second))
	l2 := mustTransport(t, manager, netFor(upstream, 3*time.Second))

	if l1 == l2 {
		t.Fatal("l1_connect_sec=1 与 l2_connect_sec=3 必须落在不同连接池，" +
			"共享一个池就意味着其中一个的 connect timeout 是死的")
	}
	// 「可观察的不同超时」：从 Transport 自己身上读回来，而不是从造它的配置。
	if got := l1.ConnectTimeout(); got != time.Second {
		t.Errorf("L1 池的 connect timeout want 1s got %v", got)
	}
	if got := l2.ConnectTimeout(); got != 3*time.Second {
		t.Errorf("L2 池的 connect timeout want 3s got %v", got)
	}
	// 三层都要带上这个值，缺任一层就有一个建连阶段不受约束。
	if got := l1.base.TLSHandshakeTimeout; got != time.Second {
		t.Errorf("TLSHandshakeTimeout want 1s got %v", got)
	}
}

func TestManager_SameConfigSharesPool(t *testing.T) {
	manager := newTestManager(t)
	upstream := netUpstream()

	first := mustTransport(t, manager, netFor(upstream, 2*time.Second))
	second := mustTransport(t, manager, netFor(upstream, 2*time.Second))
	if first != second {
		t.Fatal("同一份网络配置必须共享连接池，否则每次调用都要重新 TLS 握手")
	}
}

// 计划第 10 条：什么该换池、什么不该。
//
// 「不该换」与「该换」一样要钉住：无谓换池会把一批已建好的连接白扔掉，
// 而对高延迟公益站，重建它们的代价是每次一次完整 TLS 握手。
func TestManager_PoolIdentityCoversNetworkConfigOnly(t *testing.T) {
	manager := newTestManager(t)
	baseline := mustTransport(t, manager, netFor(netUpstream(), 2*time.Second))

	changesPool := []struct {
		name  string
		apply func(*model.Upstream)
	}{
		{"proxy_url", func(u *model.Upstream) { u.ProxyURL = "http://127.0.0.1:9" }},
		{"tls_server_name", func(u *model.Upstream) { u.TLSServerName = "sni.example.com" }},
		{"host_override", func(u *model.Upstream) { u.HostOverride = "real.example.com" }},
		{"network_revision", func(u *model.Upstream) { u.NetworkRevision = 2 }},
	}
	for _, testCase := range changesPool {
		t.Run("换池/"+testCase.name, func(t *testing.T) {
			upstream := netUpstream()
			testCase.apply(upstream)
			if got := mustTransport(t, manager, netFor(upstream, 2*time.Second)); got == baseline {
				t.Errorf("改了 %s 必须换池，复用旧池等于该配置对出站流量无效", testCase.name)
			}
		})
	}

	keepsPool := []struct {
		name  string
		apply func(*model.Upstream)
	}{
		// 这几个字段只影响显示或选路。base_url 刻意不在池键里：
		// 它一改 network_revision 就会 +1（store.UpdateUpstreamWithRevision），
		// 由那一个字段统一承载，而 http.Transport 本身按 host 分组连接，
		// 一个池服务多个 host 是正确的。
		{"name", func(u *model.Upstream) { u.Name = "改了个显示名" }},
		{"enabled", func(u *model.Upstream) { u.Enabled = false }},
		{"revision", func(u *model.Upstream) { u.Revision = 99 }},
		{"credential_revision", func(u *model.Upstream) { u.CredentialRevision = 42 }},
	}
	for _, testCase := range keepsPool {
		t.Run("留池/"+testCase.name, func(t *testing.T) {
			upstream := netUpstream()
			testCase.apply(upstream)
			if got := mustTransport(t, manager, netFor(upstream, 2*time.Second)); got != baseline {
				t.Errorf("改了 %s 不该换池：这个字段与网络目标无关", testCase.name)
			}
		})
	}
}

func TestManager_DifferentUpstreamsNeverSharePool(t *testing.T) {
	manager := newTestManager(t)
	first := netUpstream()
	second := netUpstream()
	second.ID = 8

	if mustTransport(t, manager, netFor(first, time.Second)) ==
		mustTransport(t, manager, netFor(second, time.Second)) {
		t.Fatal("不同 Upstream 必须各自一个池（§7.3 的池键第一项）")
	}
}

// ── Invalidate（计划第 8 条）────────────────────────────────

func TestManager_InvalidateClosesIdleWithoutCancelingInflight(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-release
		_, _ = w.Write([]byte("done"))
	}))
	t.Cleanup(server.Close)

	manager := newTestManager(t)
	upstream := &model.Upstream{ID: 3, BaseURL: server.URL, NetworkRevision: 1}
	network := netFor(upstream, 2*time.Second)
	transport := mustTransport(t, manager, network)

	request, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("首个请求应成功: %v", err)
	}

	// 在途请求持有旧 Transport 的引用。Invalidate 只该关**空闲**连接。
	manager.Invalidate(upstream.ID)

	close(release)
	// 用 ReadAll 而不是一次 Read：短 body 的 Read 可以同时返回 n>0 与 io.EOF，
	// 那是正常形态，按「err != nil 即失败」判会得到一个假的红。
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("Invalidate 不得取消在途请求，读 body 失败: %v", err)
	}
	response.Body.Close()
	if string(body) != "done" {
		t.Errorf("在途响应应完整读到，得到 %q", body)
	}

	// Invalidate 之后必须给出一个新池，否则「重置连接」是句空话。
	if again := mustTransport(t, manager, network); again == transport {
		t.Error("Invalidate 之后应重建 Transport")
	}
}

func TestManager_InvalidateDropsEveryPoolOfThatUpstream(t *testing.T) {
	manager := newTestManager(t)
	upstream := netUpstream()

	l1 := mustTransport(t, manager, netFor(upstream, time.Second))
	l2 := mustTransport(t, manager, netFor(upstream, 3*time.Second))
	manager.Invalidate(upstream.ID)

	// 一个站有几个池（每种 connect timeout 一个）。只清其中一个的话，
	// 「整站重置连接」就只对真实请求生效，探活还在用旧连接。
	if mustTransport(t, manager, netFor(upstream, time.Second)) == l1 {
		t.Error("L1 池未被 Invalidate 清掉")
	}
	if mustTransport(t, manager, netFor(upstream, 3*time.Second)) == l2 {
		t.Error("L2 池未被 Invalidate 清掉")
	}
}

// ── 压缩（计划第 9 条）──────────────────────────────────────

func TestManager_NeverInjectsGzipNorDecompresses(t *testing.T) {
	var gotAcceptEncoding string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAcceptEncoding = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		// gzip("hi")。Go 若自动解压，会顺手删掉 Content-Encoding。
		_, _ = w.Write([]byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0xff, 0xcb, 0xc8, 0x04, 0x00, 0x00, 0x00, 0xff, 0xff})
	}))
	t.Cleanup(server.Close)

	manager := newTestManager(t)
	upstream := &model.Upstream{ID: 4, BaseURL: server.URL, NetworkRevision: 1}
	transport := mustTransport(t, manager, netFor(upstream, 2*time.Second))

	request, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if gotAcceptEncoding != "" {
		t.Errorf("Transport 不得自动注入 Accept-Encoding，上游收到 %q", gotAcceptEncoding)
	}
	if response.Header.Get("Content-Encoding") != "gzip" {
		t.Error("Content-Encoding 被删掉了 —— 说明响应被自动解压，违反严格透传")
	}
	if response.Uncompressed {
		t.Error("响应被自动解压了")
	}
}

// ── connect timeout（计划第 2、3、4 条）─────────────────────

// connectPhaseCase 描述一种「建连没完成」的故障，四条覆盖四个阶段。
type connectPhaseCase struct {
	name  string
	setup func(t *testing.T, connect time.Duration) (target string, network NetworkConfig)
}

func TestConnectTimeout_CoversEveryConnectPhase(t *testing.T) {
	const connect = 150 * time.Millisecond

	cases := []connectPhaseCase{
		{
			name: "DNS",
			setup: func(t *testing.T, connect time.Duration) (string, NetworkConfig) {
				network := netFor(netUpstream(), connect)
				network.dialer = blockingDialer{phase: phaseDNS}
				return "https://never-resolves.invalid/v1/models", network
			},
		},
		{
			name: "TCP",
			setup: func(t *testing.T, connect time.Duration) (string, NetworkConfig) {
				network := netFor(netUpstream(), connect)
				network.dialer = blockingDialer{phase: phaseTCP}
				return "https://192.0.2.1/v1/models", network
			},
		},
		{
			// HTTP 代理接受 TCP 但不回 CONNECT 响应。
			// net.Dialer.Timeout 与 TLSHandshakeTimeout **都覆盖不到**这一段，
			// 它是这条测试存在的主要理由。
			name: "proxy CONNECT",
			setup: func(t *testing.T, connect time.Duration) (string, NetworkConfig) {
				upstream := netUpstream()
				upstream.ProxyURL = "http://" + listenAndHang(t)
				return "https://example.com/v1/models", netFor(upstream, connect)
			},
		},
		{
			// TLS server 接受 TCP 但不完成握手。
			name: "TLS 握手",
			setup: func(t *testing.T, connect time.Duration) (string, NetworkConfig) {
				return "https://" + listenAndHang(t) + "/v1/models",
					netFor(netUpstream(), connect)
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			target, network := testCase.setup(t, connect)
			transport := mustTransport(t, newTestManager(t), network)

			request, err := http.NewRequest(http.MethodGet, target, nil)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			response, err := transport.RoundTrip(request)
			elapsed := time.Since(start)
			if err == nil {
				response.Body.Close()
				t.Fatal("阻塞的建连阶段必须失败，而不是挂到调用方的总超时")
			}
			// 上限给 20 倍：这条测试要证明的是「有一个约束在起作用」，
			// 不是计时精度。CI 上共享 runner 的抖动能到几十毫秒。
			if elapsed > 20*connect {
				t.Errorf("%s 阶段没有被 connect timeout 截断，耗时 %v（预算 %v）",
					testCase.name, elapsed, connect)
			}
			if !errors.Is(err, ErrConnectTimeout) {
				t.Errorf("错误应能识别为 connect 超时（健康分类要靠它），得到 %v", err)
			}
		})
	}
}

// 计划第 5 条：GotConn 之后停表，慢响应头不被 connect timeout 截断。
//
// 这是本文件最要紧的一条：把 connect timeout 做成「整个请求的超时」
// 会把正常的长思考砍断 —— 而那正是 real_first_semantic_sec 的 300s
// 硬下限要保护的场景。
func TestConnectTimeout_StopsAfterGotConn(t *testing.T) {
	const connect = 120 * time.Millisecond

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(6 * connect)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	upstream := &model.Upstream{ID: 5, BaseURL: server.URL, NetworkRevision: 1}
	transport := mustTransport(t, newTestManager(t), netFor(upstream, connect))

	request, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("连接已建立后，慢响应头不该被 connect timeout 掐断：%v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Errorf("status want 200 got %d", response.StatusCode)
	}
}

// 计划第 5 条后半：trace sink 拿到握手时间点；复用连接不继承上一次的 TLS 时间。
func TestTrace_RecordsHandshakeAndDoesNotLeakAcrossReuse(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.StartTLS()
	t.Cleanup(server.Close)

	upstream := &model.Upstream{ID: 6, BaseURL: server.URL, NetworkRevision: 1}
	network := netFor(upstream, 2*time.Second)
	network.tlsRoots = serverRoots(t, server)
	transport := mustTransport(t, newTestManager(t), network)

	send := func() Trace {
		var trace Trace
		request, _ := http.NewRequest(http.MethodGet, server.URL, nil)
		response, err := transport.RoundTrip(WithTrace(request, &trace))
		if err != nil {
			t.Fatalf("请求失败: %v", err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		return trace
	}

	first := send()
	switch {
	case first.TLSHandshakeStart.IsZero(), first.TLSHandshakeDone.IsZero():
		t.Fatal("首个请求应记录 TLS 握手的起止时刻（probe_execution 有这两列）")
	case first.GotConn.IsZero():
		t.Fatal("应记录 GotConn —— connect timer 正是在这一刻停的")
	case first.TLSHandshakeDone.Before(first.TLSHandshakeStart):
		t.Error("握手结束时刻不应早于开始时刻")
	}

	second := send()
	if second.GotConn.IsZero() {
		t.Fatal("复用连接的请求同样要记录 GotConn")
	}
	if !second.Reused {
		t.Skip("连接未被复用，本次无法验证 TLS 时间不继承")
	}
	if !second.TLSHandshakeStart.IsZero() || !second.TLSHandshakeDone.IsZero() {
		t.Errorf("复用连接不该继承上一次的 TLS 握手时间（否则 last_tls_ms 会把"+
			"一次省掉的握手记成又握了一次），得到 start=%v done=%v",
			second.TLSHandshakeStart, second.TLSHandshakeDone)
	}
}

// 共享 Transport 上并发发请求，每个请求各自的 trace 不得互相串写。
// 这条只有在 -race 下才有牙（CI 的 Linux job 会跑）。
func TestTrace_ConcurrentRequestsShareTransportWithoutRace(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	upstream := &model.Upstream{ID: 8, BaseURL: server.URL, NetworkRevision: 1}
	transport := mustTransport(t, newTestManager(t), netFor(upstream, 2*time.Second))

	const workers = 8
	var group sync.WaitGroup
	group.Add(workers)
	for index := 0; index < workers; index++ {
		go func() {
			defer group.Done()
			var trace Trace
			request, _ := http.NewRequest(http.MethodGet, server.URL, nil)
			response, err := transport.RoundTrip(WithTrace(request, &trace))
			if err != nil {
				t.Errorf("并发请求失败: %v", err)
				return
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if trace.GotConn.IsZero() {
				t.Error("每个并发请求都该拿到自己的 GotConn")
			}
		}()
	}
	group.Wait()
}

func TestManager_RejectsBadProxyURL(t *testing.T) {
	upstream := netUpstream()
	upstream.ProxyURL = "http://[::1"

	if _, err := newTestManager(t).Transport(netFor(upstream, time.Second)); err == nil {
		t.Fatal("非法 proxy_url 必须报错，静默忽略等于让流量绕过代理")
	}
}

func TestNetworkConfig_AppliesTLSSettings(t *testing.T) {
	upstream := netUpstream()
	upstream.TLSServerName = "sni.example.com"

	transport := mustTransport(t, newTestManager(t), netFor(upstream, time.Second))
	if got := transport.base.TLSClientConfig.ServerName; got != "sni.example.com" {
		t.Errorf("Transport 的 TLS ServerName want sni.example.com got %q", got)
	}
	if transport.base.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Error("TLS 最低版本必须是 1.2")
	}
	if transport.base.TLSClientConfig.InsecureSkipVerify {
		t.Error("绝不允许跳过证书校验")
	}
}

func TestNetworkConfig_PoolKeyNeverCarriesProxyCredentials(t *testing.T) {
	upstream := netUpstream()
	upstream.ProxyURL = "http://user:hunter2@127.0.0.1:8080"
	network := netFor(upstream, time.Second)

	// 池键会进诊断输出与日志。代理密码进去就是明文凭据落盘。
	if key := network.poolKey(); strings.Contains(key, "hunter2") || strings.Contains(key, "user") {
		t.Errorf("池键不得包含代理凭据，得到 %q", key)
	}

	// 但换了密码仍必须换池 —— 否则改对了代理凭据也不生效。
	other := netUpstream()
	other.ProxyURL = "http://user:different@127.0.0.1:8080"
	if netFor(other, time.Second).poolKey() == network.poolKey() {
		t.Error("代理凭据变化必须改变池键")
	}
}

func TestNetworkConfig_ProxyURLTakesEffect(t *testing.T) {
	upstream := netUpstream()
	upstream.ProxyURL = "http://127.0.0.1:8080"

	transport := mustTransport(t, newTestManager(t), netFor(upstream, time.Second))
	if transport.base.Proxy == nil {
		t.Fatal("配了 proxy_url 就必须走代理")
	}
	proxied, err := transport.base.Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: "example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if proxied == nil || proxied.Host != "127.0.0.1:8080" {
		t.Fatalf("代理地址应为 127.0.0.1:8080，得到 %v", proxied)
	}
}

// ── helper ────────────────────────────────────────────────

type connectPhase int

const (
	phaseDNS connectPhase = iota
	phaseTCP
)

// blockingDialer 模拟卡在 DNS 或 TCP 的建连。
//
// 用假 dialer 而不是真去连一个黑洞地址：后者依赖运行环境（防火墙可能立刻
// 回 RST，CI 与本机行为不同），而这条测试要验的恰恰是「我们自己的约束生效」。
type blockingDialer struct{ phase connectPhase }

func (dialer blockingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	<-ctx.Done()
	if dialer.phase == phaseDNS {
		return nil, &net.DNSError{Err: ctx.Err().Error(), Name: address, IsTimeout: true}
	}
	return nil, &net.OpError{Op: "dial", Net: network, Err: ctx.Err()}
}

// listenAndHang 起一个只 accept、之后什么都不做的监听器。
//
// 一个 helper 服务两种场景：作为 HTTP 代理时不回 CONNECT 响应，作为 HTTPS
// 目标时不完成 TLS 握手。两者都是「TCP 通了但建连没完成」，而这正是
// net.Dialer.Timeout 覆盖不到的那一段。
func listenAndHang(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	var mutex sync.Mutex
	var connections []net.Conn
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			mutex.Lock()
			connections = append(connections, connection)
			mutex.Unlock()
		}
	}()
	t.Cleanup(func() {
		mutex.Lock()
		defer mutex.Unlock()
		for _, connection := range connections {
			_ = connection.Close()
		}
	})
	return listener.Addr().String()
}
