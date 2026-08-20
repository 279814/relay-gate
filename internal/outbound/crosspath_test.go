// Package outbound_test 里的这个文件是 P0-03 的验收门禁。
//
// 它存在的唯一理由：**同一张表**同时驱动真实转发、探活与 count_tokens 三条
// 出站路径，断言它们打出去的 URL 完全一致。
//
// 为什么必须是同一张表，而不是三个包各测各的：P0-03 要消灭的缺陷正是
// 「三条路径各拼一套 URL」。分开测的话，每条路径都能对着自己的期望值通过，
// 而它们彼此不一致 —— 那恰恰是重构前的状态。只有让三者共用一组期望值，
// 「探活通过但真实请求 404」这类分叉才会在 CI 里显形而不是在生产里。
//
// 放在外部测试包（outbound_test）是为了同时 import proxy 与 probe 而不成环。
package outbound_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/probe"
	"github.com/279814/relay-gate/internal/proxy"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/store"
)

const (
	crossRelayKey    = "rk-client"
	crossUpstreamKey = "sk-upstream-abc"
)

// ── 表 ──────────────────────────────────────────────────────

// crossPathCase 描述一份 Endpoint 配置，以及三条路径各自应该打出的
// path 与 **原始** query 字符串。
//
// query 用原字符串断言，不比较解析后的 url.Values（验收硬要求）：
// url.Values 是 map，比较它会静默放过顺序、重复键与 `+` 的差异 ——
// 而那三样恰好都是上游行为的差异来源。
type crossPathCase struct {
	name string
	// basePath 追加在测试服务器地址之后，模拟带公共路径前缀的网关。
	basePath string
	// l1Path 为空表示只探连接层（HEAD base_url）。
	l1Path     string
	fixedQuery string
	// incomingQuery 是客户端带来的 query（探活没有客户端，故不参与探活断言）。
	incomingQuery string

	wantPath       string // 三条模型路径共用的 messages path
	wantCountPath  string
	wantModelsPath string
	// wantRealQuery 是真实转发与 count_tokens 应发出的 query（固定 + 入站）。
	wantRealQuery string
	// wantProbeQuery 是探活应发出的 query（只有固定部分）。
	wantProbeQuery string
}

func crossPathCases() []crossPathCase {
	return []crossPathCase{
		{
			name:           "canonical",
			l1Path:         "/v1/models",
			incomingQuery:  "beta=true",
			wantPath:       "/v1/messages",
			wantCountPath:  "/v1/messages/count_tokens",
			wantModelsPath: "/v1/models",
			wantRealQuery:  "beta=true",
		},
		{
			// 这条钉住「不能用 ResolveReference」：吞掉前缀会让三条路径
			// 全部打到根下的 /v1/*，表现为 404 而配置看起来完全正确。
			name:           "base 带公共路径前缀",
			basePath:       "/api",
			l1Path:         "/v1/models",
			incomingQuery:  "beta=true",
			wantPath:       "/api/v1/messages",
			wantCountPath:  "/api/v1/messages/count_tokens",
			wantModelsPath: "/api/v1/models",
			wantRealQuery:  "beta=true",
		},
		{
			name:           "base 带尾斜杠",
			basePath:       "/",
			l1Path:         "/v1/models",
			incomingQuery:  "beta=true",
			wantPath:       "/v1/messages",
			wantCountPath:  "/v1/messages/count_tokens",
			wantModelsPath: "/v1/models",
			wantRealQuery:  "beta=true",
		},
		{
			// key 放在 query 里的站（§3.2）。三条路径都必须带上它，
			// 漏掉任何一条的症状都是「配了 key 却一直 401」。
			name:           "固定 query 带 key",
			l1Path:         "/v1/models",
			fixedQuery:     "key={{UPSTREAM_API_KEY}}",
			incomingQuery:  "beta=true",
			wantPath:       "/v1/messages",
			wantCountPath:  "/v1/messages/count_tokens",
			wantModelsPath: "/v1/models",
			// 固定在前、入站在后，只插一个 &（§7.1）
			wantRealQuery:  "key=" + crossUpstreamKey + "&beta=true",
			wantProbeQuery: "key=" + crossUpstreamKey,
		},
		{
			name:           "固定 query 多参数保序",
			l1Path:         "/v1/models",
			fixedQuery:     "z=1&a=2",
			incomingQuery:  "m=3&z=9",
			wantPath:       "/v1/messages",
			wantCountPath:  "/v1/messages/count_tokens",
			wantModelsPath: "/v1/models",
			// 不排序、不去重：同名 z 两份都保留，顺序原样
			wantRealQuery:  "z=1&a=2&m=3&z=9",
			wantProbeQuery: "z=1&a=2",
		},
		{
			name:           "自定义 l1_path 只影响 models",
			l1Path:         "/status",
			incomingQuery:  "beta=true",
			wantPath:       "/v1/messages",
			wantCountPath:  "/v1/messages/count_tokens",
			wantModelsPath: "/status",
			wantRealQuery:  "beta=true",
		},
	}
}

// ── 门禁本体 ─────────────────────────────────────────────────

func TestAllOutboundPathsAgreeOnURL(t *testing.T) {
	for _, testCase := range crossPathCases() {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newCrossPathFixture(t, testCase)

			// 每条路径各自发一次请求，然后拿**同一组**期望值断言。
			t.Run("real_forward", func(t *testing.T) {
				got := fixture.driveRealForward(t)
				assertTarget(t, got, testCase.wantPath, testCase.wantRealQuery)
			})
			t.Run("count_tokens", func(t *testing.T) {
				got := fixture.driveCountTokens(t)
				assertTarget(t, got, testCase.wantCountPath, testCase.wantRealQuery)
			})
			t.Run("probe_l2", func(t *testing.T) {
				got := fixture.driveProbeL2(t)
				assertTarget(t, got, testCase.wantPath, testCase.wantProbeQuery)
			})
			t.Run("probe_l1", func(t *testing.T) {
				got := fixture.driveProbeL1(t)
				assertTarget(t, got, testCase.wantModelsPath, testCase.wantProbeQuery)
			})
		})
	}
}

// 真实转发与探活打的必须是**同一个** messages 地址，并带**同一种**认证。
//
// 这条断言与上面的表是互补的：表保证每条路径符合期望，这里直接比较两条
// 路径的实际产出 —— 即使有人同时改错了期望值与实现，两者不一致仍会被抓住。
func TestRealForwardAndProbeHitIdenticalURL(t *testing.T) {
	for _, testCase := range crossPathCases() {
		t.Run(testCase.name, func(t *testing.T) {
			// 探活不带客户端 query，所以只在无入站 query 时可直接对比全等。
			bare := testCase
			bare.incomingQuery = ""
			fixture := newCrossPathFixture(t, bare)

			real := fixture.driveRealForward(t)
			probeTarget := fixture.driveProbeL2(t)

			if real.path != probeTarget.path {
				t.Errorf("真实转发与探活的 path 不一致：real=%q probe=%q",
					real.path, probeTarget.path)
			}
			if real.query != probeTarget.query {
				t.Errorf("真实转发与探活的 query 不一致：real=%q probe=%q",
					real.query, probeTarget.query)
			}
			// 认证是 P0-04 引入的第二个不分叉维度（§7.2）。原先转发与探活
			// 各有一份 injectAuth —— 那种「探活用一种认证、真实请求用另一种」
			// 的故障表现为「探活说站活着，但用户一直 401」，极难定位。
			for _, name := range model.AuthHeaders {
				if real.header.Get(name) != probeTarget.header.Get(name) {
					t.Errorf("真实转发与探活的认证头 %s 不一致：real=%q probe=%q",
						name, real.header.Get(name), probeTarget.header.Get(name))
				}
			}
		})
	}
}

// 三条路径都只发**一种**认证方式，且带的是上游 key 而非入站 relay key。
//
// 与上一条的分工：上一条比较「两条路径是否一致」，这条钉住「一致的那个值
// 本身是对的」—— 两者同时错成一样时，只有这条能抓住。
func TestAllOutboundPathsSendExactlyOneAuthHeader(t *testing.T) {
	fixture := newCrossPathFixture(t, crossPathCases()[0])

	paths := map[string]func(*testing.T) recordedRequest{
		"real_forward": fixture.driveRealForward,
		"count_tokens": fixture.driveCountTokens,
		"probe_l2":     fixture.driveProbeL2,
		"probe_l1":     fixture.driveProbeL1,
	}
	for name, drive := range paths {
		t.Run(name, func(t *testing.T) {
			got := drive(t)
			if !got.seen {
				t.Fatal("上游没有收到请求")
			}

			var present []string
			for _, header := range model.AuthHeaders {
				if got.header.Get(header) != "" {
					present = append(present, header)
				}
			}
			// crossEndpoints 配的是 x_api_key，所以恰好一个头。
			if len(present) != 1 || present[0] != "X-Api-Key" {
				t.Errorf("应恰好发一个 X-Api-Key，实际带了 %v", present)
			}
			if got := got.header.Get("X-Api-Key"); got != crossUpstreamKey {
				t.Errorf("应发上游 key，得到 %q", got)
			}
			// relay key 一个字节都不能漏给上游。
			for header, values := range got.header {
				for _, value := range values {
					if strings.Contains(value, crossRelayKey) {
						t.Errorf("relay key 泄露到出站头 %s: %q", header, value)
					}
				}
			}
		})
	}
}

func assertTarget(t *testing.T, got recordedRequest, wantPath, wantQuery string) {
	t.Helper()
	if !got.seen {
		t.Fatalf("上游没有收到请求（URL 解析很可能失败了）")
	}
	if got.path != wantPath {
		t.Errorf("path want %q got %q", wantPath, got.path)
	}
	// 原字符串比较，不解析
	if got.query != wantQuery {
		t.Errorf("query want %q got %q", wantQuery, got.query)
	}
}

// ── fixture ─────────────────────────────────────────────────

type recordedRequest struct {
	seen   bool
	method string
	path   string
	query  string
	// header 是上游实际收到的请求头，用于断言三条路径的认证也不分叉。
	header http.Header
}

type crossPathFixture struct {
	testCase   crossPathCase
	server     *httptest.Server
	upstream   *model.Upstream
	snapshot   *router.Snapshot
	settings   model.Settings
	targets    *outbound.Provider
	transports *outbound.Manager

	mu   sync.Mutex
	last recordedRequest
}

func newCrossPathFixture(t *testing.T, testCase crossPathCase) *crossPathFixture {
	t.Helper()
	fixture := &crossPathFixture{testCase: testCase}

	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		fixture.mu.Lock()
		fixture.last = recordedRequest{seen: true, method: r.Method,
			path: r.URL.Path, query: r.URL.RawQuery, header: r.Header.Clone()}
		fixture.mu.Unlock()

		// 回一个能让三条路径都判成功的响应：
		// count_tokens 要 input_tokens（否则会降级本地粗算），
		// 探活 L2 要一个语义事件（否则判假活）。
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w,
			"event: content_block_delta\ndata: {\"input_tokens\":7,\"delta\":{\"text\":\"2\"}}\n\n")
	}))
	t.Cleanup(fixture.server.Close)

	fixture.upstream = &model.Upstream{
		ID: 10, Name: "mock", BaseURL: fixture.server.URL + testCase.basePath,
		APIKey: crossUpstreamKey, AuthStyle: model.AuthXAPIKey,
		L1Path: testCase.l1Path, Enabled: true, CredentialRevision: 1,
	}
	modelName := &model.ModelName{ID: 1, Name: "claude-opus-5",
		Protocol: model.ProtoAnthropic, MatchMode: model.MatchExact, Enabled: true}
	modelName.Defaults()
	route := &model.Route{ID: 100, ModelNameID: 1, UpstreamID: 10,
		Priority: 1, Weight: 100, Enabled: true}

	fixture.snapshot = router.BuildSnapshot([]*model.ModelName{modelName},
		[]*model.Upstream{fixture.upstream}, []*model.Route{route})

	fixture.settings = model.DefaultSettings()
	fixture.settings.RealConnectSec = 2
	fixture.settings.RealFirstTokenSec = 2
	fixture.settings.RealIdleSec = 2
	fixture.settings.RealTotalSec = 5
	fixture.settings.CountTokensSec = 5
	fixture.settings.L1TotalSec = 5
	fixture.settings.L2TotalSec = 5
	fixture.settings.L2FirstTokenSec = 3
	fixture.settings.SampleEnabled = false
	fixture.settings.HalfOpenEnabled = false

	// 与 main.go 同构的装配：一个 Provider + 一个 Resolver + 一个 Manager，
	// 三条路径共用。Manager 共用是必须的 —— 探活与真实请求各建一套连接池
	// 就丢掉了「探活顺带把连接热着」这份收益，而那是首字节延迟的可观部分。
	fixture.targets = outbound.NewProvider(
		crossEndpoints{upstream: fixture.upstream, fixedQuery: testCase.fixedQuery},
		nil, outbound.NewResolver(crossHasher{}))
	fixture.transports = outbound.NewManager()
	t.Cleanup(fixture.transports.CloseIdleConnections)
	return fixture
}

func (fixture *crossPathFixture) take() recordedRequest {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	got := fixture.last
	fixture.last = recordedRequest{}
	return got
}

func (fixture *crossPathFixture) handler() *proxy.Handler {
	return proxy.NewHandler(fixture, alwaysAliveHealth{}, nil,
		[]string{crossRelayKey}, discardLogger()).
		WithTargets(fixture.targets, nil).
		WithTransports(fixture.transports)
}

func (fixture *crossPathFixture) driveRealForward(t *testing.T) recordedRequest {
	t.Helper()
	return fixture.serveHTTP(t, "/v1/messages")
}

func (fixture *crossPathFixture) driveCountTokens(t *testing.T) recordedRequest {
	t.Helper()
	return fixture.serveHTTP(t, "/v1/messages/count_tokens")
}

func (fixture *crossPathFixture) serveHTTP(t *testing.T, path string) recordedRequest {
	t.Helper()
	handler := fixture.handler()

	target := path
	if fixture.testCase.incomingQuery != "" {
		target += "?" + fixture.testCase.incomingQuery
	}
	request := httptest.NewRequest(http.MethodPost, target,
		strings.NewReader(`{"model":"claude-opus-5","max_tokens":1}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Api-Key", crossRelayKey)

	mux := http.NewServeMux()
	handler.Routes(mux)
	mux.ServeHTTP(httptest.NewRecorder(), request)
	return fixture.take()
}

// prober 造一个与真实转发共用同一份 Manager 的 Prober。
//
// 用 Manager 而不是 http.DefaultTransport：探活与真实请求必须共用连接池，
// 而这条门禁的职责就是「三条路径不分叉」—— 连接池是其中一个维度。
func (fixture *crossPathFixture) prober(t *testing.T) *probe.Prober {
	t.Helper()
	transport, err := fixture.transports.Transport(
		outbound.NetworkFor(fixture.upstream.ProbeConfig(),
			outbound.L2Budget(fixture.settings).Connect))
	if err != nil {
		t.Fatalf("取探活连接池: %v", err)
	}
	return &probe.Prober{Transport: transport, Targets: fixture.targets}
}

func (fixture *crossPathFixture) driveProbeL2(t *testing.T) recordedRequest {
	t.Helper()
	modelName := fixture.snapshot.ModelNames[0]
	route := fixture.snapshot.RoutesByModelName[modelName.ID][0]
	fixture.prober(t).L2(context.Background(), fixture.upstream, modelName, route, fixture.settings)
	return fixture.take()
}

func (fixture *crossPathFixture) driveProbeL1(t *testing.T) recordedRequest {
	t.Helper()
	fixture.prober(t).L1(context.Background(), fixture.upstream, fixture.settings)
	return fixture.take()
}

// proxy.ConfigSource / probe.ConfigSource
func (fixture *crossPathFixture) Snapshot() (*router.Snapshot, error) { return fixture.snapshot, nil }
func (fixture *crossPathFixture) Settings() (model.Settings, error)   { return fixture.settings, nil }
func (fixture *crossPathFixture) RunState() (store.RunState, error)   { return store.StateRunning, nil }

// crossEndpoints 与 Store 的 canonicalEndpointBundle 同构：override 由
// model.EndpointURLOverride 翻译，保证测试与生产读到的是同一套 Endpoint。
type crossEndpoints struct {
	upstream   *model.Upstream
	fixedQuery string
}

func (source crossEndpoints) Endpoint(_ context.Context, upstreamID int64,
	kind model.EndpointKind) (*model.UpstreamEndpoint, error) {

	return &model.UpstreamEndpoint{
		ID: 1, UpstreamID: upstreamID, Kind: kind,
		URLMode:            model.EndpointURLCanonical,
		URLOverride:        source.upstream.EndpointURLOverride(kind),
		FixedQueryTemplate: source.fixedQuery,
		AuthProfile: model.EndpointAuthProfile{
			Mode: model.AuthModeXAPIKey, SecretRef: "upstream_api_key", Revision: 1,
		},
		Revision: 1,
	}, nil
}

type crossHasher struct{}

func (crossHasher) SumRequestURL(raw []byte) string { return fmt.Sprintf("x:%x", len(raw)) }

// alwaysAliveHealth 让选路总能拿到候选，不限并发。
type alwaysAliveHealth struct{}

func (alwaysAliveHealth) State(int64) model.HealthState { return model.StateAlive }
func (alwaysAliveHealth) CoolingDown(int64) bool        { return false }
func (alwaysAliveHealth) TryAcquire(int64, int) (func(), bool) {
	return func() {}, true
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
