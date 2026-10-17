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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/observationseq"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/probe"
	"github.com/279814/relay-gate/internal/proxy"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/runstate"
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
	// basePath is materialized into Endpoint overrides for a shared gateway prefix.
	basePath string
	// modelsAtOrigin places models at the origin while model Endpoints keep the prefix.
	modelsAtOrigin bool
	// modelsPath is materialized as the explicit models Endpoint URL override.
	modelsPath string
	fixedQuery string
	// incomingQuery 是客户端带来的 query（探活没有客户端，故不参与探活断言）。
	incomingQuery string

	wantPath       string // 三条模型路径共用的 messages path
	wantCountPath  string
	wantModelsPath string
	// wantRealQuery 是真实转发与 count_tokens 应发出的 query（固定 + 入站）。
	wantRealQuery string
	// wantProbeL2Query 是 L2 应发出的 query：Endpoint 固定 query + **Recipe 的
	// 固定 query**。后者来自内置 messages 模板的 `?beta=true` —— §3.1 抓包实测
	// 真实 Claude Code 打的就是 /v1/messages?beta=true，而 §3.3 把「旧 L2 丢失
	// 真实请求中的 RawQuery」列为必须废弃的结论。
	wantProbeL2Query string
	// wantProbeModelsQuery 是 L1 应发出的 query。内置 models 模板没有固定
	// query（GET /v1/models 本来就不带），所以只有 Endpoint 那部分。
	wantProbeModelsQuery string
}

// probeRecipeQuery 是内置 messages 模板声明的固定 query。
//
// 写成常量而不是从 manifest 读：这是一份**验收**期望值，从被测对象里取值
// 会让「manifest 改错了」与「期望值跟着改错了」同时发生而测试仍绿。
const probeRecipeQuery = "beta=true"

func crossPathCases() []crossPathCase {
	return []crossPathCase{
		{
			name:             "canonical",
			modelsPath:       "/v1/models",
			incomingQuery:    "beta=true",
			wantPath:         "/v1/messages",
			wantCountPath:    "/v1/messages/count_tokens",
			wantModelsPath:   "/v1/models",
			wantRealQuery:    "beta=true",
			wantProbeL2Query: probeRecipeQuery,
		},
		{
			// 这条钉住「不能用 ResolveReference」：吞掉前缀会让三条路径
			// 全部打到根下的 /v1/*，表现为 404 而配置看起来完全正确。
			name:             "base 带公共路径前缀",
			basePath:         "/api",
			modelsPath:       "/v1/models",
			incomingQuery:    "beta=true",
			wantPath:         "/api/v1/messages",
			wantCountPath:    "/api/v1/messages/count_tokens",
			wantModelsPath:   "/api/v1/models",
			wantRealQuery:    "beta=true",
			wantProbeL2Query: probeRecipeQuery,
		},
		{
			name:             "base 带尾斜杠",
			basePath:         "/",
			modelsPath:       "/v1/models",
			incomingQuery:    "beta=true",
			wantPath:         "/v1/messages",
			wantCountPath:    "/v1/messages/count_tokens",
			wantModelsPath:   "/v1/models",
			wantRealQuery:    "beta=true",
			wantProbeL2Query: probeRecipeQuery,
		},
		{
			// key 放在 query 里的站（§7.1 FixedQueryTemplate）。三条路径都必须带上它，
			// 漏掉任何一条的症状都是「配了 key 却一直 401」。
			name:           "固定 query 带 key",
			modelsPath:     "/v1/models",
			fixedQuery:     "key={{UPSTREAM_API_KEY}}",
			incomingQuery:  "beta=true",
			wantPath:       "/v1/messages",
			wantCountPath:  "/v1/messages/count_tokens",
			wantModelsPath: "/v1/models",
			// 固定在前、入站在后，只插一个 &（§7.1）
			wantRealQuery: "key=" + crossUpstreamKey + "&beta=true",
			// 探活侧「入站」那一格由 Recipe 的固定 query 占据，拼接规则同上。
			wantProbeL2Query:     "key=" + crossUpstreamKey + "&" + probeRecipeQuery,
			wantProbeModelsQuery: "key=" + crossUpstreamKey,
		},
		{
			name:           "固定 query 多参数保序",
			modelsPath:     "/v1/models",
			fixedQuery:     "z=1&a=2",
			incomingQuery:  "m=3&z=9",
			wantPath:       "/v1/messages",
			wantCountPath:  "/v1/messages/count_tokens",
			wantModelsPath: "/v1/models",
			// 不排序、不去重：同名 z 两份都保留，顺序原样
			wantRealQuery:        "z=1&a=2&m=3&z=9",
			wantProbeL2Query:     "z=1&a=2&" + probeRecipeQuery,
			wantProbeModelsQuery: "z=1&a=2",
		},
		{
			name:             "自定义 models Endpoint 只影响 models",
			modelsPath:       "/status",
			incomingQuery:    "beta=true",
			wantPath:         "/v1/messages",
			wantCountPath:    "/v1/messages/count_tokens",
			wantModelsPath:   "/status",
			wantRealQuery:    "beta=true",
			wantProbeL2Query: probeRecipeQuery,
		},
		{
			// One upstream can publish distinct absolute Endpoint overrides:
			// model requests retain the shared prefix, models targets the origin.
			name:             "models 显式 origin override 不叠 base 前缀",
			basePath:         "/custom/entry",
			modelsAtOrigin:   true,
			modelsPath:       "/v1/models",
			incomingQuery:    "beta=true",
			wantPath:         "/custom/entry/v1/messages",
			wantCountPath:    "/custom/entry/v1/messages/count_tokens",
			wantModelsPath:   "/v1/models",
			wantRealQuery:    "beta=true",
			wantProbeL2Query: probeRecipeQuery,
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
				assertTarget(t, got, testCase.wantPath, testCase.wantProbeL2Query)
			})
			t.Run("probe_l1", func(t *testing.T) {
				got := fixture.driveProbeL1(t)
				assertTarget(t, got, testCase.wantModelsPath, testCase.wantProbeModelsQuery)
			})
		})
	}
}

// 真实转发与探活打的必须是**同一个** messages 地址，并带**同一种**认证。
//
// 这条断言与上面的表是互补的：表保证每条路径符合期望，这里直接比较两条
// 路径的实际产出 —— 即使有人同时改错了期望值与实现，两者不一致仍会被抓住。
//
// 对比时给真实转发喂上 Recipe 那份固定 query：探活现在按内置模板发
// `?beta=true`，而那正是 §3.1 抓包里真实 Claude Code 打的路径。也就是说
// 「同一个地址」的含义没变 —— 变的是探活终于也带上了它，而旧 L2 会丢掉
// （§3.3 把这条列为必须废弃的结论）。
func TestRealForwardAndProbeHitIdenticalURL(t *testing.T) {
	for _, testCase := range crossPathCases() {
		t.Run(testCase.name, func(t *testing.T) {
			// 让客户端发的 query 与探活模板的固定 query 相同，两条路径才可比。
			aligned := testCase
			aligned.incomingQuery = probeRecipeQuery
			fixture := newCrossPathFixture(t, aligned)

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
			// Persisted Endpoint profiles explicitly choose x_api_key.
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

func TestAllOutboundPathsUseScenarioBudgetPools(t *testing.T) {
	fixture := newCrossPathFixture(t, crossPathCases()[0])
	for index, scenario := range []struct {
		name    string
		connect time.Duration
		drive   func(*testing.T) recordedRequest
	}{
		{"real", time.Second, fixture.driveRealForward},
		{"count_tokens", 2 * time.Second, fixture.driveCountTokens},
		{"L1", 3 * time.Second, fixture.driveProbeL1},
		{"L2", 4 * time.Second, fixture.driveProbeL2},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			if !scenario.drive(t).seen {
				t.Fatal("path did not send its real HTTP request")
			}
			if got := fixture.transports.PoolCount(); got != index+1 {
				t.Fatalf("scenario did not select its independent budget pool: pools=%d want=%d", got, index+1)
			}
			network := outbound.NetworkFor(fixture.upstream.ProbeConfig(), scenario.connect)
			pool, err := fixture.transports.Transport(network)
			if err != nil {
				t.Fatal(err)
			}
			again, err := fixture.transports.Transport(network)
			if err != nil {
				t.Fatal(err)
			}
			if pool != again || fixture.transports.PoolCount() != index+1 {
				t.Fatal("the HTTP path used another network/budget identity or did not reuse its Manager pool")
			}
		})
	}
}

func TestAllOutboundPathsSharePoolForEqualConnectBudget(t *testing.T) {
	fixture := newCrossPathFixture(t, crossPathCases()[0])
	fixture.settings.RealConnectSec = 2
	fixture.settings.CountTokensConnectSec = 2
	fixture.settings.L1ConnectSec = 2
	fixture.settings.L2ConnectSec = 2
	fixture.saveSettings(t)
	if err := fixture.source.Refresh(); err != nil {
		t.Fatal(err)
	}
	for _, drive := range []func(*testing.T) recordedRequest{fixture.driveRealForward, fixture.driveCountTokens, fixture.driveProbeL1, fixture.driveProbeL2} {
		if !drive(t).seen {
			t.Fatal("path did not perform its HTTP operation")
		}
		if got := fixture.transports.PoolCount(); got != 1 {
			t.Fatalf("same network and connect budget split the shared Manager: pools=%d", got)
		}
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
	store      *store.Store
	runState   *runstate.Controller
	source     *livecfg.Source
	executor   *probe.Executor
	scheduler  *probe.Scheduler

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

		// Each real protocol must complete; arbitrary bytes cannot stand in
		// for models, count_tokens and semantic model evidence simultaneously.
		if strings.HasSuffix(r.URL.Path, "/messages/count_tokens") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"input_tokens":7}`)
		} else if r.Method == http.MethodGet || r.Method == http.MethodHead {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"data":[]}`)
		} else {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"2\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
		}
	}))
	t.Cleanup(fixture.server.Close)

	cipher, err := store.NewCipher("cross-path-fixture-master-key")
	if err != nil {
		t.Fatal(err)
	}
	fixture.store, err = store.Open(filepath.Join(t.TempDir(), "crosspath.db"), cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fixture.store.Close() })
	fixture.runState, err = runstate.NewController(fixture.store)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fixture.runState.Close)
	fixture.upstream = &model.Upstream{Name: "mock", BaseURL: fixture.server.URL, APIKey: crossUpstreamKey, Enabled: true, ProbeMode: model.ProbeModeActive}
	endpoints := make([]*model.UpstreamEndpoint, 0, 5)
	for _, kind := range []model.EndpointKind{model.EndpointModels, model.EndpointMessages, model.EndpointResponses, model.EndpointChatCompletions, model.EndpointCountTokens} {
		endpoint := &model.UpstreamEndpoint{Kind: kind, URLMode: model.EndpointURLCanonical, FixedQueryTemplate: testCase.fixedQuery,
			AuthProfile: model.EndpointAuthProfile{Mode: model.AuthModeXAPIKey, SecretRef: "upstream_api_key", Revision: 1}, Revision: 1}
		if testCase.basePath != "" && testCase.basePath != "/" {
			endpoint.URLOverride = fixture.server.URL + testCase.basePath + kind.CanonicalPath()
		} else if testCase.basePath == "/" {
			fixture.upstream.BaseURL = fixture.server.URL + "/"
		}
		if kind == model.EndpointModels {
			switch {
			case testCase.modelsAtOrigin:
				endpoint.URLOverride = fixture.server.URL + testCase.modelsPath
			case testCase.modelsPath != "/v1/models":
				endpoint.URLOverride = fixture.server.URL + strings.TrimRight(testCase.basePath, "/") + testCase.modelsPath
			}
		}
		endpoints = append(endpoints, endpoint)
	}
	if err := fixture.store.CreateUpstreamWithEndpoints(context.Background(), fixture.upstream, endpoints); err != nil {
		t.Fatal(err)
	}
	modelName := &model.ModelName{Name: "claude-opus-5", Protocol: model.ProtoAnthropic, MatchMode: model.MatchExact, Enabled: true}
	modelName.Defaults()
	if err := fixture.store.CreateModelName(modelName); err != nil {
		t.Fatal(err)
	}
	route := &model.Route{ModelNameID: modelName.ID, UpstreamID: fixture.upstream.ID, Priority: 1, Weight: 100, Enabled: true}
	if err := fixture.store.CreateRoute(route); err != nil {
		t.Fatal(err)
	}

	fixture.settings = model.DefaultSettings()
	// Four distinct valid connect budgets prove the production paths select
	// their own scenario pools within the single shared Manager.
	fixture.settings.RealConnectSec = 1
	fixture.settings.CountTokensConnectSec = 2
	fixture.settings.CountTokensTotalSec = 5
	fixture.settings.L1ConnectSec = 3
	fixture.settings.L1TotalSec = 5
	fixture.settings.L2ConnectSec = 4
	fixture.settings.L2TotalSec = 5
	fixture.settings.L2FirstSemanticSec = 3
	fixture.settings.L2ResponseHeaderSec = 3
	fixture.settings.L2FirstByteSec = 3
	fixture.settings.L2FirstEventSec = 3
	fixture.settings.L2FirstSemanticSec = 3
	fixture.settings.L2IdleSec = 1
	fixture.settings.SampleEnabled = false
	fixture.settings.HalfOpenEnabled = false
	fixture.saveSettings(t)
	fixture.source = livecfg.New(fixture.store, discardLogger())
	if err := fixture.source.Refresh(); err != nil {
		t.Fatal(err)
	}
	fixture.snapshot, err = fixture.source.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	fixture.upstream = fixture.snapshot.Upstreams[fixture.upstream.ID]
	fixture.targets = outbound.NewProvider(fixture.source, nil, outbound.NewResolver(crossHasher{}))
	fixture.transports = outbound.NewManager()
	t.Cleanup(fixture.transports.CloseIdleConnections)
	recipes := probe.NewRecipeResolver(fixture.store).WithNotFound(func(err error) bool { return errors.Is(err, store.ErrNotFound) })
	tracker := health.NewTracker(fixture.source)
	reach := health.NewReachabilityTracker(fixture.source)
	caps := probe.NewCapabilityRegistry(fixture.source).WithRouteGeneration(tracker)
	recorder := probe.NewResultRecorder(fixture.store, health.NewObservationReducer(nil), reach, caps)
	fixture.executor = probe.NewExecutor(fixture.targets, fixture.store, recipes, probe.ManagerTransports{Manager: fixture.transports}, recorder, probe.AlwaysOpenAdmission(), probe.WallClock(), discardLogger())
	seq, err := observationseq.Open(context.Background(), fixture.store)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(seq.Close)
	fixture.scheduler = probe.NewScheduler(fixture.source, tracker, reach, discardLogger()).WithRecipes(recipes).WithExecutor(fixture.executor).WithSequencer(seq)
	return fixture
}

func (fixture *crossPathFixture) saveSettings(t *testing.T) {
	t.Helper()
	_, revision, err := fixture.store.GetSettingsWithRevision()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.SaveSettingsWithRevision(fixture.settings, revision); err != nil {
		t.Fatal(err)
	}
}

func (fixture *crossPathFixture) take() recordedRequest {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	got := fixture.last
	fixture.last = recordedRequest{}
	return got
}

func (fixture *crossPathFixture) handler() *proxy.Handler {
	return proxy.NewHandler(fixture.source, alwaysAliveHealth{}, nil,
		[]string{crossRelayKey}, discardLogger()).
		WithRunState(fixture.runState).WithTargets(fixture.targets, fixture.store).
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
		strings.NewReader(`{"model":"claude-opus-5","max_tokens":1,"messages":[{"role":"user","content":"1+1=?"}],"stream":true}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Api-Key", crossRelayKey)

	mux := http.NewServeMux()
	handler.Routes(mux)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != 200 || response.Header().Get("X-Relay-Count-Tokens") != "" {
		t.Fatalf("path failed or silently used local count estimate: status=%d body=%s", response.Code, response.Body.String())
	}
	return fixture.take()
}

// Preparation uses the same published Store/Source facts and sequencer as the
// production Scheduler, then the Executor alone performs the HTTP operation.
func (fixture *crossPathFixture) driveProbe(t *testing.T, endpoint model.EndpointKind) recordedRequest {
	t.Helper()
	request := probe.ExecutionRequest{ExecutionID: fmt.Sprintf("cross-%s-%d", endpoint, time.Now().UnixNano()), Trigger: model.TriggerManual,
		Upstream: fixture.upstream, Endpoint: endpoint, Mode: probe.ObserveProbe}
	if endpoint != model.EndpointModels {
		request.ModelName = fixture.snapshot.ModelNames[0]
		request.Route = fixture.snapshot.RoutesByModelName[request.ModelName.ID][0]
	}
	if err := fixture.scheduler.PrepareManual(context.Background(), &request); err != nil {
		t.Fatal(err)
	}
	if request.ObservationOrder <= 0 || request.CapabilityExpectation == nil || request.ReachabilityExpectation == nil {
		t.Fatal("probe was not bound to current persisted configuration/order")
	}
	result, err := fixture.executor.Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Execution.Success || !result.Apply.ExecutionStored || result.Apply.Capability != model.ApplyCurrent || result.Apply.Reachability != model.ApplyCurrent {
		t.Fatalf("probe failed or observation was not committed: execution=%+v apply=%+v", result.Execution, result.Apply)
	}
	return fixture.take()
}

func (fixture *crossPathFixture) driveProbeL2(t *testing.T) recordedRequest {
	t.Helper()
	return fixture.driveProbe(t, model.EndpointMessages)
}
func (fixture *crossPathFixture) driveProbeL1(t *testing.T) recordedRequest {
	t.Helper()
	return fixture.driveProbe(t, model.EndpointModels)
}

type crossHasher struct{}

func (crossHasher) SumRequestURL(raw []byte) string { return fmt.Sprintf("x:%x", len(raw)) }

// alwaysAliveHealth 让选路总能拿到候选，不限并发。
type alwaysAliveHealth struct{}

func (alwaysAliveHealth) State(int64) model.HealthState { return model.StateAlive }
func (alwaysAliveHealth) CoolingDown(int64) bool        { return false }
func (alwaysAliveHealth) TryAcquire(int64, int) (func(), uint64, bool) {
	return func() {}, 1, true
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
