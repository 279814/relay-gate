package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

// recordingReporter 数健康回写的次数。
//
// count_tokens 的关键不变量是「一次都不该调」（§3.1），所以这个替身
// 只需要计数，不需要记内容。加锁是因为生产实现的契约允许它被
// 异步调用，测试替身不该比契约更宽松。
type recordingReporter struct {
	mu       sync.Mutex
	reported int
	probed   int
}

func (r *recordingReporter) ReportResult(int64, *ResultView) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reported++
}

func (r *recordingReporter) TriggerProbe(int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.probed++
}

func (r *recordingReporter) reports() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reported
}

func (r *recordingReporter) probes() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.probed
}

// countTokensRequest 构造一个打到 count_tokens 的入站请求。
func (hs *harness) countTokensRequest(body string) *http.Request {
	r := httptest.NewRequest("POST", "/v1/messages/count_tokens", strings.NewReader(body))
	r.Header = claudeCodeHeaders()
	r.Header.Set("X-Api-Key", hs.relayPW)
	return r
}

// decodeInputTokens 取出响应里的 input_tokens，顺带断言响应是合法 JSON。
//
// 合法性本身就是一条断言：降级路径若在已写出响应之后又追加一份兜底结果，
// 客户端拿到的是两个拼在一起的 JSON 对象 —— 那种 body 用 Decoder 读第一个
// 对象仍会成功，所以这里显式检查「后面没有多余内容」。
func decodeInputTokens(t *testing.T, body string) int {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(body))
	var resp struct {
		InputTokens *int `json:"input_tokens"`
	}
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("解析响应失败: %v（原文 %q）", err, body)
	}
	if dec.More() {
		t.Fatalf("响应里有多个 JSON 对象，说明降级路径重复写出了响应: %q", body)
	}
	if resp.InputTokens == nil {
		t.Fatalf("响应缺少 input_tokens 字段: %q", body)
	}
	return *resp.InputTokens
}

// ── 转发路径 ──────────────────────────────────────────────

// 上游支持 count_tokens 时，必须用上游的真实值，不能用本地估算 ——
// 本地估算有 ±20% 误差，能拿到准确值时用估算值是白白降级。
func TestCountTokens_ProxiesToUpstreamWhenSupported(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"input_tokens":12345}`))
	})

	rec := hs.serve(hs.countTokensRequest(
		`{"model":"claude-opus-5","messages":[{"role":"user","content":"hi"}]}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, want 200", rec.Code)
	}
	if got := decodeInputTokens(t, rec.Body.String()); got != 12345 {
		t.Errorf("input_tokens = %d, want 12345（应为上游的真实值而非本地估算）", got)
	}
	// 走了上游就不该打估算标记，否则排查时会误以为这次是兜底。
	if v := rec.Header().Get("X-Relay-Count-Tokens"); v != "" {
		t.Errorf("X-Relay-Count-Tokens = %q, 转发成功时不该打估算标记", v)
	}

	// 出站路径必须是 count_tokens 而不是 /v1/messages：它是 Anthropic
	// 协议下的附加端点，路径 1:1 对应（§3.1），不能被 Protocol.Path() 覆盖。
	if got := hs.gotReq.path; got != "/v1/messages/count_tokens" {
		t.Errorf("上游收到的路径 = %q, want /v1/messages/count_tokens", got)
	}
}

// 出站鉴权必须换成上游 key。漏了这一步就是把 relay key 发给公益站，
// 结果是一个难以归因的 401。
func TestCountTokens_ReplacesInboundCredentials(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"input_tokens":7}`))
	})
	hs.serve(hs.countTokensRequest(`{"model":"claude-opus-5","messages":[]}`))

	if got := hs.gotReq.headers.Get("X-Api-Key"); got != "sk-upstream-secret" {
		t.Errorf("出站 X-Api-Key = %q, want sk-upstream-secret", got)
	}
	if strings.Contains(hs.gotReq.headers.Get("X-Api-Key"), hs.relayPW) {
		t.Error("出站请求带上了入站的 relay key")
	}
}

// 配了 upstream_model 时 body 里的 model 要跟着改，否则上游按一个
// 它不认识的模型名去算 token，回 400。
func TestCountTokens_AppliesModelMapping(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"input_tokens":3}`))
	})
	hs.cfg.snap.RoutesByModelName[1][0].UpstreamModel = "claude-3-opus-20240229"

	hs.serve(hs.countTokensRequest(`{"model":"claude-opus-5","messages":[]}`))

	if !strings.Contains(string(hs.gotReq.body), `"claude-3-opus-20240229"`) {
		t.Errorf("出站 body 未应用映射: %s", hs.gotReq.body)
	}
}

// ── 降级路径 ──────────────────────────────────────────────

// M0 实测 4 个可用站里有 2 个对这个端点回 404。这是**最常见**的情况，
// 必须降级到本地粗算而不是把 404 透给客户端 —— 后者会让 Claude Code 起不来。
func TestCountTokens_FallsBackWhenUpstreamUnsupported(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusBadRequest,
		http.StatusUnauthorized, http.StatusInternalServerError} {

		t.Run(fmt.Sprintf("上游%d", status), func(t *testing.T) {
			hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				w.Write([]byte(`{"error":{"message":"not supported"}}`))
			})

			rec := hs.serve(hs.countTokensRequest(
				`{"model":"claude-opus-5","messages":[{"role":"user","content":"hello world"}]}`))

			if rec.Code != http.StatusOK {
				t.Fatalf("状态码 = %d, want 200（上游不支持时应本地兜底）", rec.Code)
			}
			if got := decodeInputTokens(t, rec.Body.String()); got <= 0 {
				t.Errorf("input_tokens = %d, want > 0", got)
			}
			if v := rec.Header().Get("X-Relay-Count-Tokens"); v != "estimated" {
				t.Errorf("X-Relay-Count-Tokens = %q, want estimated", v)
			}
		})
	}
}

// 上游连不上时同样要兜底。这条与上一条的区别是失败发生在 RoundTrip 而不是
// 状态码，两条路径是分开的 return。
func TestCountTokens_FallsBackWhenUpstreamUnreachable(t *testing.T) {
	hs := newHarness(t, nil)
	hs.up.Close() // 关掉上游，制造连接失败

	rec := hs.serve(hs.countTokensRequest(
		`{"model":"claude-opus-5","messages":[{"role":"user","content":"hi"}]}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, want 200（上游连不上时应本地兜底）", rec.Code)
	}
	if decodeInputTokens(t, rec.Body.String()) <= 0 {
		t.Error("兜底应给出正数 token")
	}
}

// 模型没配时也要兜底，不能回 404。
// Claude Code 拿不到 token 数就起不来，而它问的那个模型可能只是还没配。
func TestCountTokens_FallsBackWhenModelNotConfigured(t *testing.T) {
	hs := newHarness(t, nil)

	rec := hs.serve(hs.countTokensRequest(
		`{"model":"unconfigured-model","messages":[{"role":"user","content":"hi"}]}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, want 200（模型没配时应本地兜底）", rec.Code)
	}
	if decodeInputTokens(t, rec.Body.String()) <= 0 {
		t.Error("兜底应给出正数 token")
	}
}

// 全部 Route 都 dead 时也要兜底。这个端点太轻量，没有必要为它半开放行。
func TestCountTokens_FallsBackWhenAllRoutesDead(t *testing.T) {
	hs := newHarness(t, nil)
	hs.health.dead[100] = true

	rec := hs.serve(hs.countTokensRequest(
		`{"model":"claude-opus-5","messages":[{"role":"user","content":"hi"}]}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, want 200", rec.Code)
	}
	if decodeInputTokens(t, rec.Body.String()) <= 0 {
		t.Error("兜底应给出正数 token")
	}
}

// 上游把 key 回显在错误消息里时，日志里**不能**出现明文 key。
//
// `{"error":"Invalid API key: sk-xxx"}` 是公益站 401 的常见格式，而 401 正是
// 降级路径最容易触发的分支。不脱敏的话日志就成了明文 key 的副本 ——
// §3.6.3b 对样本库的要求是无条件的，日志没有理由比它宽松。
//
// 这条测试要真去读日志输出，不能只看响应：问题恰恰在于它对响应毫无影响。
func TestCountTokens_UpstreamErrorBodyRedactedInLog(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		// 上游把它收到的 key 原样回显 —— 这里是出站的上游 key
		w.Write([]byte(`{"error":{"message":"Invalid API key: sk-upstream-secret"}}`))
	})

	var logs bytes.Buffer
	hs.h.log = slog.New(slog.NewTextHandler(&logs, nil))

	rec := hs.serve(hs.countTokensRequest(
		`{"model":"claude-opus-5","messages":[{"role":"user","content":"hi"}]}`))

	// 仍应正常兜底，脱敏不改变行为
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, want 200", rec.Code)
	}

	if strings.Contains(logs.String(), "sk-upstream-secret") {
		t.Errorf("日志里出现了明文上游 key:\n%s", logs.String())
	}
	// 确认脱敏没有把整段原文吞掉 —— 降级原因仍要可诊断，
	// 否则「为什么走了兜底」就无从查起。
	if !strings.Contains(logs.String(), "401") {
		t.Errorf("日志里应保留上游状态码以便诊断:\n%s", logs.String())
	}
}

// 入站 relay key 同样不能进日志。上游可能回显的是它收到的任意凭据，
// 而 auth_style=auto 时我们两个头都发，回显哪一个都有可能。
func TestCountTokens_InboundKeyRedactedInLog(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"unexpected credential rk-client-key"}`)
	})

	var logs bytes.Buffer
	hs.h.log = slog.New(slog.NewTextHandler(&logs, nil))

	hs.serve(hs.countTokensRequest(`{"model":"claude-opus-5","messages":[]}`))

	if strings.Contains(logs.String(), hs.relayPW) {
		t.Errorf("日志里出现了明文 relay key:\n%s", logs.String())
	}
}

// 短 key 同样不能漏进日志。
//
// sample.RedactBodyKeys 有 12 字符的下限（短于此不脱敏），那对样本是对的 ——
// 样本存的是完整对话原文，短 key 会偶然命中无数次，把原文打得千疮百孔。
// 但日志这条路径进来的只是 200 字符的错误原文，多打几个码无所谓，
// 漏一个 key 才是实实在在的泄露。
//
// 而这是**真实可达**的配置：RELAY_KEYS 只校验非空、没有长度下限
// （config.validate），上游 api_key 同样没有。
func TestCountTokens_ShortKeyRedactedInLog(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"bad credential sk-short99"}`))
	})
	for _, up := range hs.cfg.snap.Upstreams {
		up.APIKey = "sk-short99" // 10 字符，短于 sample 包的 12 字符下限
	}

	var logs bytes.Buffer
	hs.h.log = slog.New(slog.NewTextHandler(&logs, nil))

	hs.serve(hs.countTokensRequest(`{"model":"claude-opus-5","messages":[]}`))

	if strings.Contains(logs.String(), "sk-short99") {
		t.Errorf("短 key 未被脱敏:\n%s", logs.String())
	}
}

// 上游未配 key 时日志原文要完好。
//
// 这条只钉住「不崩、不把原文吞掉」这个下限。原本我想测的是
// 「ReplaceAll 用空串会在每个字节间插掩码」，但实测那不会发生 ——
// MaskKey("") 返回空串，于是替换等于原地不动。所以代码里那个 k == ""
// 的跳过是**防御性**的（防 MaskKey 日后改成返回固定掩码），
// 而不是在修一个当前存在的 bug。这里如实写明，免得下一个人
// 以为这条测试守着什么它其实守不住的东西。
func TestCountTokens_EmptyKeyKeepsLogReadable(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"upstream exploded"}`))
	})
	for _, up := range hs.cfg.snap.Upstreams {
		up.APIKey = ""
	}

	var logs bytes.Buffer
	hs.h.log = slog.New(slog.NewTextHandler(&logs, nil))

	hs.serve(hs.countTokensRequest(`{"model":"claude-opus-5","messages":[]}`))

	if !strings.Contains(logs.String(), "upstream exploded") {
		t.Errorf("空 key 把日志原文破坏了:\n%s", logs.String())
	}
}

// 真实请求的 ErrBody 必须在交给健康判定前脱敏。
//
// 这与 count_tokens 的日志脱敏是**不同的路径**，泄露面也更大：ErrBody 经
// probe.ClassifyHTTP → errFromBody 拼进 Outcome.Err → health.Report →
// 存成 route_health.last_error（**落库**）→ 由 /admin/api/health 显示。
// 不脱敏的话一个明文上游 key 会同时躺在数据库里和管理界面上。
//
// 断言在 ResultView 上而不是走完整个 health 链路：viewOf 是 ErrBody 进入
// 健康判定的唯一入口，在这里拦住就覆盖了全部下游。
func TestServe_ErrBodyRedactedBeforeHealthReport(t *testing.T) {
	const upKey = "sk-upstream-secret" // 与 newHarness 里配的一致

	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		// 上游把收到的 key 回显 —— 401 最常见的形态
		fmt.Fprintf(w, `{"error":{"message":"Invalid API key: %s"}}`, upKey)
	})

	spy := &capturingReporter{}
	hs.h.WithHealthReporter(spy)

	hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5","messages":[]}`))

	got := spy.last()
	if got == nil {
		t.Fatal("401 应上报健康结论")
	}
	if bytes.Contains(got.ErrBody, []byte(upKey)) {
		t.Errorf("ErrBody 里有明文上游 key（会落库并显示在 UI 上）：%s", got.ErrBody)
	}
	// 脱敏不能把诊断内容一起吞掉 —— 健康判定要靠 ErrBody 区分
	// 「鉴权错误」与「普通 5xx」（§4.3），内容没了就只能一律按最保守处理。
	if len(got.ErrBody) == 0 {
		t.Error("ErrBody 被清空了，健康判定将无法区分致命错误与普通故障")
	}
}

// capturingReporter 留下最后一次上报的内容，用于断言脱敏。
type capturingReporter struct {
	mu   sync.Mutex
	seen *ResultView
}

func (c *capturingReporter) ReportResult(_ int64, res *ResultView) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen = res
}

func (c *capturingReporter) TriggerProbe(int64) {}

func (c *capturingReporter) last() *ResultView {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.seen
}

// §3.1 / §10.3：count_tokens 的失败**不得**计入健康状态。
// 这是刻意的 —— 它每轮对话都被调用，噪声会淹没真实请求给出的信号，
// 而一个轻量端点的失败不该把一个能正常对话的站判死。
func TestCountTokens_FailureDoesNotAffectHealth(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	spy := &recordingReporter{}
	hs.h.WithHealthReporter(spy)

	rec := hs.serve(hs.countTokensRequest(`{"model":"claude-opus-5","messages":[]}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, want 200", rec.Code)
	}
	if n := spy.reports(); n != 0 {
		t.Errorf("ReportResult 被调用 %d 次, want 0（count_tokens 失败不计健康）", n)
	}
	if n := spy.probes(); n != 0 {
		t.Errorf("TriggerProbe 被调用 %d 次, want 0", n)
	}
}

// 成功时同样不回写。piggyback 会因此把一次 L2 探活跳掉，
// 而 count_tokens 根本没有验证过模型能不能生成内容 —— 它连模型都没调用。
func TestCountTokens_SuccessDoesNotAffectHealth(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"input_tokens":5}`))
	})
	spy := &recordingReporter{}
	hs.h.WithHealthReporter(spy)

	hs.serve(hs.countTokensRequest(`{"model":"claude-opus-5","messages":[]}`))

	if n := spy.reports(); n != 0 {
		t.Errorf("ReportResult 被调用 %d 次, want 0（成功也不该 piggyback）", n)
	}
}

// 并发额度必须配平。漏一次 Release 那条 Route 的在途计数就只增不减，
// 配了 max_concurrency 之后会被永远排除在选路之外，且不会自愈。
func TestCountTokens_ReleasesConcurrencySlot(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"input_tokens":5}`))
	})
	hs.serve(hs.countTokensRequest(`{"model":"claude-opus-5","messages":[]}`))

	if _, open, _ := hs.health.stats(); open != 0 {
		t.Errorf("在途计数 = %d, want 0（额度未归还）", open)
	}
}

// ── 鉴权与总闸 ────────────────────────────────────────────

// 鉴权不能漏。这个端点与三个透传端点共用同一套 relay key，
// 漏了它等于给一个免鉴权的入口（§5.2f）。
func TestCountTokens_RequiresAuth(t *testing.T) {
	hs := newHarness(t, nil)
	r := httptest.NewRequest("POST", "/v1/messages/count_tokens",
		strings.NewReader(`{"model":"claude-opus-5","messages":[]}`))
	// 不带任何凭据

	rec := hs.serve(r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("状态码 = %d, want 401", rec.Code)
	}
}

// 暂停时拒绝新请求（§4.8）。不能因为「有本地兜底」就放行 ——
// 暂停的语义是「不用时不浪费额度」，而放行会继续打到上游。
func TestCountTokens_RejectedWhenPaused(t *testing.T) {
	hs := newHarness(t, nil)
	hs.cfg.state = store.StatePaused

	rec := hs.serve(hs.countTokensRequest(`{"model":"claude-opus-5","messages":[]}`))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("状态码 = %d, want 503", rec.Code)
	}
	if got := rec.Header().Get("X-Relay-State"); got != "paused" {
		t.Errorf("X-Relay-State = %q, want paused", got)
	}
}

// ── 本地估算 ──────────────────────────────────────────────

// 回归测试：system 与 content 都可以是 content block 数组，而不只是字符串。
//
// Claude Code 发的正是数组形态（带 cache_control）。把它们声明成 string
// 会让 json.Unmarshal 报类型错误，于是一个**完全合法**的请求拿到 400 ——
// 这是本文件第一版的真实 bug。
func TestEstimateInputTokens_AcceptsBlockArrayShapes(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"system 是字符串", `{"model":"m","system":"你是一个助手","messages":[]}`},
		{"system 是数组", `{"model":"m","system":[{"type":"text","text":"你是一个助手",
			"cache_control":{"type":"ephemeral"}}],"messages":[]}`},
		{"content 是字符串", `{"model":"m","messages":[{"role":"user","content":"hello"}]}`},
		{"content 是数组", `{"model":"m","messages":[{"role":"user",
			"content":[{"type":"text","text":"hello"}]}]}`},
		{"含 tool_use 的 input", `{"model":"m","messages":[{"role":"assistant",
			"content":[{"type":"tool_use","id":"t1","name":"bash",
			"input":{"command":"ls -la /tmp"}}]}]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := estimateInputTokens([]byte(c.body))
			if err != nil {
				t.Fatalf("估算失败: %v", err)
			}
			if got <= 0 {
				t.Errorf("token = %d, want > 0", got)
			}
		})
	}
}

// 工具定义必须算进去。Claude Code 每轮都带完整的 tools schema，
// 它常常比对话本身长得多 —— 漏掉不是 ±20% 的误差，是数量级的误差。
func TestEstimateInputTokens_CountsToolDefinitions(t *testing.T) {
	bare := `{"model":"m","messages":[{"role":"user","content":"hi"}]}`
	withTools := `{"model":"m","messages":[{"role":"user","content":"hi"}],
		"tools":[{"name":"bash","description":"Run a shell command on the local machine",
		"input_schema":{"type":"object","properties":{"command":{"type":"string",
		"description":"The shell command to execute"}}}}]}`

	a, err := estimateInputTokens([]byte(bare))
	if err != nil {
		t.Fatalf("估算失败: %v", err)
	}
	b, err := estimateInputTokens([]byte(withTools))
	if err != nil {
		t.Fatalf("估算失败: %v", err)
	}
	if b <= a {
		t.Errorf("带 tools 的估算 (%d) 应显著大于不带的 (%d)", b, a)
	}
}

// 长文本要给出更大的值。这是估算唯一真正需要保证的性质：
// 绝对精度做不到（真实是 BPE subword），但单调性必须成立 ——
// 上下文越长预算越大，否则它作为预算就完全没用。
func TestEstimateTokens_MonotonicWithLength(t *testing.T) {
	short := estimateTokens("hello world")
	long := estimateTokens(strings.Repeat("hello world ", 100))
	if long <= short {
		t.Errorf("长文本估算 (%d) 应大于短文本 (%d)", long, short)
	}
	if estimateTokens("") != 0 {
		t.Error("空串应为 0")
	}
}

// CJK 没有空格分词，按词切会把一整句算成一个词。必须按字算。
func TestEstimateTokens_CJKCountedPerChar(t *testing.T) {
	// 12 个汉字，无空格。按词切只有 1 个词 → 约 1 token，那是严重低估。
	got := estimateTokens("今天天气很好我们出去散步吧")
	if got < 10 {
		t.Errorf("CJK 估算 = %d, 明显偏低（应按字计，约 1.5×字数）", got)
	}
}

// 兜底路径上 body 不是合法 JSON 时回 400，而不是 panic 或 0。
//
// 回 0 比回错误更危险：客户端会以为上下文是空的，然后发一个超长请求给上游。
//
// 注意这里必须**强制走兜底**（用一个没配的 model）。转发路径不做这个校验
// 是刻意的 —— ExtractModel 用流式扫描，读到顶层 model 就返回，不看后面的
// 字节；body 合不合法交给上游判断。那是严格透传的要求（§3.3），
// 我们没有资格代替上游拒绝一个请求。
func TestCountTokens_InvalidJSONIsBadRequestOnFallback(t *testing.T) {
	hs := newHarness(t, nil)
	r := hs.countTokensRequest(`{"model":"unconfigured-model","messages":[}`)
	rec := hs.serve(r)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("状态码 = %d, want 400（原文 %q）", rec.Code, rec.Body.String())
	}
}

// 与上一条配对：转发路径**不**代替上游校验 body。
// 上游收下并回 200，我们就原样回 200 —— 这是严格透传的直接后果。
func TestCountTokens_ProxyPathDoesNotValidateBody(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"input_tokens":9}`))
	})
	rec := hs.serve(hs.countTokensRequest(`{"model":"claude-opus-5","messages":[}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, want 200（body 校验归上游）", rec.Code)
	}
	if got := decodeInputTokens(t, rec.Body.String()); got != 9 {
		t.Errorf("input_tokens = %d, want 9", got)
	}
}

// 回归测试：无空白的长串（base64 图片）不能被算成 1 个 token。
//
// 这是 review 时实测抓到的真 bug。一张 1024×1024 的图 base64 后有几百 KB
// 且完全没有空白，原实现把它当成「1 个词」→ 1 个 token，而它在 Anthropic
// 侧约合 1400 个。低估上千倍。
//
// 方向尤其糟：低估会让 Claude Code 以为上下文还很空，然后发一个超出窗口的
// 请求被上游 400 拒掉 —— 而「宁可估高」正是这个估算器的设计前提。
func TestEstimateTokens_LongUnbrokenStringNotCountedAsOneWord(t *testing.T) {
	// 模拟 base64：连续字母，无空白无标点
	b64 := strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", 4096) // 128KB
	got := estimateTokens(b64)

	// 128KB base64 按 4 字符/token 算约 32k。允许量级内的偏差，
	// 但绝不能是个位数 —— 那是 bug 的特征。
	if got < 10_000 {
		t.Errorf("128KB base64 估算 = %d，明显低估（应为万级）", got)
	}

	// 单调性：图更大，估值必须更大
	bigger := estimateTokens(strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", 8192))
	if bigger <= got {
		t.Errorf("更大的 base64 估算 (%d) 应大于较小的 (%d)", bigger, got)
	}
}

// 但正常英文不能因为上一条而被高估。折算只该对超长词生效。
func TestEstimateTokens_NormalProseUnaffectedByLongWordRule(t *testing.T) {
	prose := "The quick brown fox jumps over the lazy dog near the riverbank."
	got := estimateTokens(prose)

	// 12 个词 × 1.3 ≈ 15。真实 tokenizer 约 14。
	// 若折算规则误伤了普通单词，这个值会明显偏大。
	if got < 10 || got > 25 {
		t.Errorf("普通英文估算 = %d，期望 10–25（折算规则不该误伤普通单词）", got)
	}
}

// ── /v1/models ────────────────────────────────────────────

func TestModels_ListsEnabledModelNames(t *testing.T) {
	hs := newHarness(t, nil)
	// 再加两个：一个启用、一个停用，验证过滤与定序。
	extra := []*model.ModelName{
		{ID: 2, Name: "aaa-model", Protocol: model.ProtoOpenAIChat,
			MatchMode: model.MatchExact, Enabled: true},
		{ID: 3, Name: "disabled-model", Protocol: model.ProtoAnthropic,
			MatchMode: model.MatchExact, Enabled: false},
	}
	hs.cfg.snap.ModelNames = append(hs.cfg.snap.ModelNames, extra...)

	r := httptest.NewRequest("GET", "/v1/models", nil)
	r.Header.Set("X-Api-Key", hs.relayPW)
	rec := hs.serve(r)

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, want 200", rec.Code)
	}
	var resp struct {
		Object string `json:"object"`
		Data   []struct {
			ID      string `json:"id"`
			Object  string `json:"object"`
			OwnedBy string `json:"owned_by"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v（原文 %q）", err, rec.Body.String())
	}
	if resp.Object != "list" {
		t.Errorf("object = %q, want list", resp.Object)
	}

	var ids []string
	for _, d := range resp.Data {
		ids = append(ids, d.ID)
		if d.Object != "model" {
			t.Errorf("%s 的 object = %q, want model", d.ID, d.Object)
		}
	}
	// 已定序，所以可以直接比对完整列表 —— 停用的那个必须不在里面。
	want := []string{"aaa-model", "claude-opus-5"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Errorf("模型列表 = %v, want %v", ids, want)
	}
}

// 列表不按健康状态过滤：一个暂时 dead 的模型在列表里消失，客户端可能
// 把它从自己的配置里也去掉，而它几十秒后就恢复了。
func TestModels_IncludesDeadRoutes(t *testing.T) {
	hs := newHarness(t, nil)
	hs.health.dead[100] = true

	r := httptest.NewRequest("GET", "/v1/models", nil)
	r.Header.Set("X-Api-Key", hs.relayPW)
	rec := hs.serve(r)

	if !strings.Contains(rec.Body.String(), "claude-opus-5") {
		t.Errorf("dead 的模型不该从列表里消失: %s", rec.Body.String())
	}
}

// 空配置要回一个空数组，不能是 JSON null ——
// 客户端多半直接 for 循环，null 会让它崩在启动阶段。
func TestModels_EmptyConfigReturnsEmptyArray(t *testing.T) {
	hs := newHarness(t, nil)
	hs.cfg.snap.ModelNames = nil

	r := httptest.NewRequest("GET", "/v1/models", nil)
	r.Header.Set("X-Api-Key", hs.relayPW)
	rec := hs.serve(r)

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"data":[]`) {
		t.Errorf("空配置应回 \"data\":[]，得到 %s", rec.Body.String())
	}
}

func TestModels_RequiresAuth(t *testing.T) {
	hs := newHarness(t, nil)
	rec := hs.serve(httptest.NewRequest("GET", "/v1/models", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("状态码 = %d, want 401", rec.Code)
	}
}
