package probe

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/proxy"
)

// 上游把 key 回显在错误消息里时，判定结论里**不能**出现明文 key。
//
// 这条路径的泄露面比日志更大：Outcome.Err 会流进 health.Report →
// 存成 route_health.last_error（**落库**）→ 由 /admin/api/health 的 reason
// 字段显示在管理界面上。也就是说一个明文上游 key 会同时躺在数据库里
// 和 UI 上。
//
// `{"error":"Invalid API key: sk-xxx"}` 是公益站 401 的常见格式，而 401
// 在 §4.3 里是「致命类」—— 恰恰是最需要把原文显示给用户看的那一类，
// 于是也最容易把 key 一起显示出去。
func TestL1_UpstreamKeyNotLeakedIntoVerdict(t *testing.T) {
	const upKey = "sk-live-upstream-abcdef123456"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		// 上游把它收到的 key 原样回显
		_, _ = w.Write([]byte(`{"error":{"message":"Invalid API key: ` + upKey + `"}}`))
	}))
	defer srv.Close()

	up := upstreamFor(srv.URL)
	up.APIKey = upKey

	out := testProber().L1(context.Background(), up, fastSettings())

	if out.Err == nil {
		t.Fatal("401 应带上失败原因")
	}
	if strings.Contains(out.Err.Error(), upKey) {
		t.Errorf("判定结论里出现了明文上游 key（会落库并显示在 UI 上）：%q", out.Err)
	}
	// 脱敏不能把诊断信息一起吞掉：状态码必须还在，否则用户看到一句
	// 「鉴权错误」却不知道是哪一步出的问题。
	if !strings.Contains(out.Err.Error(), "401") {
		t.Errorf("应保留状态码以便排查：%q", out.Err)
	}
}

// L2 的流内错误同样要脱敏。
//
// 这条与 L1 走的是不同的代码路径：流内错误没有 HTTP 状态码（外层是 200），
// 由 streamErrStatus + ClassifyHTTP 处理。两条路径各有自己的 errFromBody
// 调用，所以要分别验证。
func TestL2_UpstreamKeyNotLeakedFromStreamError(t *testing.T) {
	const upKey = "sk-live-upstream-abcdef123456"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		drainBody(r)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		// 200 但流内报错，且把 key 回显进来 —— 公益站的常见形态
		_, _ = w.Write([]byte(`event: error
data: {"error":{"type":"authentication_error","message":"bad key ` + upKey + `"}}

`))
	}))
	defer srv.Close()

	up := upstreamFor(srv.URL)
	up.APIKey = upKey

	out := testProber().L2(context.Background(), up,
		modelNameFor(model.ProtoAnthropic), &model.Route{ID: 1}, fastSettings())

	if out.Err == nil {
		t.Fatal("流内错误应带上失败原因")
	}
	if strings.Contains(out.Err.Error(), upKey) {
		t.Errorf("流内错误泄露了明文上游 key：%q", out.Err)
	}
}

// L2 的 HTTP 错误路径（4xx/5xx，非流内）同样要脱敏。
func TestL2_UpstreamKeyNotLeakedFromHTTPError(t *testing.T) {
	const upKey = "sk-live-upstream-abcdef123456"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		drainBody(r)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden for key ` + upKey + `"}`))
	}))
	defer srv.Close()

	up := upstreamFor(srv.URL)
	up.APIKey = upKey

	out := testProber().L2(context.Background(), up,
		modelNameFor(model.ProtoAnthropic), &model.Route{ID: 1}, fastSettings())

	if out.Err == nil {
		t.Fatal("403 应带上失败原因")
	}
	if strings.Contains(out.Err.Error(), upKey) {
		t.Errorf("HTTP 错误泄露了明文上游 key：%q", out.Err)
	}
}

// 上游原文里**没有** key 时，错误信息必须一字不改。
//
// 这是配对的反面用例：脱敏只该动 key，不该顺手改写别的内容。
// 上游给的原文是排查的主要依据（「400: model xxx not found」直接告诉
// 用户该改哪里），被脱敏逻辑意外改动的话，那个价值就打了折扣。
func TestL1_ErrorTextUnchangedWhenNoKeyPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"model claude-opus-9 not found"}}`))
	}))
	defer srv.Close()

	up := upstreamFor(srv.URL)
	up.APIKey = "sk-live-upstream-abcdef123456"

	out := testProber().L1(context.Background(), up, fastSettings())

	if out.Err == nil {
		t.Fatal("400 应带上失败原因")
	}
	// 原文里的诊断信息必须完整保留
	if !strings.Contains(out.Err.Error(), "model claude-opus-9 not found") {
		t.Errorf("不含 key 的原文被改动了：%q", out.Err)
	}
}

type blockingURLErrorTransport struct{ leakURL string }

func (rt blockingURLErrorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	<-req.Context().Done()
	return nil, &url.Error{Op: req.Method, URL: rt.leakURL, Err: req.Context().Err()}
}

// 探测 ctx 到期时 RoundTrip 返回的 *url.Error 同样带完整 URL（含 query Secret），
// ctxOutcome 分支不得把它带进 Outcome.Err（Scheduler 日志与 last_error）。
func TestProber_CtxExpiredRoundTrip_OmitsRequestURL(t *testing.T) {
	const secret = "sk-fixture-ctx-query-secret"
	leakURL := "https://leak.example.test/v1/models?api_key=" + secret
	up := upstreamFor("https://leak.example.test")
	prober := &Prober{Transport: blockingURLErrorTransport{leakURL: leakURL}, Targets: testTargets()}

	run := map[string]func(ctx context.Context) Outcome{
		"L1": func(ctx context.Context) Outcome { return prober.L1(ctx, up, fastSettings()) },
		"L2": func(ctx context.Context) Outcome {
			return prober.L2(ctx, up, modelNameFor(model.ProtoAnthropic), &model.Route{ID: 1}, fastSettings())
		},
	}
	for name, probe := range run {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			out := probe(ctx)
			if out.Verdict != health.VerdictUnavailable {
				t.Fatalf("Verdict=%s, want unavailable", out.Verdict)
			}
			if !errors.Is(out.Err, proxy.ErrConnect) {
				t.Fatal("ctx 到期的传输失败应返回通用 ErrConnect")
			}
			got := out.Err.Error()
			if strings.Contains(got, secret) || strings.Contains(got, "leak.example.test") {
				t.Fatal("Outcome.Err 携带了请求 URL 或 query Secret")
			}
		})
	}
}
