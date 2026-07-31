package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
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

// 短 key 同样不能漏。
//
// sample.RedactBodyKeys 有 12 字符下限（短于此不脱敏），所以这里必须走
// RedactDiagnostic。而短 key 是真实可达的配置 —— 上游 api_key 没有
// 长度校验（model.Validate 只要求非空）。
func TestL1_ShortUpstreamKeyStillRedacted(t *testing.T) {
	const upKey = "sk-short1" // 9 字符，短于 12

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"bad key ` + upKey + `"}`))
	}))
	defer srv.Close()

	up := upstreamFor(srv.URL)
	up.APIKey = upKey

	out := testProber().L1(context.Background(), up, fastSettings())

	if out.Err == nil {
		t.Fatal("401 应带上失败原因")
	}
	if strings.Contains(out.Err.Error(), upKey) {
		t.Errorf("短 key 未被脱敏：%q", out.Err)
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
