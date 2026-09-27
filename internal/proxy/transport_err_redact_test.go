package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/router"
)

// 上游回显请求行时，net/http 的解析错误会把那一行原样带进 res.Err：
//
//	malformed HTTP status code "/v1/messages?key=<key>&beta=true"
//
// 这段文本来自上游响应，不是出站 URL 的 *url.Error，所以「RoundTrip 不带 URL」
// 挡不住它。FixedQueryTemplate / legacy_exact 把 key 放在 query 时（§7.1），
// 转发日志、重试日志、样本 Error 与 count_tokens 降级原因都会拿到明文 key。
func echoRequestLineUpstream(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				line, err := bufio.NewReader(c).ReadString('\n')
				if err != nil {
					return
				}
				_, _ = c.Write([]byte(line + "\r\n"))
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func newEchoLineHarness(t *testing.T, secret string) (*harness, *bytes.Buffer) {
	t.Helper()
	addr := echoRequestLineUpstream(t)
	hs := newHarness(t, nil)
	up := hs.cfg.snap.Upstreams[10]
	up.APIKey = secret
	up.FullURLMode = true
	up.BaseURL = "http://" + addr + "/v1/messages"
	hs.h = hs.h.WithTargets(testTargetsWithQuery(hs.cfg, "key={{UPSTREAM_API_KEY}}"), nil)
	var logs bytes.Buffer
	hs.h.log = slog.New(slog.NewTextHandler(&logs, nil))
	return hs, &logs
}

func TestTransportErr_EchoedRequestLineRedactedInLogAndSample(t *testing.T) {
	const secret = "sk-upstream-secret-echoed-in-status-line"
	hs, logs := newEchoLineHarness(t, secret)

	rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))
	if rec.Code == 200 {
		t.Fatalf("畸形响应却回了 200，body=%q", rec.Body.String())
	}

	if !strings.Contains(logs.String(), "malformed") {
		t.Fatalf("日志应带出 net/http 的解析错误，便于诊断:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), secret) {
		t.Errorf("转发日志出现了明文上游 key:\n%s", logs.String())
	}
	smp := hs.sink.one(t)
	if smp.Error == "" {
		t.Fatal("样本 Error 不应为空")
	}
	if strings.Contains(smp.Error, secret) {
		t.Errorf("样本 Error 出现了明文上游 key：%q", smp.Error)
	}
}

// logRetry 与 logResult 打的是同一个 res.Err。目前回显只发生在 GotConn 之后
// （ErrUpstreamBroke，不换站），但这条日志不能依赖重试策略来保证不泄露。
func TestTransportErr_LogRetryRedactsKeyInErr(t *testing.T) {
	const secret = "sk-upstream-secret-echoed-in-retry-log"
	hs, logs := newEchoLineHarness(t, secret)
	cand := &router.Candidate{Upstream: hs.cfg.snap.Upstreams[10],
		Route: &model.Route{ID: 100}}
	la := &liveAttempt{cand: cand, keys: []string{secret}, at: &Attempt{res: &Result{
		Err: fmt.Errorf("%w: net/http: HTTP/1.x transport connection broken: "+
			"malformed HTTP status code %q", ErrConnect, "/v1/messages?key="+secret),
	}}}

	hs.h.logRetry(la, "claude-opus-5", 1, 2)

	if !strings.Contains(logs.String(), "malformed") {
		t.Fatalf("重试日志应保留错误原因:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), secret) {
		t.Errorf("重试日志出现了明文上游 key:\n%s", logs.String())
	}
}

// 健康回写的 Err 会被 Tracker 原样存成 route_health.last_error（落库，
// /admin/api/health 可见），必须与 ErrBody 一样先脱敏。
func TestTransportErr_EchoedRequestLineRedactedInHealthReport(t *testing.T) {
	const secret = "sk-upstream-secret-echoed-health-report"
	hs, _ := newEchoLineHarness(t, secret)
	spy := &capturingReporter{}
	hs.h.WithHealthReporter(spy)

	hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`))

	got := spy.last()
	if got == nil || got.Err == nil {
		t.Fatalf("应上报传输层错误，got=%+v", got)
	}
	if !strings.Contains(got.Err.Error(), "malformed") {
		t.Fatalf("健康 Err 应保留解析错误原因：%q", got.Err.Error())
	}
	if strings.Contains(got.Err.Error(), secret) {
		t.Errorf("健康 Err 出现了明文上游 key：%q", got.Err.Error())
	}
	if !IsUpstreamFault(got.Err) {
		t.Errorf("脱敏后丢了错误链，健康分类会误判：%v", got.Err)
	}
}

func TestViewOf_RedactedErrKeepsSentinel(t *testing.T) {
	const secret = "sk-upstream-secret-in-view-err"
	res := &Result{Err: fmt.Errorf("%w: malformed HTTP status code %q",
		ErrUpstreamBroke, "/v1/messages?key="+secret)}
	v := viewOf(res, []string{secret}, model.EndpointMessages)
	if strings.Contains(v.Err.Error(), secret) {
		t.Errorf("view.Err 出现了明文 key：%q", v.Err.Error())
	}
	if !errors.Is(v.Err, ErrUpstreamBroke) {
		t.Errorf("view.Err 丢了哨兵：%v", v.Err)
	}
	if viewOf(&Result{}, []string{secret}, model.EndpointMessages).Err != nil {
		t.Error("nil Err 应保持 nil")
	}
}

func TestTransportErr_EchoedRequestLineRedactedInCountTokensReason(t *testing.T) {
	const secret = "sk-upstream-secret-echoed-count-tokens"
	hs, logs := newEchoLineHarness(t, secret)

	rec := hs.serve(hs.countTokensRequest(
		`{"model":"claude-opus-5","messages":[{"role":"user","content":"hi"}]}`))
	if rec.Code != 200 {
		t.Fatalf("应降级本地粗算，status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(logs.String(), "malformed") {
		t.Fatalf("降级原因应带出解析错误:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), secret) {
		t.Errorf("count_tokens 降级日志出现了明文上游 key:\n%s", logs.String())
	}
}
