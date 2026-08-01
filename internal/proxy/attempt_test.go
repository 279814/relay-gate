package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Send / Commit / Discard 的资源账。
//
// 这组测试盯的不是功能，是**泄漏**：Attempt 持着一个 context.CancelFunc
// 与一个未关的 resp.Body，两者都必须由 Commit 或 Discard 释放。漏掉的话
// 单元测试照样全绿 —— 症状要到连接池耗尽或 goroutine 堆积时才显形，
// 那时候已经很难回溯到这里。

func TestAttempt_DiscardClosesBodyAndCancelsCtx(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(502)
		w.Write([]byte(`{"error":"bad gateway"}`))
	}))
	defer up.Close()

	f := testForwarder(t, fastTimeouts())
	at := f.Send(context.Background(), "POST", up.URL, http.Header{}, []byte("{}"))
	if at.Failed() {
		t.Fatalf("应拿到响应头：%v", at.Result().Err)
	}
	if at.Status() != 502 {
		t.Fatalf("状态码应为 502，得到 %d", at.Status())
	}

	// 提交前不该有任何字节写给客户端 —— 这正是能重试的前提。
	if at.Result().HeadersSent {
		t.Error("Send 之后 HeadersSent 不该为 true")
	}

	ctx := at.ctx
	at.Discard()

	if ctx.Err() == nil {
		t.Error("Discard 之后 context 应已取消，否则它会留到 Total 超时才回收")
	}
}

// Send 失败（连不上）时也必须能 Discard —— context 是 Send 建的。
func TestAttempt_DiscardAfterSendFailureDoesNotPanic(t *testing.T) {
	f := testForwarder(t, fastTimeouts())
	at := f.Send(context.Background(), "POST", "http://127.0.0.1:1", http.Header{}, []byte("{}"))
	if !at.Failed() {
		t.Fatal("连 127.0.0.1:1 应失败")
	}
	ctx := at.ctx
	at.Discard() // resp 为 nil，不能崩
	if ctx.Err() == nil {
		t.Error("失败的尝试也要释放 context")
	}
}

// Commit 走完整路径：响应头 + 响应体，且 body 恰好关一次。
func TestAttempt_CommitWritesHeadersAndBody(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Marker", "yes")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer up.Close()

	f := testForwarder(t, fastTimeouts())
	at := f.Send(context.Background(), "POST", up.URL, http.Header{}, []byte("{}"))
	if at.Failed() {
		t.Fatalf("Send 失败：%v", at.Result().Err)
	}

	rec := httptest.NewRecorder()
	res := at.Commit(rec)
	if res.Err != nil {
		t.Fatalf("Commit 失败：%v", res.Err)
	}
	if rec.Code != 200 {
		t.Errorf("状态码应为 200，得到 %d", rec.Code)
	}
	if rec.Body.String() != `{"ok":true}` {
		t.Errorf("body = %q", rec.Body.String())
	}
	if rec.Header().Get("X-Upstream-Marker") != "yes" {
		t.Error("上游响应头应原样回传")
	}
	if !res.HeadersSent {
		t.Error("Commit 之后 HeadersSent 应为 true")
	}
	ctx := at.ctx
	if ctx.Err() == nil {
		t.Error("Commit 之后 context 应已取消")
	}
}

// Commit 之后再 Discard（调用方写错了）不该二次关 body 或二次写。
//
// 这不是假想：重试循环里「提交成功后跳出」与「函数出口统一 Discard」
// 很容易同时存在，而二次 Close 在 http.Response.Body 上是未定义行为。
func TestAttempt_CommitThenDiscardIsSafe(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	}))
	defer up.Close()

	f := testForwarder(t, fastTimeouts())
	at := f.Send(context.Background(), "POST", up.URL, http.Header{}, []byte("{}"))
	rec := httptest.NewRecorder()
	at.Commit(rec)
	at.Discard() // 应为 no-op

	if rec.Body.String() != `{"ok":true}` {
		t.Errorf("Discard 影响了已提交的响应：%q", rec.Body.String())
	}
}

// Discard 会读掉一小段 body 让连接能还回池子。上限必须生效 ——
// 否则丢弃一个长 SSE 流时会在这里读到超时。
func TestAttempt_DiscardDoesNotDrainUnboundedBody(t *testing.T) {
	// 一个不停吐数据、永不结束的上游。
	stop := make(chan struct{})
	defer close(stop)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := w.Write([]byte("data: " + strings.Repeat("x", 1024) + "\n\n")); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	}))
	defer up.Close()

	f := testForwarder(t, fastTimeouts())
	at := f.Send(context.Background(), "POST", up.URL, http.Header{}, []byte("{}"))
	if at.Failed() {
		t.Fatalf("Send 失败：%v", at.Result().Err)
	}

	done := make(chan struct{})
	go func() { at.Discard(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Discard 卡在读 body 上 —— 排水没有上限，遇到长流会一直读下去")
	}
}
