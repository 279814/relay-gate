package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const fakeRelayKey = "fake-relay-key-for-tests"

func relayEnv(name string) string {
	if name == "RELAY_TEST_KEY" {
		return fakeRelayKey
	}
	return ""
}

func probeLines(stdout string) map[string]string {
	lines := map[string]string{}
	for _, line := range strings.Split(stdout, "\n") {
		cols := strings.Split(line, "\t")
		if len(cols) >= 5 && (cols[0] == "PASS" || cols[0] == "FAIL") {
			lines[cols[2]] = cols[0] + " " + cols[3] + " " + cols[4]
		}
	}
	return lines
}

// 一个 New API / One API / sub2api 形态的网关：四个端点都在，SSE 的
// Content-Type 带 charset 或干脆标错，请求形状由服务端逐项校验。
func TestProbeCLI_FlagMode_AllEndpointsAgainstRelayShapes(t *testing.T) {
	var mu sync.Mutex
	var problems []string
	fail := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+fakeRelayKey {
			fail("path %s: bad Authorization", r.URL.Path)
		}
		var body map[string]any
		if r.Method == http.MethodPost {
			raw, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(raw, &body); err != nil {
				fail("path %s: body not JSON", r.URL.Path)
			}
		}
		switch r.URL.Path {
		case "/v1/models":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"object":"list","data":[{"id":"claude-x"},{"id":"gpt-x"}],"success":true}`)
		case "/v1/messages":
			if r.Header.Get("anthropic-version") == "" {
				fail("messages: missing anthropic-version")
			}
			if body["max_tokens"] != float64(1) || body["stream"] != true {
				fail("messages: want max_tokens=1 stream=true, got %v", body)
			}
			// 公益站常见：SSE 正文却标成 application/json。
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"output_tokens\":0}}}\n\n"+
				"event: ping\ndata: {\"type\":\"ping\"}\n\n"+
				"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"2\"}}\n\n"+
				"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
		case "/v1/messages/count_tokens":
			if r.Header.Get("anthropic-version") == "" {
				fail("count_tokens: missing anthropic-version")
			}
			if _, ok := body["max_tokens"]; ok {
				fail("count_tokens: must not send max_tokens")
			}
			if _, ok := body["stream"]; ok {
				fail("count_tokens: must not send stream")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"input_tokens":9}`)
		case "/v1/responses":
			if body["max_output_tokens"] != float64(16) || body["stream"] != true {
				fail("responses: want max_output_tokens=16 stream=true, got %v", body)
			}
			w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
			_, _ = io.WriteString(w, "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"status\":\"in_progress\"}}\n\n"+
				"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"2\"}\n\n")
		case "/v1/chat/completions":
			if body["max_tokens"] != float64(1) {
				fail("chat: want max_tokens=1, got %v", body)
			}
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data:{\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":\"\"}}]}\n\n"+
				"data:{\"choices\":[{\"delta\":{\"content\":\"2\"}}]}\n\ndata:[DONE]\n\n")
		default:
			fail("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runProbeCLI([]string{
		"probe-matrix", "--online", "--accept-probe-cost",
		"--base-url", srv.URL + "/v1/", "--key-env", "RELAY_TEST_KEY",
		"--claude-model", "claude-x", "--gpt-model", "gpt-x", "--name", "relay",
	}, nil, &stdout, &stderr, probeCLIDeps{transport: srv.Client().Transport, getenv: relayEnv})

	mu.Lock()
	defer mu.Unlock()
	for _, p := range problems {
		t.Error(p)
	}
	if code != exitOK {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	lines := probeLines(stdout.String())
	for _, ep := range []string{"models", "messages", "count_tokens", "responses", "chat_completions"} {
		if !strings.HasPrefix(lines[ep], "PASS http=200") {
			t.Errorf("%s: %q", ep, lines[ep])
		}
	}
	if strings.Contains(stdout.String()+stderr.String(), fakeRelayKey) ||
		strings.Contains(stdout.String(), srv.URL) {
		t.Fatal("stdout/stderr leaked key or base URL")
	}
}

// 起初失败的那类站（agentrouter / anyrouter / Decode / seekai）的共同点是
// HTTP 200 流内报错。这里按三种网关的真实错误形态逐一喂给 CLI，要求结论
// 是具体的错误类别而不是 fake_alive / 解析失败。
func TestProbeCLI_RelayStreamErrorShapes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"data":[]}`)
		case "/v1/messages":
			// sub2api：Anthropic 原生 error 事件。
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"busy\"}}\n\n")
		case "/v1/messages/count_tokens":
			// One API 没有这个路由。
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":{"message":"Invalid URL (POST /v1/messages/count_tokens)","type":"invalid_request_error","code":""}}`)
		case "/v1/responses":
			// New API 透传的 response.failed。
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"status\":\"in_progress\"}}\n\n"+
				"event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{\"status\":\"failed\",\"error\":{\"code\":\"rate_limit_exceeded\",\"message\":\"slow down\"}}}\n\n")
		case "/v1/chat/completions":
			// One API / New API：没有 event 行的 data 错误。
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: {\"error\":{\"message\":\"upstream failed\",\"type\":\"new_api_error\",\"code\":\"bad_response_status_code\"}}\n\ndata: [DONE]\n\n")
		}
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runProbeCLI([]string{
		"probe-matrix", "--online", "--accept-probe-cost",
		"--base-url", srv.URL, "--claude-model", "claude-x", "--gpt-model", "gpt-x",
	}, nil, &stdout, &stderr, probeCLIDeps{transport: srv.Client().Transport, getenv: relayEnv})
	if code != exitFail {
		t.Fatalf("code=%d stdout=%s", code, stdout.String())
	}
	want := map[string]string{
		"models":           "PASS http=200 class=none",
		"messages":         "FAIL http=200 class=rate_limited",
		"count_tokens":     "FAIL http=404 class=unsupported",
		"responses":        "FAIL http=200 class=rate_limited",
		"chat_completions": "FAIL http=200 class=transient_error",
	}
	got := probeLines(stdout.String())
	for ep, w := range want {
		if got[ep] != w {
			t.Errorf("%s: got %q want %q", ep, got[ep], w)
		}
	}
}

// 首个语义证据之后 CLI 必须停止读取：上游之后挂住不收尾时，CLI 仍应立刻返回，
// 而不是等到超时（那等于把整份 max_tokens 都读完）。
func TestProbeCLI_StopsReadingAfterFirstSemantic(t *testing.T) {
	released := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"data":[{"id":"claude-x"}]}`)
			return
		case "/v1/messages/count_tokens":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"input_tokens":3}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"2\"}}\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-released:
		}
	}))
	defer srv.Close()
	defer close(released)

	done := make(chan int, 1)
	var stdout bytes.Buffer
	go func() {
		done <- runProbeCLI([]string{
			"probe-matrix", "--online", "--accept-probe-cost",
			"--base-url", srv.URL, "--claude-model", "claude-x",
		}, nil, &stdout, io.Discard, probeCLIDeps{transport: srv.Client().Transport, getenv: relayEnv})
	}()
	select {
	case code := <-done:
		if code != exitOK {
			t.Fatalf("code=%d stdout=%s", code, stdout.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("CLI kept reading after the first semantic event")
	}
}

func TestProbeCLI_FlagModeValidation(t *testing.T) {
	cases := []struct {
		name string
		args []string
		code int
	}{
		{"input and base-url", []string{"probe-matrix", "--online", "--accept-probe-cost",
			"--input", "x.tsv", "--base-url", "http://127.0.0.1:9", "--claude-model", "c"}, exitUsage},
		{"neither input nor base-url", []string{"probe-matrix", "--online", "--accept-probe-cost"}, exitUsage},
		{"empty key env", []string{"probe-matrix", "--online", "--accept-probe-cost",
			"--base-url", "http://127.0.0.1:9", "--key-env", "MISSING", "--claude-model", "c"}, exitFail},
		{"no models", []string{"probe-matrix", "--online", "--accept-probe-cost",
			"--base-url", "http://127.0.0.1:9"}, exitFail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trips := 0
			rt := roundTripFunc(func(*http.Request) (*http.Response, error) {
				trips++
				return nil, io.EOF
			})
			code := runProbeCLI(tc.args, nil, io.Discard, io.Discard,
				probeCLIDeps{transport: rt, getenv: relayEnv})
			if code != tc.code {
				t.Fatalf("code=%d want %d", code, tc.code)
			}
			if trips != 0 {
				t.Fatalf("trips=%d", trips)
			}
		})
	}
}
