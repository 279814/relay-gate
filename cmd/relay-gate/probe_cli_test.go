package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRunMain_DispatchesProbeBeforeServer(t *testing.T) {
	var stderr bytes.Buffer
	code := runMain([]string{"relay-gate", "probe-one"}, strings.NewReader(""), io.Discard, &stderr)
	if code != exitUsage {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "启动失败") {
		t.Fatal("probe 子命令不应走到 server 启动")
	}
}

func TestProbeCLI_RequiresOnlineAndCost(t *testing.T) {
	trips := 0
	rt := roundTripFunc(func(*http.Request) (*http.Response, error) {
		trips++
		return nil, io.EOF
	})
	dir := t.TempDir()
	out := filepath.Join(dir, "out.json")
	tsv := filepath.Join(dir, "in.tsv")
	writeFile(t, tsv, "a\thttp://127.0.0.1:9\tfake\tclaude-x\t-\tok\n")

	var stderr bytes.Buffer
	code := runProbeCLI([]string{
		"probe-one", "--input", tsv, "--name", "a", "--output", out,
	}, nil, io.Discard, &stderr, probeCLIDeps{transport: rt, repoRoot: dir})
	if code != exitFail {
		t.Fatalf("code=%d", code)
	}
	if trips != 0 {
		t.Fatalf("unauthorized trips=%d", trips)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("未授权不得创建 output")
	}
}

func TestProbeCLI_ControlRequiresReplayFlag(t *testing.T) {
	trips := 0
	rt := roundTripFunc(func(*http.Request) (*http.Response, error) {
		trips++
		return nil, io.EOF
	})
	dir := t.TempDir()
	out := filepath.Join(dir, "out.json")
	tsv := filepath.Join(dir, "in.tsv")
	mani := filepath.Join(dir, "mani.json")
	writeFile(t, tsv, "a\thttp://127.0.0.1:9\tfake\tclaude-x\t-\tok\n")
	writeFile(t, mani, `{"version":"1","entries":[]}`)

	code := runProbeCLI([]string{
		"probe-one", "--online", "--accept-probe-cost",
		"--input", tsv, "--name", "a", "--output", out,
		"--control-manifest", mani,
	}, nil, io.Discard, io.Discard, probeCLIDeps{transport: rt, repoRoot: ""})
	if code != exitFail {
		t.Fatalf("code=%d", code)
	}
	if trips != 0 {
		t.Fatalf("trips=%d", trips)
	}
}

func TestProbeCLI_UnknownAcceptFlag(t *testing.T) {
	var stderr bytes.Buffer
	code := runProbeCLI([]string{
		"probe-one", "--online", "--accept-probe-cost", "--accept-evil",
		"--input", "x", "--name", "a", "--output", "y",
	}, nil, io.Discard, &stderr, probeCLIDeps{})
	if code != exitUsage {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(stderr.String(), "未知授权") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestProbeCLI_ParseTSV_CRLFAndDash(t *testing.T) {
	rows, err := loadTSV("-", strings.NewReader("a\thttp://x\tk\tclaude-1\t-\t好用\r\nb\thttp://y\tk\t-\tgpt-1\t挂了\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Alias != "a" || len(rows[0].GPTModels) != 0 {
		t.Fatalf("%+v", rows)
	}
	if len(rows[1].ClaudeModels) != 0 || rows[1].GPTModels[0] != "gpt-1" {
		t.Fatalf("%+v", rows[1])
	}
}

func TestProbeCLI_RejectDuplicateAlias(t *testing.T) {
	_, err := loadTSV("-", strings.NewReader("a\thttp://x\tk\tclaude-1\t-\t\na\thttp://y\tk\tclaude-2\t-\t\n"))
	if err == nil || !strings.Contains(err.Error(), "重复") {
		t.Fatalf("err=%v", err)
	}
}

func TestProbeCLI_MockMatrix_UsesDecoderClassifier(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/v1/models"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"id":"claude-x"}]}`))
		case strings.Contains(r.URL.Path, "count_tokens"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"input_tokens":12}`))
		default:
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"2\"}}\n\n" +
				"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"))
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	tsv := filepath.Join(dir, "in.tsv")
	out := filepath.Join(dir, "out.json")
	report := filepath.Join(dir, "report.md")
	writeFile(t, tsv, "mock\t"+srv.URL+"\tfake-key\tclaude-x\t-\tok\n")

	var stdout, stderr bytes.Buffer
	code := runProbeCLI([]string{
		"probe-matrix", "--online", "--accept-probe-cost",
		"--input", tsv, "--output", out, "--report", report,
	}, nil, &stdout, &stderr, probeCLIDeps{
		transport: srv.Client().Transport,
		now:       time.Now,
		repoRoot:  "",
	})
	if code != exitOK && code != exitFail {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("fake-key")) || bytes.Contains(data, []byte(srv.URL)) {
		t.Fatalf("output leaked secret/url: %s", data)
	}
	var rows []probeResultRow
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) < 2 {
		t.Fatalf("want multiple endpoint rows, got %d", len(rows))
	}
	// 每个站 /models 一次；messages + count_tokens 各一次 —— 无隐藏 retry。
	var modelsHits int
	for _, r := range rows {
		if r.Endpoint == "models" {
			modelsHits++
		}
	}
	if modelsHits != 1 {
		t.Fatalf("models hits=%d", modelsHits)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
