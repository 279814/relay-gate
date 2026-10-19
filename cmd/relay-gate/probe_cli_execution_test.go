package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func cliPrivateRepository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := cliRestrictPrivatePath(root); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("git", "init", "-q", root)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("initialize disposable repository: %v %s", err, output)
	}
	for name, content := range map[string]string{".gitignore": ".local/p0/\n", ".dockerignore": ".local/p0/\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, ".local", "p0", "reports"), 0700); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestProbeCLISharedExecutorSendsEveryDeclaredCandidateOnceWithCanonicalAuth(t *testing.T) {
	const key = "synthetic-cli-single-auth-fixture-credential"
	var mu sync.Mutex
	hits := map[string]int{}
	badAuth := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire, _ := io.ReadAll(r.Body)
		var input struct{ Model string }
		_ = json.Unmarshal(wire, &input)
		mu.Lock()
		hits[r.URL.Path+"|"+input.Model]++
		// Anthropic and OpenAI must use their explicit single-header profile,
		// never the retired CLI's unconditional pair of auth headers.
		if strings.HasPrefix(r.URL.Path, "/v1/messages") {
			badAuth = badAuth || r.Header.Get("X-Api-Key") != key || r.Header.Get("Authorization") != ""
		} else {
			badAuth = badAuth || r.Header.Get("Authorization") != "Bearer "+key || r.Header.Get("X-Api-Key") != ""
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/models":
			io.WriteString(w, `{"data":[{"id":"fixture"}]}`)
		case "/v1/messages/count_tokens":
			io.WriteString(w, `{"input_tokens":3}`)
		case "/v1/messages":
			io.WriteString(w, `{"type":"message","content":[{"type":"text","text":"2"}],"stop_reason":"end_turn","usage":{"output_tokens":1}}`)
		case "/v1/chat/completions":
			io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"2"},"finish_reason":"stop"}]}`)
		case "/v1/responses":
			io.WriteString(w, `{"object":"response","status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"2"}]}]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	root := cliPrivateRepository(t)
	output := filepath.Join(root, ".local", "p0", "reports", "matrix.json")
	var stdout, stderr bytes.Buffer
	code := runProbeCLI([]string{"probe-matrix", "--online", "--accept-probe-cost", "--base-url", server.URL,
		"--key-env", "CLI_FIXTURE_KEY", "--claude-model", "claude-one,claude-two", "--gpt-model", "gpt-one,gpt-two", "--output", output},
		nil, &stdout, &stderr, probeCLIDeps{repoRoot: root, getenv: func(string) string { return key }})
	if code != exitOK {
		t.Fatalf("matrix failed: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if badAuth {
		t.Error("CLI bypassed the production canonical Auth profile")
	}
	want := []string{"/v1/models|", "/v1/messages|claude-one", "/v1/messages/count_tokens|claude-one", "/v1/messages|claude-two", "/v1/messages/count_tokens|claude-two",
		"/v1/chat/completions|gpt-one", "/v1/responses|gpt-one", "/v1/chat/completions|gpt-two", "/v1/responses|gpt-two"}
	if len(hits) != len(want) {
		t.Errorf("candidate count=%d, want %d: %v", len(hits), len(want), hits)
	}
	for _, target := range want {
		if hits[target] != 1 {
			t.Errorf("actual sends %s=%d, want one", target, hits[target])
		}
	}
	wire, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{key, server.URL, root} {
		if bytes.Contains(wire, []byte(private)) || strings.Contains(stdout.String()+stderr.String(), private) {
			t.Fatal("CLI leaked private input into its public report")
		}
	}
}

func TestProbeCLIDiagnosticErrorsAndAliasesCannotEchoInputSecrets(t *testing.T) {
	const private = "synthetic-cli-secret-that-must-not-be-public"
	for _, args := range [][]string{
		{"probe-one", "--accept-" + private, "--input", "-", "--name", "fixture"},
		{"probe-one", "--online", "--accept-probe-cost", "--base-url", "http://127.0.0.1:9", "--key-env", "KEY", "--claude-model", "model", "--name", private},
	} {
		var stdout, stderr bytes.Buffer
		sends := 0
		code := runProbeCLI(args, nil, &stdout, &stderr, probeCLIDeps{getenv: func(string) string { return private }, transport: roundTripFunc(func(*http.Request) (*http.Response, error) { sends++; return nil, io.EOF })})
		if code == exitOK || sends != 0 || strings.Contains(stdout.String()+stderr.String(), private) {
			t.Fatalf("secret-bearing diagnostic escaped: code=%d sends=%d leaked=%t", code, sends, strings.Contains(stdout.String()+stderr.String(), private))
		}
	}
}

func TestProbeCLIReportRechecksPrivateDestinationBeforeWriting(t *testing.T) {
	root := cliPrivateRepository(t)
	output := filepath.Join(root, ".local", "p0", "reports", "result.json")
	outside := filepath.Join(t.TempDir(), "must-stay-unchanged.json")
	writeFile(t, outside, "sentinel")
	probeLink := filepath.Join(root, "link-check")
	if err := os.Symlink(outside, probeLink); err != nil {
		t.Skip("symlink privilege unavailable")
	}
	os.Remove(probeLink)
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() {
			if err := os.Symlink(outside, output); err != nil {
				t.Error(err)
			}
		})
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/models":
			io.WriteString(w, `{"data":[]}`)
		case "/v1/messages/count_tokens":
			io.WriteString(w, `{"input_tokens":3}`)
		default:
			io.WriteString(w, `{"type":"message","content":[{"type":"text","text":"2"}],"stop_reason":"end_turn"}`)
		}
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	code := runProbeCLI([]string{"probe-one", "--name", "fixture", "--online", "--accept-probe-cost", "--base-url", server.URL, "--key-env", "KEY", "--claude-model", "fixture-model", "--output", output}, nil, &stdout, &stderr,
		probeCLIDeps{repoRoot: root, getenv: func(string) string { return "synthetic-cli-report-fixture-credential" }})
	data, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if code == exitOK || string(data) != "sentinel" {
		t.Fatal("report followed a destination swapped after preflight")
	}
	if strings.Contains(stdout.String()+stderr.String(), root) || strings.Contains(stdout.String()+stderr.String(), outside) {
		t.Fatal("report write error disclosed private paths")
	}
}
