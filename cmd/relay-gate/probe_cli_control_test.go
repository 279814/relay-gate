package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

func controlDigest(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }

func writeControlPair(t *testing.T, root string, mutate func(map[string]any, map[string]any)) string {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	body := []byte("{ \"model\":\"captured-model\",\"stream\":true,\"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":\"1+1=? control:0123456789abcdef\"}]}\n")
	headers := json.RawMessage(`[{"name":"Content-Type","values":["application/json"]},{"name":"X-Api-Key","values":["{{UPSTREAM_API_KEY}}"]},{"name":"Accept","values":["application/json","text/event-stream"]},{"name":"Accept-Encoding","values":["gzip, br"]},{"name":"Connection","values":["close"]}]`)
	isolation := map[string]bool{"configuration": true, "mcp": true, "hooks": true, "plugins": true, "environment": true, "temporary_workdir": true}
	fixture := map[string]any{"format_version": 2, "protocol": "anthropic", "endpoint": "messages", "source": "claude-code-isolated", "control_id": "0123456789abcdef", "nonce": "0123456789abcdef",
		"captured_at": now.Add(-time.Second).Format(time.RFC3339), "completed_at": now.Format(time.RFC3339), "truncated": false, "authentication_verified": true, "isolation": isolation,
		"method": "POST", "request_target": "/v1/messages?beta=true", "headers": headers, "body_base64": base64.StdEncoding.EncodeToString(body)}
	entry := map[string]any{"alias": "fixture", "protocol": "anthropic", "endpoint": "messages", "fixture_path": "control.json", "control_id": "0123456789abcdef", "nonce": "0123456789abcdef",
		"captured_at": fixture["captured_at"], "completed_at": fixture["completed_at"], "header_sha256": controlDigest(headers), "body_sha256": controlDigest(body), "body_bytes": len(body), "truncated": false,
		"source": "claude-code-isolated", "secret_scan_version": "1"}
	if mutate != nil {
		mutate(fixture, entry)
	}
	controls := filepath.Join(root, ".local", "p0", "controls")
	if err := os.MkdirAll(controls, 0700); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{"control.json": fixture, "manifest.json": map[string]any{"version": "1", "entries": []any{entry}}} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(controls, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(controls, "manifest.json")
}

func TestProbeCLIPrivateInputAndOutputPolicyPrecedesAnySend(t *testing.T) {
	for _, kind := range []string{"input-outside-ignored-root", "docker-reincluded", "input-public-permissions", "output-outside-ignored-root", "output-parent-symlink"} {
		t.Run(kind, func(t *testing.T) {
			root := cliPrivateRepository(t)
			input := filepath.Join(root, ".local", "p0", "sites.tsv")
			output := filepath.Join(root, ".local", "p0", "reports", "result.json")
			if kind == "input-outside-ignored-root" {
				input = filepath.Join(root, "public.tsv")
			}
			if kind == "output-outside-ignored-root" {
				output = filepath.Join(root, "public.json")
			}
			if kind == "docker-reincluded" {
				if err := os.WriteFile(filepath.Join(root, ".dockerignore"), []byte(".local/p0/\n!.local/p0/sites.tsv\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "output-parent-symlink" {
				link := filepath.Join(root, ".local", "p0", "linked-reports")
				if err := os.Symlink(t.TempDir(), link); err != nil {
					t.Skip("symlink privilege unavailable")
				}
				output = filepath.Join(link, "result.json")
			}
			writeFile(t, input, "fixture\thttp://127.0.0.1:9\tsynthetic-cli-private-fixture-key\tmodel\t-\n")
			if kind == "input-public-permissions" {
				if runtime.GOOS == "windows" {
					if out, err := exec.Command("icacls.exe", input, "/grant", "*S-1-1-0:(R)", "/Q").CombinedOutput(); err != nil {
						t.Fatalf("set disposable broad ACL: %v %s", err, out)
					}
				} else {
					if err := os.Chmod(input, 0644); err != nil {
						t.Fatal(err)
					}
				}
			}
			sends := 0
			code := runProbeCLI([]string{"probe-one", "--name", "fixture", "--online", "--accept-probe-cost", "--input", input, "--output", output}, nil, io.Discard, io.Discard,
				probeCLIDeps{repoRoot: root, transport: roundTripFunc(func(*http.Request) (*http.Response, error) { sends++; return nil, io.EOF })})
			if code == exitOK || sends != 0 {
				t.Fatalf("unsafe private I/O reached network: code=%d sends=%d", code, sends)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("rejected private I/O created output")
			}
		})
	}
}

func TestProbeCLIControlReadsAndReplaysExactFixtureBeforeCompactProbe(t *testing.T) {
	root := cliPrivateRepository(t)
	manifest := writeControlPair(t, root, func(f, _ map[string]any) { f["request_target"] = "/v1/messages?%62eta=%74rue&mode=fixture" })
	if _, err := readCLIPrivateFile(manifest, root, maxControlBytes); err != nil {
		t.Fatalf("manifest file protection: %v", err)
	}
	if _, err := loadControlManifest(manifest, root, time.Now()); err != nil {
		t.Fatalf("valid dedicated control rejected: %v", err)
	}
	var mu sync.Mutex
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path == "/v1/messages" {
			mu.Lock()
			requests = append(requests, string(body))
			mu.Unlock()
			if strings.Contains(string(body), "control:0123456789abcdef") {
				if r.URL.RawQuery != "%62eta=%74rue&mode=fixture" || strings.Join(r.Header.Values("Accept"), ",") != "application/json,text/event-stream" || r.Header.Get("Accept-Encoding") != "gzip, br" || r.Header.Get("Connection") != "" {
					t.Error("control headers/query were not preserved")
				}
			}
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"2\"}}\n\n")
		} else {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/v1/models" {
				io.WriteString(w, `{"data":[{"id":"target-model"}]}`)
			} else {
				io.WriteString(w, `{"input_tokens":3}`)
			}
		}
	}))
	defer server.Close()
	output := filepath.Join(root, ".local", "p0", "reports", "result.json")
	var stdout, stderr bytes.Buffer
	validated, err := loadControlManifest(manifest, root, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	completed, err := time.Parse(time.RFC3339Nano, validated.Entries[0].CompletedAt)
	if err != nil {
		t.Fatal(err)
	}
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/v1/messages" {
			deadline, ok := request.Context().Deadline()
			if !ok || !deadline.Equal(completed.Add(60*time.Second)) {
				t.Error("actual control/probe send did not retain the original absolute freshness deadline")
			}
		}
		return http.DefaultTransport.RoundTrip(request)
	})
	_ = runProbeCLI([]string{"probe-one", "--name", "fixture", "--online", "--accept-probe-cost", "--accept-control-replay", "--control-manifest", manifest, "--base-url", server.URL, "--key-env", "FIXTURE_KEY", "--claude-model", "target-model", "--output", output}, nil, &stdout, &stderr,
		probeCLIDeps{repoRoot: root, transport: transport, getenv: func(string) string { return "synthetic-cli-control-fixture-credential" }})
	mu.Lock()
	defer mu.Unlock()
	want := "{ \"model\":\"target-model\",\"stream\":true,\"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":\"1+1=? control:0123456789abcdef\"}]}\n"
	if len(requests) != 2 || requests[0] != want || strings.Contains(requests[len(requests)-1], "control:") {
		t.Fatalf("control was skipped/reencoded/reordered: sends=%d bodies=%q stderr=%s", len(requests), requests, stderr.String())
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"control_status": "paired"`)) {
		t.Fatalf("actual successful control was not paired: %s", data)
	}
	if !strings.Contains(stderr.String(), "sites=1") || !strings.Contains(stderr.String(), "max_requests=4") || !strings.Contains(stderr.String(), "body_bytes_upper=") {
		t.Errorf("cost/privacy preflight did not include actual control: %s", stderr.String())
	}
	var rows []probeResultRow
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.HTTPStatus == 200 && row.ResponseHash == "" {
			t.Errorf("actual observed response hash missing for %s", row.Endpoint)
		}
	}
}

func TestProbeCLIControlFreshnessIsRecheckedAtBothActualSendBoundaries(t *testing.T) {
	for _, expireAt := range []string{"models", "control"} {
		t.Run(expireAt, func(t *testing.T) {
			root := cliPrivateRepository(t)
			manifest := writeControlPair(t, root, nil)
			base := time.Now()
			var offset atomic.Int64
			var messages atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/v1/models" {
					if expireAt == "models" {
						offset.Store(61)
					}
					io.WriteString(w, `{"data":[]}`)
					return
				}
				if r.URL.Path == "/v1/messages" {
					messages.Add(1)
					if expireAt == "control" {
						offset.Store(61)
					}
					io.WriteString(w, `{"type":"message","content":[{"type":"text","text":"2"}],"stop_reason":"end_turn"}`)
					return
				}
				io.WriteString(w, `{"input_tokens":3}`)
			}))
			defer server.Close()
			output := filepath.Join(root, ".local", "p0", "reports", "result.json")
			code := runProbeCLI([]string{"probe-one", "--name", "fixture", "--online", "--accept-probe-cost", "--accept-control-replay", "--control-manifest", manifest, "--base-url", server.URL, "--key-env", "KEY", "--claude-model", "target", "--output", output}, nil, io.Discard, io.Discard,
				probeCLIDeps{repoRoot: root, now: func() time.Time { return base.Add(time.Duration(offset.Load()) * time.Second) }, getenv: func(string) string { return "synthetic-control-freshness-fixture-credential" }})
			want := int64(0)
			if expireAt == "control" {
				want = 1
			}
			if code == exitOK || messages.Load() != want {
				t.Fatalf("expired control was sent/reused: code=%d model sends=%d want=%d", code, messages.Load(), want)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("expired control produced a false complete report")
			}
		})
	}
}

func TestProbeCLIActualControlSuccessAndProbeFailureIsACompatibilityFailure(t *testing.T) {
	root := cliPrivateRepository(t)
	manifest := writeControlPair(t, root, nil)
	var modelSends atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/models":
			io.WriteString(w, `{"data":[]}`)
		case "/v1/messages/count_tokens":
			io.WriteString(w, `{"input_tokens":3}`)
		case "/v1/messages":
			modelSends.Add(1)
			body, _ := io.ReadAll(r.Body)
			if bytes.Contains(body, []byte("control:0123456789abcdef")) {
				io.WriteString(w, `{"type":"message","content":[{"type":"text","text":"2"}],"stop_reason":"end_turn"}`)
			} else {
				w.WriteHeader(401)
				io.WriteString(w, `{"error":{"type":"authentication_error","message":"synthetic private detail never exported"}}`)
			}
		}
	}))
	defer server.Close()
	output := filepath.Join(root, ".local", "p0", "reports", "result.json")
	code := runProbeCLI([]string{"probe-one", "--name", "fixture", "--online", "--accept-probe-cost", "--accept-control-replay", "--control-manifest", manifest, "--base-url", server.URL, "--key-env", "KEY", "--claude-model", "target", "--output", output}, nil, io.Discard, io.Discard,
		probeCLIDeps{repoRoot: root, getenv: func(string) string { return "synthetic-control-compatibility-fixture-credential" }})
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var rows []probeResultRow
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range rows {
		if row.Endpoint == "messages" {
			found = true
			if row.ControlStatus != "control_ok_probe_fail" || row.Control == nil || !row.Control.Success || row.ErrorClass != "auth_rejected" || row.CompatOK {
				t.Fatalf("control/probe failure scope was invented: %+v", row)
			}
		}
	}
	if !found || code != exitFail || modelSends.Load() != 2 || bytes.Contains(data, []byte("synthetic private detail")) {
		t.Fatal("compatibility failure was hidden, retried, or leaked error text")
	}
}

func TestProbeCLIControlRejectsUnverifiedFixtureBeforeAnySendOrReport(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(map[string]any, map[string]any)
	}{
		{"body-hash", func(_ map[string]any, e map[string]any) { e["body_sha256"] = string(bytes.Repeat([]byte("0"), 64)) }},
		{"headers-hash", func(_ map[string]any, e map[string]any) { e["header_sha256"] = string(bytes.Repeat([]byte("0"), 64)) }},
		{"incomplete", func(f, e map[string]any) { f["truncated"] = true; e["truncated"] = true }},
		{"unverified-auth", func(f, _ map[string]any) { f["authentication_verified"] = false }},
		{"unisolated-hooks", func(f, _ map[string]any) { f["isolation"].(map[string]bool)["hooks"] = false }},
		{"ordinary-history-source", func(f, e map[string]any) { f["source"] = "sample"; e["source"] = "sample" }},
		{"future-control", func(f, e map[string]any) {
			future := time.Now().Add(time.Minute).UTC().Format(time.RFC3339)
			f["completed_at"] = future
			e["completed_at"] = future
		}},
		{"fixture-missing", func(_ map[string]any, e map[string]any) { e["fixture_path"] = "missing.json" }},
		{"fixture-outside-controls", func(_ map[string]any, e map[string]any) { e["fixture_path"] = "../../../outside.json" }},
		{"unknown-scan", func(_ map[string]any, e map[string]any) { e["secret_scan_version"] = "unknown" }},
		{"models-cannot-add-a-second-site-request", func(f, e map[string]any) {
			for _, object := range []map[string]any{f, e} {
				object["endpoint"] = "models"
				object["protocol"] = ""
			}
			f["request_target"] = "/v1/models"
			f["method"] = "GET"
			f["body_base64"] = ""
			e["body_sha256"] = controlDigest(nil)
			e["body_bytes"] = 0
		}},
		{"business-text", func(f, e map[string]any) {
			body := []byte(`{"model":"captured","messages":[{"role":"user","content":"private project conversation"}]}`)
			f["body_base64"] = base64.StdEncoding.EncodeToString(body)
			e["body_sha256"] = controlDigest(body)
			e["body_bytes"] = len(body)
		}},
		{"business-system", controlBodyMutation(`{"model":"captured","system":"synthetic-private-project-roadmap","messages":[{"role":"user","content":"1+1=? control:0123456789abcdef"}]}`)},
		{"business-metadata", controlBodyMutation(`{"model":"captured","metadata":{"user_id":"synthetic-private-user"},"messages":[{"role":"user","content":"1+1=? control:0123456789abcdef"}]}`)},
		{"business-thinking", controlBodyMutation(`{"model":"captured","thinking":{"type":"disabled","text":"synthetic-private-project-roadmap"},"messages":[{"role":"user","content":"1+1=? control:0123456789abcdef"}]}`)},
		{"business-stop-sequence", controlBodyMutation(`{"model":"captured","stop_sequences":["synthetic-private-project-roadmap"],"messages":[{"role":"user","content":"1+1=? control:0123456789abcdef"}]}`)},
		{"business-numeric-option", controlBodyMutation(`{"model":"captured","temperature":{"private":"business"},"messages":[{"role":"user","content":"1+1=? control:0123456789abcdef"}]}`)},
		{"cross-protocol-input", controlBodyMutation(`{"model":"captured","input":"synthetic-private-project-roadmap","messages":[{"role":"user","content":"1+1=? control:0123456789abcdef"}]}`)},
		{"case-alias-hides-business", controlBodyMutation(`{"model":"captured","max_tokens":1,"messages":[{"role":"user","content":"private"}],"MESSAGES":[{"role":"user","content":"1+1=? control:0123456789abcdef"}]}`)},
		{"nested-case-alias-hides-business", controlBodyMutation(`{"model":"captured","max_tokens":1,"messages":[{"role":"user","content":"private","CONTENT":"1+1=? control:0123456789abcdef"}]}`)},
		{"case-alias-output-limit", controlBodyMutation(`{"model":"captured","MAX_TOKENS":1,"messages":[{"role":"user","content":"1+1=? control:0123456789abcdef"}]}`)},
		{"known-credential-query", func(f, _ map[string]any) {
			f["request_target"] = "/v1/messages?api_key=synthetic-cli-control-fixture-credential"
		}},
		{"encoded-known-credential-query", func(f, _ map[string]any) {
			f["request_target"] = "/v1/messages?beta=%73ynthetic-cli-control-fixture-credential"
		}},
		{"second-auth-query", func(f, _ map[string]any) { f["request_target"] = "/v1/messages?api_key=synthetic-unrelated-token" }},
		{"business-query", func(f, _ map[string]any) { f["request_target"] = "/v1/messages?task=synthetic-private-project-roadmap" }},
		{"business-header", controlHeaderMutation(`[{"name":"X-Api-Key","values":["{{UPSTREAM_API_KEY}}"]},{"name":"X-Private-Project","values":["synthetic-private-project-roadmap"]}]`)},
		{"business-in-approved-header", controlHeaderMutation(`[{"name":"X-Api-Key","values":["{{UPSTREAM_API_KEY}}"]},{"name":"User-Agent","values":["claude-cli/2.1.220 private-project"]}]`)},
		{"business-media-param", controlHeaderMutation(`[{"name":"X-Api-Key","values":["{{UPSTREAM_API_KEY}}"]},{"name":"Content-Type","values":["application/json; private=business"]}]`)},
		{"escaped-credential-model", controlBodyMutation(`{"model":"\u0073ynthetic-cli-control-fixture-credential","max_tokens":1,"messages":[{"role":"user","content":"1+1=? control:0123456789abcdef"}]}`)},
		{"credential-in-isolated-metadata", func(f, e map[string]any) {
			body := []byte(`{"model":"captured","system":"synthetic-cli-control-fixture-credential","messages":[{"role":"user","content":"1+1=? control:0123456789abcdef"}]}`)
			f["body_base64"] = base64.StdEncoding.EncodeToString(body)
			e["body_sha256"] = controlDigest(body)
			e["body_bytes"] = len(body)
		}},
		{"cookie-secret", func(f, e map[string]any) {
			headers := json.RawMessage(`[{"name":"X-Api-Key","values":["{{UPSTREAM_API_KEY}}"]},{"name":"Cookie","values":["secret_session=opaque-value"]}]`)
			f["headers"] = headers
			e["header_sha256"] = controlDigest(headers)
		}},
		{"hidden-duplicate-message", func(f, e map[string]any) {
			body := []byte(`{"model":"captured","messages":[{"role":"user","content":"private project conversation"}],"messages":[{"role":"user","content":"1+1=? control:0123456789abcdef"}]}`)
			f["body_base64"] = base64.StdEncoding.EncodeToString(body)
			e["body_sha256"] = controlDigest(body)
			e["body_bytes"] = len(body)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := cliPrivateRepository(t)
			manifest := writeControlPair(t, root, test.mutate)
			output := filepath.Join(root, ".local", "p0", "reports", "output.json")
			sends := 0
			transport := roundTripFunc(func(*http.Request) (*http.Response, error) { sends++; return nil, io.EOF })
			code := runProbeCLI([]string{"probe-one", "--name", "fixture", "--online", "--accept-probe-cost", "--accept-control-replay", "--control-manifest", manifest, "--base-url", "http://127.0.0.1:9", "--key-env", "FIXTURE_KEY", "--claude-model", "model", "--output", output}, nil, io.Discard, io.Discard,
				probeCLIDeps{repoRoot: root, transport: transport, getenv: func(string) string { return "synthetic-cli-control-fixture-credential" }})
			if code == exitOK || sends != 0 {
				t.Fatalf("invalid control reached transport: code=%d sends=%d", code, sends)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("invalid control created a false result")
			}
		})
	}
}

func controlBodyMutation(body string) func(map[string]any, map[string]any) {
	return func(f, e map[string]any) {
		f["body_base64"] = base64.StdEncoding.EncodeToString([]byte(body))
		e["body_sha256"] = controlDigest([]byte(body))
		e["body_bytes"] = len(body)
	}
}

func controlHeaderMutation(headers string) func(map[string]any, map[string]any) {
	return func(f, e map[string]any) {
		f["headers"] = json.RawMessage(headers)
		e["header_sha256"] = controlDigest([]byte(headers))
	}
}

func TestControlPromptRejectsBusinessOutsideEndpointInput(t *testing.T) {
	for _, body := range []string{
		`{"model":"captured","input":"1+1=? control:0123456789abcdef","messages":[{"role":"user","content":"private"}]}`,
		`{"model":"captured","input":"1+1=? control:0123456789abcdef","system":"private"}`,
		`{"model":"captured","input":"1+1=? control:0123456789abcdef","metadata":{"user_id":"private"}}`,
	} {
		if err := validateControlPrompt(model.EndpointResponses, []byte(body), "0123456789abcdef"); err == nil {
			t.Fatalf("responses accepted unchecked business fields: %s", body)
		}
	}
}

func TestControlPromptApprovedEndpointMatrix(t *testing.T) {
	for _, test := range []struct {
		endpoint model.EndpointKind
		body     string
	}{
		{model.EndpointMessages, `{"model":"captured","max_tokens":1,"stream":true,"system":"Reply with 2 only.","metadata":{},"thinking":{"type":"disabled"},"stop_sequences":[],"temperature":0,"top_p":1,"top_k":0,"messages":[{"role":"user","content":"1+1=? control:0123456789abcdef"}]}`},
		{model.EndpointCountTokens, `{"model":"captured","system":[{"type":"text","text":"Reply with 2 only.","cache_control":{"type":"ephemeral"}}],"metadata":{},"messages":[{"role":"user","content":[{"type":"text","text":"1+1=? control:0123456789abcdef"}]}]}`},
		{model.EndpointResponses, `{"model":"captured","max_output_tokens":16,"stream":true,"metadata":{},"input":[{"role":"user","content":[{"type":"input_text","text":"1+1=? control:0123456789abcdef"}]}]}`},
		{model.EndpointChatCompletions, `{"model":"captured","max_completion_tokens":1,"stream":true,"messages":[{"role":"user","content":"1+1=? control:0123456789abcdef"}]}`},
	} {
		t.Run(string(test.endpoint), func(t *testing.T) {
			if err := validateControlPrompt(test.endpoint, []byte(test.body), "0123456789abcdef"); err != nil {
				t.Fatalf("approved dedicated control was rejected: %v", err)
			}
		})
	}
}

func TestControlPromptRejectsInvalidOptionsAndHiddenValues(t *testing.T) {
	for _, extra := range []string{
		`"system":[{"type":"text","text":"Reply with 2 only.","private":"business"}]`,
		`"system":[{"type":"text","text":"Reply with 2 only.","cache_control":{"type":"ephemeral","private":"business"}}]`,
		`"system":[{"type":"text","text":"Reply with 2 only.","cache_control":null}]`,
		`"metadata":null`, `"metadata":[]`, `"thinking":{"type":"enabled","budget_tokens":1024}`,
		`"temperature":"private"`, `"temperature":-1`, `"temperature":3`, `"top_p":2`, `"top_k":-1`,
		`"stream":"private"`, `"stream":null`, `"max_output_tokens":16`, `"max_completion_tokens":1`,
	} {
		body := `{"model":"captured","max_tokens":1,` + extra + `,"messages":[{"role":"user","content":"1+1=? control:0123456789abcdef"}]}`
		if err := validateControlPrompt(model.EndpointMessages, []byte(body), "0123456789abcdef"); err == nil {
			t.Fatalf("invalid control option accepted: %s", extra)
		}
	}
	for _, limit := range []string{"0", "-1", "1.5", "2147483648", `"private"`, "null"} {
		body := `{"model":"captured","max_tokens":` + limit + `,"messages":[{"role":"user","content":"1+1=? control:0123456789abcdef"}]}`
		if err := validateControlPrompt(model.EndpointMessages, []byte(body), "0123456789abcdef"); err == nil {
			t.Fatalf("invalid output bound accepted: %s", limit)
		}
	}
}

func TestProbeCLIModelCannotInjectControlTemplateOrCredentials(t *testing.T) {
	for _, modelName := range []string{"{{UPSTREAM_API_KEY}}", "synthetic-cli-control-fixture-credential"} {
		t.Run(modelName, func(t *testing.T) {
			root := cliPrivateRepository(t)
			manifest := writeControlPair(t, root, nil)
			sends := 0
			code := runProbeCLI([]string{"probe-one", "--name", "fixture", "--online", "--accept-probe-cost", "--accept-control-replay", "--control-manifest", manifest, "--base-url", "http://127.0.0.1:9", "--key-env", "KEY", "--claude-model", modelName}, nil, io.Discard, io.Discard,
				probeCLIDeps{repoRoot: root, transport: roundTripFunc(func(*http.Request) (*http.Response, error) { sends++; return nil, io.EOF }), getenv: func(string) string { return "synthetic-cli-control-fixture-credential" }})
			if code == exitOK || sends != 0 {
				t.Fatalf("model input reached transport with template/credential: code=%d sends=%d", code, sends)
			}
		})
	}
}
