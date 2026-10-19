package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestProbeCLISharedControlPreservesOpenAIProtocolsAndCompressedWire(t *testing.T) {
	for _, test := range []struct{ protocol, endpoint, path, body, want string }{
		{"openai-responses", "responses", "/v1/responses", "{ \"model\":\"captured\", \"stream\":true,\"max_output_tokens\":16,\"input\":\"1+1=? control:0123456789abcdef\"}\n", "{ \"model\":\"target\", \"stream\":true,\"max_output_tokens\":16,\"input\":\"1+1=? control:0123456789abcdef\"}\n"},
		{"openai-chat", "chat_completions", "/v1/chat/completions", "{ \"model\":\"captured\", \"stream\":true,\"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":\"1+1=? control:0123456789abcdef\"}]}\n", "{ \"model\":\"target\", \"stream\":true,\"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":\"1+1=? control:0123456789abcdef\"}]}\n"},
	} {
		t.Run(test.endpoint, func(t *testing.T) {
			const key = "synthetic-openai-control-fixture-credential"
			root := cliPrivateRepository(t)
			manifest := writeControlPair(t, root, func(f, e map[string]any) {
				body := []byte(test.body)
				headers := json.RawMessage(`[{"name":"Content-Type","values":["application/json"]},{"name":"Authorization","values":["Bearer {{UPSTREAM_API_KEY}}"]},{"name":"Accept","values":["application/json","text/event-stream"]},{"name":"Accept-Encoding","values":["gzip"]}]`)
				for _, object := range []map[string]any{f, e} {
					object["protocol"] = test.protocol
					object["endpoint"] = test.endpoint
					object["source"] = "cc-switch-isolated"
				}
				f["request_target"] = test.path + "?mode=fixture"
				f["headers"] = headers
				f["body_base64"] = base64.StdEncoding.EncodeToString(body)
				e["header_sha256"] = controlDigest(headers)
				e["body_sha256"] = controlDigest(body)
				e["body_bytes"] = len(body)
			})
			var mu sync.Mutex
			var bodies []string
			models := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if r.Header.Get("Authorization") != "Bearer "+key || r.Header.Get("X-Api-Key") != "" {
					t.Error("control/probe bypassed canonical OpenAI Auth")
				}
				if r.URL.Path == test.path {
					mu.Lock()
					bodies = append(bodies, string(body))
					mu.Unlock()
				}
				var payload string
				switch r.URL.Path {
				case "/v1/models":
					mu.Lock()
					models++
					mu.Unlock()
					payload = `{"data":[]}`
				case "/v1/chat/completions":
					payload = `{"choices":[{"message":{"role":"assistant","content":"2"},"finish_reason":"stop"}]}`
				case "/v1/responses":
					payload = `{"object":"response","status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"2"}]}]}`
				default:
					t.Error("unexpected endpoint")
				}
				w.Header().Set("Content-Type", "application/json")
				if bytes.Contains(body, []byte("control:0123456789abcdef")) {
					if r.URL.RawQuery != "mode=fixture" || strings.Join(r.Header.Values("Accept"), ",") != "application/json,text/event-stream" || r.Header.Get("Accept-Encoding") != "gzip" {
						t.Error("native control headers/query changed")
					}
					w.Header().Set("Content-Encoding", "gzip")
					encoder := gzip.NewWriter(w)
					io.WriteString(encoder, payload)
					encoder.Close()
				} else {
					io.WriteString(w, payload)
				}
			}))
			defer server.Close()
			output := filepath.Join(root, ".local", "p0", "reports", "result.json")
			code := runProbeCLI([]string{"probe-one", "--name", "fixture", "--online", "--accept-probe-cost", "--accept-control-replay", "--control-manifest", manifest, "--base-url", server.URL, "--key-env", "KEY", "--gpt-model", "target", "--output", output}, nil, io.Discard, io.Discard,
				probeCLIDeps{repoRoot: root, getenv: func(string) string { return key }})
			mu.Lock()
			defer mu.Unlock()
			if models != 1 || len(bodies) != 2 || bodies[0] != test.want || strings.Contains(bodies[1], "control:") {
				t.Fatalf("wrong actual control/probe sends: models=%d bodies=%q", models, bodies)
			}
			data, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			var rows []probeResultRow
			if err := json.Unmarshal(data, &rows); err != nil {
				t.Fatal(err)
			}
			paired := false
			for _, row := range rows {
				if row.Endpoint == test.endpoint {
					paired = row.ControlStatus == "paired" && row.Control != nil && row.Control.Success && row.DecisionSuccess && row.CompatOK && row.ResponseHash != ""
				}
			}
			// The other declared OpenAI protocol has no native control. It must
			// remain missing even though its ordinary Probe itself succeeded.
			if !paired || code != exitFail {
				t.Fatalf("compressed native control was fabricated/lost: code=%d rows=%+v", code, rows)
			}
		})
	}
}
