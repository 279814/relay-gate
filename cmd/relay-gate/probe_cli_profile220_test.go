package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

const testProfile220 = "claude-code-2.1.220-windows-isolated-v1"
const testProfile220SHA = "af5bf1f1b2aadffc768eccd787084c6fdf9ba81624cbe96c1c6d9ac1a1550231"

// This constructs a synthetic parser fixture, never evidence of a native run.
func writeProfile220Pair(t *testing.T, root string, mutate func(map[string]any, map[string]any, map[string]any)) (string, []byte) {
	t.Helper()
	var sample struct {
		Nonce   string                 `json:"nonce"`
		Body    json.RawMessage        `json:"body"`
		Headers []model.HeaderTemplate `json:"headers"`
	}
	data, err := os.ReadFile("testdata/control220-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &sample); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	body := regexp.MustCompile(`2026-10-23`).ReplaceAll(sample.Body, []byte(now.Format("2006-01-02")))
	fixture := map[string]any{
		"format_version": 3, "profile": testProfile220, "source_executable_sha256": testProfile220SHA,
		"source_version": "2.1.220 (Claude Code)", "protocol": "anthropic", "endpoint": "messages",
		"source": "claude-code-isolated", "control_id": sample.Nonce, "nonce": sample.Nonce,
		"captured_at": now.Add(-time.Second).Format(time.RFC3339), "completed_at": now.Format(time.RFC3339),
		"truncated": false, "authentication_verified": true,
		"isolation": map[string]bool{"configuration": true, "mcp": true, "hooks": true, "plugins": true, "environment": true, "temporary_workdir": true},
		"method":    "POST", "request_target": "/v1/messages?beta=true", "request_line": "POST /v1/messages?beta=true HTTP/1.1",
		"body_base64": base64.StdEncoding.EncodeToString(body), "headers": sample.Headers, "secret_scan_version": "1",
	}
	entry := map[string]any{"alias": "fixture", "profile": testProfile220, "protocol": "anthropic", "endpoint": "messages", "fixture_path": "native220.json", "control_id": sample.Nonce, "nonce": sample.Nonce, "captured_at": fixture["captured_at"], "completed_at": fixture["completed_at"], "truncated": false, "source": "claude-code-isolated", "secret_scan_version": "1"}
	manifest := map[string]any{"version": "2", "entries": []any{entry}}
	if mutate != nil {
		mutate(fixture, entry, manifest)
	}
	body, err = base64.StdEncoding.DecodeString(fixture["body_base64"].(string))
	if err != nil {
		t.Fatal(err)
	}
	headers := fixture["headers"].([]model.HeaderTemplate)
	for index := range headers {
		if strings.EqualFold(headers[index].Name, "Content-Length") {
			headers[index].Values = []string{strconv.Itoa(len(body))}
		}
	}
	headerJSON, err := json.Marshal(headers)
	if err != nil {
		t.Fatal(err)
	}
	fixture["headers"] = json.RawMessage(headerJSON)
	for _, value := range []map[string]any{fixture, entry} {
		value["header_sha256"], value["body_sha256"], value["body_bytes"] = controlDigest(headerJSON), controlDigest(body), len(body)
	}
	controls := filepath.Join(root, ".local", "p0", "controls")
	if err := os.MkdirAll(controls, 0700); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{"native220.json": fixture, "native-manifest.json": manifest} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(controls, name), encoded, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(controls, "native-manifest.json"), body
}

func TestNative220ProfilePreservesReviewedBody(t *testing.T) {
	root := cliPrivateRepository(t)
	path, body := writeProfile220Pair(t, root, nil)
	manifest, err := loadControlManifest(path, root, time.Now())
	if err != nil {
		t.Fatalf("reviewed synthetic schema rejected: %v", err)
	}
	if !bytes.Equal(manifest.Entries[0].loaded.body, body) {
		t.Fatal("validation reencoded the original body")
	}
}

func TestNative220ProducerAndReaderContract(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell unavailable")
	}
	root := cliPrivateRepository(t)
	manifestPath, original := writeProfile220Pair(t, root, nil)
	input := filepath.Join(filepath.Dir(manifestPath), "native220.json")
	source, err := filepath.Abs(filepath.Join("..", "..", "scripts", "capture-claude220-control.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-Command", `
. $env:PROFILE220_SOURCE -OutputPath unused -ManifestPath unused2 -Alias fixture -ClaudePath unused
$capture = Get-Content -LiteralPath $env:PROFILE220_INPUT -Raw | ConvertFrom-Json -AsHashtable
$entries=@($capture.headers | ForEach-Object { @{Name=$_.name;Values=@($_.values)} })
$request = @{ RequestLine=$capture.request_line; HeaderEntries=$entries; Body=[Convert]::FromBase64String($capture.body_base64) }
foreach ($h in $request.HeaderEntries) { if ($h.Name -ieq 'x-api-key') { $h.Values=@('synthetic-profile220-credential') } }
$now=[DateTimeOffset]::UtcNow.ToString('O')
[byte[]]$content=ConvertTo-Control220Envelope $request 'synthetic-profile220-credential' $capture.nonce $now $now
[byte[]]$manifest=ConvertTo-ControlManifest $content 'fixture' 'native220.json' -Profile $profile220
$rejects=0
foreach ($mutation in @('account','system','tools','date','duplicate','header')) {
    $changed=@{RequestLine=$request.RequestLine; HeaderEntries=$request.HeaderEntries; Body=$request.Body}
    $body=[Text.Encoding]::UTF8.GetString($request.Body) | ConvertFrom-Json -AsHashtable
    switch ($mutation) {
        'account' { $id=$body.metadata.user_id | ConvertFrom-Json -AsHashtable; $id.account_uuid='synthetic-private'; $body.metadata.user_id=$id | ConvertTo-Json -Compress }
        'system' { $body.system[1].text='synthetic-private' }
        'tools' { $body.tools=@(@{name='synthetic-private'}) }
        'date' { $body.messages[0].content[0].text += ' synthetic-private' }
        'header' { $changed.HeaderEntries=@($request.HeaderEntries)+@(@{Name='X-Private-Project';Values=@('synthetic-private')}) }
    }
    if ($mutation -eq 'duplicate') {
        $changed.Body=[Text.Encoding]::UTF8.GetBytes(('{"model":"synthetic-private",'+[Text.Encoding]::UTF8.GetString($request.Body).Substring(1)))
    } else { $changed.Body=[Text.Encoding]::UTF8.GetBytes(($body | ConvertTo-Json -Depth 16 -Compress)) }
    try { [void](ConvertTo-Control220Envelope $changed 'synthetic-profile220-credential' $capture.nonce $now $now) } catch { $rejects++ }
}

[Console]::Write((@{capture=[Convert]::ToBase64String($content);manifest=[Convert]::ToBase64String($manifest);rejects=$rejects} | ConvertTo-Json -Compress))
`)
	command.Env = append(os.Environ(), "PROFILE220_SOURCE="+source, "PROFILE220_INPUT="+input)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("producer failed: %v %s", err, output)
	}
	var result struct {
		Capture  string `json:"capture"`
		Manifest string `json:"manifest"`
		Rejects  int    `json:"rejects"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatal(err)
	}
	if result.Rejects != 6 {
		t.Fatalf("producer rejected %d of 6 unsafe fixtures", result.Rejects)
	}
	for path, encoded := range map[string]string{input: result.Capture, manifestPath: result.Manifest} {
		data, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("synthetic-profile220-credential")) {
			t.Fatal("producer leaked authentication")
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := loadControlManifest(manifestPath, root, time.Now())
	if err != nil {
		t.Fatalf("producer output rejected: %v", err)
	}
	if !bytes.Equal(manifest.Entries[0].loaded.body, original) {
		t.Fatal("producer reencoded native body")
	}
}

func TestNative220CaptureRejectsUnsafeLaunch(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("pinned producer is Windows only")
	}
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell unavailable")
	}
	source, err := filepath.Abs(filepath.Join("..", "..", "scripts", "capture-claude220-control.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, broad := range []bool{false, true} {
		t.Run(strconv.FormatBool(broad), func(t *testing.T) {
			root := cliPrivateRepository(t)
			if broad {
				if output, err := exec.Command("icacls.exe", filepath.Join(root, ".local", "p0"), "/grant", "*S-1-1-0:(RX)", "/Q").CombinedOutput(); err != nil {
					t.Fatalf("fixture ACL: %v %s", err, output)
				}
			}
			fakeExecutable := filepath.Join(root, "unreviewed.exe")
			if err := os.WriteFile(fakeExecutable, []byte("synthetic invalid executable"), 0600); err != nil {
				t.Fatal(err)
			}
			capture := filepath.Join(root, ".local", "p0", "controls", "capture.json")
			manifest := filepath.Join(root, ".local", "p0", "controls", "manifest.json")
			output, err := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-File", source, "-RepositoryRoot", root, "-OutputPath", capture, "-ManifestPath", manifest, "-Alias", "fixture", "-ClaudePath", fakeExecutable, "-Execute").CombinedOutput()
			want := "capture_executable_not_reviewed"
			if broad {
				want = "capture_parent_permissions_rejected"
			}
			if err == nil || strings.TrimSpace(string(output)) != want {
				t.Fatalf("unexpected rejection: %v %s", err, output)
			}
			for _, path := range []string{capture, manifest} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("rejected launch exported a control")
				}
			}
		})
	}
}

func changeProfile220Body(fn func(map[string]any)) func(map[string]any, map[string]any, map[string]any) {
	return func(f, _, _ map[string]any) {
		raw, _ := base64.StdEncoding.DecodeString(f["body_base64"].(string))
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		fn(body)
		raw, _ = json.Marshal(body)
		f["body_base64"] = base64.StdEncoding.EncodeToString(raw)
	}
}

func changeProfile220Identity(fn func(map[string]any)) func(map[string]any, map[string]any, map[string]any) {
	return changeProfile220Body(func(body map[string]any) {
		metadata := body["metadata"].(map[string]any)
		var identity map[string]any
		_ = json.Unmarshal([]byte(metadata["user_id"].(string)), &identity)
		fn(identity)
		encoded, _ := json.Marshal(identity)
		metadata["user_id"] = string(encoded)
	})
}

func TestNative220ProfileRejectsUnsafeContentBeforeSend(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any, map[string]any, map[string]any)
	}{
		{"old-manifest", func(_, _, m map[string]any) { m["version"] = "1" }},
		{"unknown-profile", func(_, e, _ map[string]any) { e["profile"] = "unknown" }},
		{"old-envelope", func(f, _, _ map[string]any) { f["format_version"] = 2 }},
		{"new-client", func(f, _, _ map[string]any) { f["source_version"] = "2.1.296 (Claude Code)" }},
		{"wrong-binary", func(f, _, _ map[string]any) { f["source_executable_sha256"] = strings.Repeat("0", 64) }},
		{"unreviewed-query", func(f, _, _ map[string]any) {
			f["request_target"] = "/v1/messages?beta=true&mode=fixture"
			f["request_line"] = "POST /v1/messages?beta=true&mode=fixture HTTP/1.1"
		}},
		{"test-capture", func(f, _, _ map[string]any) { f["test_mode"] = true }},
		{"null-account", changeProfile220Identity(func(m map[string]any) { m["account_uuid"] = nil })},
		{"missing-account", changeProfile220Identity(func(m map[string]any) { delete(m, "account_uuid") })},
		{"nonempty-account", changeProfile220Identity(func(m map[string]any) { m["account_uuid"] = "synthetic-private" })},
		{"nonderived-device", changeProfile220Identity(func(m map[string]any) { m["device_id"] = strings.Repeat("0", 64) })},
		{"nonderived-session", changeProfile220Identity(func(m map[string]any) { m["session_id"] = "00000000-0000-4000-8000-000000000000" })},
		{"extra-identity", changeProfile220Identity(func(m map[string]any) { m["extra"] = "synthetic-private" })},
		{"opaque-safeguards", changeProfile220Body(func(b map[string]any) { b["safeguards"] = []any{} })},
		{"tools", changeProfile220Body(func(b map[string]any) { b["tools"] = []any{map[string]any{"name": "synthetic-private"}} })},
		{"null-tools", changeProfile220Body(func(b map[string]any) { b["tools"] = nil })},
		{"output-budget", changeProfile220Body(func(b map[string]any) { b["max_tokens"] = 65 })},
		{"thinking", changeProfile220Body(func(b map[string]any) { b["thinking"] = map[string]any{"type": "adaptive"} })},
		{"effort", changeProfile220Body(func(b map[string]any) { b["output_config"] = map[string]any{"effort": "high"} })},
		{"private-metadata", changeProfile220Body(func(b map[string]any) { b["metadata"] = map[string]any{"user_id": "synthetic-private"} })},
		{"private-system", changeProfile220Body(func(b map[string]any) { b["system"].([]any)[1].(map[string]any)["text"] = "synthetic-private" })},
		{"extra-system", changeProfile220Body(func(b map[string]any) {
			b["system"] = append(b["system"].([]any), map[string]any{"type": "text", "text": "synthetic-private"})
		})},
		{"private-message", changeProfile220Body(func(b map[string]any) {
			b["messages"].([]any)[0].(map[string]any)["content"].([]any)[1].(map[string]any)["text"] = "synthetic-private"
		})},
		{"timeout-header", func(f, _, _ map[string]any) {
			hs := f["headers"].([]model.HeaderTemplate)
			for i := range hs {
				if strings.EqualFold(hs[i].Name, "X-Stainless-Timeout") {
					hs[i].Values = []string{"601"}
				}
			}
		}},
		{"session-header", func(f, _, _ map[string]any) {
			hs := f["headers"].([]model.HeaderTemplate)
			for i := range hs {
				if strings.EqualFold(hs[i].Name, "X-Claude-Code-Session-Id") {
					hs[i].Values = []string{"00000000-0000-4000-8000-000000000000"}
				}
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := cliPrivateRepository(t)
			manifest, _ := writeProfile220Pair(t, root, tc.mutate)
			calls := 0
			out := filepath.Join(root, ".local", "p0", "reports", "result.json")
			var stdout, stderr bytes.Buffer
			code := runProbeCLI([]string{"probe-one", "--name", "fixture", "--online", "--accept-probe-cost", "--accept-control-replay", "--control-manifest", manifest, "--base-url", "http://127.0.0.1:1", "--key-env", "FIXTURE_KEY", "--claude-model", "target-model", "--output", out}, nil, &stdout, &stderr,
				probeCLIDeps{repoRoot: root, transport: roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, io.EOF }), getenv: func(string) string { return "synthetic-native-profile-test-credential" }})
			if code == 0 || calls != 0 {
				t.Fatalf("unsafe control admitted: code=%d calls=%d", code, calls)
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatal("rejected control created a report")
			}
		})
	}
}

func TestControlProfileVersionBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		edit  func(map[string]any, map[string]any, map[string]any)
		valid bool
	}{
		{"legacy-v1", nil, true},
		{"legacy-v2-explicit", func(_, e, m map[string]any) { m["version"] = "2"; e["profile"] = "legacy-format2-v1" }, true},
		{"v1-null-profile", func(_, e, _ map[string]any) { e["profile"] = nil }, false},
		{"v1-empty-profile", func(_, e, _ map[string]any) { e["profile"] = "" }, false},
		{"v2-missing-profile", func(_, _, m map[string]any) { m["version"] = "2" }, false},
		{"legacy-null-capture-profile", func(f, _, _ map[string]any) { f["profile"] = nil }, false},
		{"legacy-empty-executable", func(f, _, _ map[string]any) { f["source_executable_sha256"] = "" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := cliPrivateRepository(t)
			path := writeControlPair(t, root, nil)
			var manifest, fixture map[string]any
			data, _ := os.ReadFile(path)
			if err := json.Unmarshal(data, &manifest); err != nil {
				t.Fatal(err)
			}
			fixturePath := filepath.Join(filepath.Dir(path), "control.json")
			data, _ = os.ReadFile(fixturePath)
			if err := json.Unmarshal(data, &fixture); err != nil {
				t.Fatal(err)
			}
			entry := manifest["entries"].([]any)[0].(map[string]any)
			if tc.edit != nil {
				tc.edit(fixture, entry, manifest)
			}
			for name, value := range map[string]any{path: manifest, fixturePath: fixture} {
				data, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := loadControlManifest(path, root, time.Now())
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
		})
	}
}

func TestNative220ProfileReplaysOriginalBytesWithSharedExecutor(t *testing.T) {
	root := cliPrivateRepository(t)
	manifest, original := writeProfile220Pair(t, root, nil)
	var mu sync.Mutex
	var bodies [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/messages" {
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			bodies = append(bodies, body)
			mu.Unlock()
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"2\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
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
	var stdout, stderr bytes.Buffer
	_ = runProbeCLI([]string{"probe-one", "--name", "fixture", "--online", "--accept-probe-cost", "--accept-control-replay", "--control-manifest", manifest, "--base-url", server.URL, "--key-env", "FIXTURE_KEY", "--claude-model", "target-model", "--output", filepath.Join(root, ".local", "p0", "reports", "result.json")}, nil, &stdout, &stderr, probeCLIDeps{repoRoot: root, getenv: func(string) string { return "synthetic-native-profile-test-credential" }})
	want := bytes.Replace(original, []byte(`"captured-model"`), []byte(`"target-model"`), 1)
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 || !bytes.Equal(bodies[0], want) {
		t.Fatalf("native control skipped or reencoded: sends=%d", len(bodies))
	}
}
