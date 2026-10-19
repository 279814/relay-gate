package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCaptureProducerEmitsControlAcceptedByTheRealCLIReader(t *testing.T) {
	powerShell, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell unavailable")
	}
	root := cliPrivateRepository(t)
	directory := filepath.Join(root, ".local", "p0", "controls")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	const key = "synthetic-cli-capture-fixture-credential"
	body := []byte(`{"model":"captured-model","max_tokens":1,"stream":true,"system":[{"type":"text","text":"Reply with 2 only.","cache_control":{"type":"ephemeral"}}],"metadata":{},"thinking":{"type":"disabled"},"stop_sequences":[],"temperature":0,"top_p":1,"top_k":1,"messages":[{"role":"user","content":"1+1=? control:0123456789abcdef"}]}`)
	request := map[string]any{"RequestLine": "POST /v1/messages?beta=true HTTP/1.1", "HeaderEntries": []map[string]any{{"Name": "x-api-key", "Values": []string{key}}, {"Name": "Content-Type", "Values": []string{"application/json"}}, {"Name": "Accept", "Values": []string{"application/json"}}, {"Name": "X-App", "Values": []string{"cli"}}, {"Name": "Accept", "Values": []string{"text/event-stream"}}}, "Headers": map[string][]string{"x-api-key": {key}, "content-type": {"application/json"}, "accept": {"application/json", "text/event-stream"}}, "BodyBase64": base64.StdEncoding.EncodeToString(body)}
	input := filepath.Join(directory, "request.local.json")
	data, _ := json.Marshal(request)
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	source, err := filepath.Abs(filepath.Join("..", "..", "scripts", "capture-claude-request.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	code := `. $env:CLI_CAPTURE_SOURCE
$request = Get-Content -LiteralPath $env:CLI_CAPTURE_INPUT -Raw | ConvertFrom-Json -AsHashtable
$request.Body = [Convert]::FromBase64String($request.BodyBase64)
$now = [DateTimeOffset]::UtcNow.ToString('O')
[byte[]]$content = ConvertTo-VerifiedControlEnvelope -Request $request -FakeKey $env:CLI_CAPTURE_KEY -Nonce '0123456789abcdef' -SourceVersion 'fixture-client' -CapturedAt $now -CompletedAt $now
[byte[]]$manifest = ConvertTo-ControlManifest -ControlContent $content -Alias 'fixture' -FixtureFileName 'control.json'
[Console]::Write(([ordered]@{ capture=[Convert]::ToBase64String($content); manifest=[Convert]::ToBase64String($manifest) } | ConvertTo-Json -Compress))
`
	script := filepath.Join(directory, "capture-test.ps1")
	if err := os.WriteFile(script, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(powerShell, "-NoProfile", "-NonInteractive", "-File", script)
	command.Env = append(os.Environ(), "CLI_CAPTURE_SOURCE="+source, "CLI_CAPTURE_INPUT="+input, "CLI_CAPTURE_KEY="+key)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("capture producer failed: %v %s", err, output)
	}
	if strings.Contains(string(output), key) {
		t.Fatal("capture retained its authentication credential")
	}
	var bundle struct {
		Capture  string `json:"capture"`
		Manifest string `json:"manifest"`
	}
	if err := json.Unmarshal(output, &bundle); err != nil {
		t.Fatal(err)
	}
	output, err = base64.StdEncoding.DecodeString(bundle.Capture)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(output), key) {
		t.Fatal("captured auth was not replaced with a typed placeholder")
	}
	var capture struct {
		HeaderSHA256 string `json:"header_sha256"`
		BodySHA256   string `json:"body_sha256"`
		BodyBytes    int    `json:"body_bytes"`
		CapturedAt   string `json:"captured_at"`
		CompletedAt  string `json:"completed_at"`
		Headers      []struct {
			Name   string   `json:"name"`
			Values []string `json:"values"`
		} `json:"headers"`
	}
	if err := json.Unmarshal(output, &capture); err != nil {
		t.Fatal(err)
	}
	if len(capture.Headers) != 5 || capture.Headers[2].Name != "Accept" || capture.Headers[3].Name != "X-App" || capture.Headers[4].Name != "Accept" || capture.Headers[2].Values[0] != "application/json" || capture.Headers[4].Values[0] != "text/event-stream" {
		t.Fatal("capture lost interleaved raw header order")
	}
	fixture := filepath.Join(directory, "control.json")
	if err := os.WriteFile(fixture, output, 0600); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(directory, "manifest.json")
	wire, err := base64.StdEncoding.DecodeString(bundle.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, wire, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadControlManifest(manifest, root, time.Now()); err != nil {
		t.Fatalf("real capture format cannot reach the CLI: %v", err)
	}
}

func TestCaptureProducerRejectsUnknownAndBusinessHeadersBeforeExport(t *testing.T) {
	powerShell, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell unavailable")
	}
	source, _ := filepath.Abs(filepath.Join("..", "..", "scripts", "capture-claude-request.ps1"))
	for _, header := range []struct{ name, value string }{{"X-Private-Project", "private"}, {"User-Agent", "claude-cli/2.1.220 private"}, {"Content-Type", "application/json; private=business"}, {"X-Stainless-Os", "private"}} {
		t.Run(header.name, func(t *testing.T) {
			command := exec.Command(powerShell, "-NoProfile", "-NonInteractive", "-Command", `. $env:CLI_CAPTURE_SOURCE
$request = @{ RequestLine='POST /v1/messages HTTP/1.1'; HeaderEntries=@(@{Name='x-api-key';Values=@('synthetic-capture-key')},@{Name=$env:CLI_CAPTURE_HEADER;Values=@($env:CLI_CAPTURE_VALUE)}); Body=[Text.Encoding]::UTF8.GetBytes('{"model":"captured-model","max_tokens":1,"messages":[{"role":"user","content":"1+1=? control:0123456789abcdef"}]}') }
$now=[DateTimeOffset]::UtcNow.ToString('O')
[void](ConvertTo-VerifiedControlEnvelope -Request $request -FakeKey 'synthetic-capture-key' -Nonce '0123456789abcdef' -SourceVersion 'fixture-client' -CapturedAt $now -CompletedAt $now)
`)
			command.Env = append(os.Environ(), "CLI_CAPTURE_SOURCE="+source, "CLI_CAPTURE_HEADER="+header.name, "CLI_CAPTURE_VALUE="+header.value)
			if output, err := command.CombinedOutput(); err == nil {
				t.Fatalf("producer exported unchecked header: %s", output)
			}
		})
	}
}

func TestCaptureProducerRejectsBusinessFieldsBeforeExport(t *testing.T) {
	powerShell, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell unavailable")
	}
	source, err := filepath.Abs(filepath.Join("..", "..", "scripts", "capture-claude-request.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"system":"private project"`, `"metadata":{"user_id":"private user"}`, `"thinking":{"type":"disabled","text":"private"}`, `"input":"private"`} {
		t.Run(field, func(t *testing.T) {
			body := []byte(`{"model":"captured-model","max_tokens":1,` + field + `,"messages":[{"role":"user","content":"1+1=? control:0123456789abcdef"}]}`)
			command := exec.Command(powerShell, "-NoProfile", "-NonInteractive", "-Command", `. $env:CLI_CAPTURE_SOURCE
$request = @{ RequestLine='POST /v1/messages?beta=true HTTP/1.1'; HeaderEntries=@(@{Name='x-api-key';Values=@('synthetic-capture-key')}); Body=[Convert]::FromBase64String($env:CLI_CAPTURE_BODY) }
$now=[DateTimeOffset]::UtcNow.ToString('O')
[void](ConvertTo-VerifiedControlEnvelope -Request $request -FakeKey 'synthetic-capture-key' -Nonce '0123456789abcdef' -SourceVersion 'fixture-client' -CapturedAt $now -CompletedAt $now)
`)
			command.Env = append(os.Environ(), "CLI_CAPTURE_SOURCE="+source, "CLI_CAPTURE_BODY="+base64.StdEncoding.EncodeToString(body))
			if output, err := command.CombinedOutput(); err == nil {
				t.Fatalf("producer exported unchecked business body: %s", output)
			}
		})
	}
}
