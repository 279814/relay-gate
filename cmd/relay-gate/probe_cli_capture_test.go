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
	body := []byte(`{"model":"captured-model","max_tokens":1,"stream":true,"messages":[{"role":"user","content":"1+1=? control:0123456789abcdef"}]}`)
	request := map[string]any{"RequestLine": "POST /v1/messages?beta=true HTTP/1.1", "HeaderEntries": []map[string]any{{"Name": "x-api-key", "Values": []string{key}}, {"Name": "Content-Type", "Values": []string{"application/json"}}, {"Name": "X-Control-Test", "Values": []string{"one"}}, {"Name": "X-Between", "Values": []string{"literal"}}, {"Name": "X-Control-Test", "Values": []string{"two"}}}, "Headers": map[string][]string{"x-api-key": {key}, "content-type": {"application/json"}, "x-control-test": {"one", "two"}}, "BodyBase64": base64.StdEncoding.EncodeToString(body)}
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
	if len(capture.Headers) != 5 || capture.Headers[2].Name != "X-Control-Test" || capture.Headers[3].Name != "X-Between" || capture.Headers[4].Name != "X-Control-Test" {
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
