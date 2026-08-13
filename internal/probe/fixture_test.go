package probe

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

type fixtureManifest struct {
	Version int           `json:"version"`
	Source  fixtureSource `json:"source"`
	Cases   []fixtureCase `json:"cases"`
}

type fixtureSource struct {
	Kind             string `json:"kind"`
	Client           string `json:"client"`
	ClientVersion    string `json:"client_version"`
	MetadataRedacted bool   `json:"metadata_redacted"`
}

type fixtureCase struct {
	ID               string              `json:"id"`
	Protocol         string              `json:"protocol"`
	Endpoint         string              `json:"endpoint"`
	WireFormat       string              `json:"wire_format"`
	Status           int                 `json:"status"`
	Headers          map[string][]string `json:"headers"`
	RequestFile      string              `json:"request_file"`
	ResponseFile     string              `json:"response_file"`
	ChunkPlan        fixtureChunkPlan    `json:"chunk_plan"`
	ExpectedEvents   []fixtureEvent      `json:"expected_events"`
	ExpectedDecision fixtureDecision     `json:"expected_decision"`
}

type fixtureChunkPlan struct {
	Name string `json:"name"`
	Seed int64  `json:"seed,omitempty"`
}

type fixtureEvent struct {
	Type     string `json:"type"`
	Semantic bool   `json:"semantic,omitempty"`
	Error    bool   `json:"error,omitempty"`
}

type fixtureDecision struct {
	Success    bool   `json:"success"`
	Capability string `json:"capability"`
	ErrorClass string `json:"error_class"`
}

func loadFixtureManifest(root string) (*fixtureManifest, error) {
	f, err := os.Open(filepath.Join(root, "manifest.json"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var manifest fixtureManifest
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode fixture manifest: %w", err)
	}
	if err := validateFixtureManifest(root, &manifest); err != nil {
		return nil, fmt.Errorf("validate fixture manifest: %w", err)
	}
	return &manifest, nil
}

func validateFixtureManifest(root string, manifest *fixtureManifest) error {
	if manifest.Version != 1 {
		return fmt.Errorf("unsupported manifest version %d", manifest.Version)
	}
	if manifest.Source.Kind != "sanitized_control_reference" {
		return fmt.Errorf("unknown fixture source kind %q", manifest.Source.Kind)
	}
	if strings.TrimSpace(manifest.Source.Client) == "" {
		return fmt.Errorf("fixture source client must not be empty")
	}
	if strings.TrimSpace(manifest.Source.ClientVersion) == "" {
		return fmt.Errorf("fixture source client version must not be empty")
	}
	if !manifest.Source.MetadataRedacted {
		return fmt.Errorf("fixture source metadata must be redacted")
	}

	caseIDs := make(map[string]struct{}, len(manifest.Cases))
	for _, fixture := range manifest.Cases {
		if fixture.ID == "" {
			return fmt.Errorf("case id must not be empty")
		}
		if _, exists := caseIDs[fixture.ID]; exists {
			return fmt.Errorf("duplicate case id %q", fixture.ID)
		}
		caseIDs[fixture.ID] = struct{}{}

		switch fixture.Protocol {
		case "anthropic", "openai-responses", "openai-chat":
		case "":
			if fixture.Endpoint != "models" {
				return fmt.Errorf("case %q has empty protocol outside models endpoint", fixture.ID)
			}
		default:
			return fmt.Errorf("case %q has unknown protocol %q", fixture.ID, fixture.Protocol)
		}
		if err := validateFixtureEndpoint(fixture.Protocol, fixture.Endpoint); err != nil {
			return fmt.Errorf("case %q: %w", fixture.ID, err)
		}
		switch fixture.WireFormat {
		case "sse", "ndjson", "json":
		default:
			return fmt.Errorf("case %q has unknown wire format %q", fixture.ID, fixture.WireFormat)
		}
		if fixture.Status < 100 || fixture.Status > 599 {
			return fmt.Errorf("case %q has invalid HTTP status %d", fixture.ID, fixture.Status)
		}
		if len(fixture.Headers) == 0 {
			return fmt.Errorf("case %q must declare response headers", fixture.ID)
		}
		for name, values := range fixture.Headers {
			if strings.TrimSpace(name) == "" || len(values) == 0 {
				return fmt.Errorf("case %q has incomplete response headers", fixture.ID)
			}
			for _, value := range values {
				if strings.TrimSpace(value) == "" {
					return fmt.Errorf("case %q has empty response header value", fixture.ID)
				}
			}
		}
		if len(fixture.ExpectedEvents) == 0 {
			return fmt.Errorf("case %q must declare expected events", fixture.ID)
		}
		for _, event := range fixture.ExpectedEvents {
			if event.Type == "" {
				return fmt.Errorf("case %q has empty expected event type", fixture.ID)
			}
		}
		if !fixtureCapabilityValid(fixture.ExpectedDecision.Capability) || fixture.ExpectedDecision.ErrorClass == "" {
			return fmt.Errorf("case %q has invalid expected decision", fixture.ID)
		}
		if err := validateFixtureChunkPlan(fixture.ChunkPlan); err != nil {
			return fmt.Errorf("case %q: %w", fixture.ID, err)
		}

		if err := validateFixtureFile(root, "request file", fixture.RequestFile); err != nil {
			return fmt.Errorf("case %q: %w", fixture.ID, err)
		}
		if err := validateFixtureFile(root, "response file", fixture.ResponseFile); err != nil {
			return fmt.Errorf("case %q: %w", fixture.ID, err)
		}
	}
	return nil
}

func validateFixtureEndpoint(protocol, endpoint string) error {
	wantProtocol, known := map[string]string{
		"models":           "",
		"messages":         "anthropic",
		"responses":        "openai-responses",
		"chat_completions": "openai-chat",
		"count_tokens":     "anthropic",
	}[endpoint]
	if !known {
		return fmt.Errorf("unknown endpoint %q", endpoint)
	}
	if protocol != wantProtocol {
		return fmt.Errorf("endpoint %q requires protocol %q", endpoint, wantProtocol)
	}
	return nil
}

func fixtureCapabilityValid(capability string) bool {
	switch capability {
	case "unknown", "supported", "unsupported", "transient_error", "config_error":
		return true
	default:
		return false
	}
}

func validateFixtureChunkPlan(plan fixtureChunkPlan) error {
	switch plan.Name {
	case "whole", "single_byte", "crlf_boundary", "utf8_midpoint", "sse_multiline_data":
		return nil
	case "random":
		if plan.Seed == 0 {
			return fmt.Errorf("random chunk seed must be non-zero")
		}
		return nil
	default:
		return fmt.Errorf("unknown chunk plan %q", plan.Name)
	}
}

func splitFixtureResponse(body []byte, plan fixtureChunkPlan) ([]byte, [][]byte, error) {
	if err := validateFixtureChunkPlan(plan); err != nil {
		return nil, nil, err
	}

	wire := append([]byte(nil), body...)
	switch plan.Name {
	case "whole":
		return wire, [][]byte{wire}, nil
	case "single_byte":
		chunks := make([][]byte, 0, len(wire))
		for i := range wire {
			chunks = append(chunks, wire[i:i+1])
		}
		return wire, chunks, nil
	case "random":
		chunks := make([][]byte, 0, len(wire)/4+1)
		state := uint64(plan.Seed)
		for start := 0; start < len(wire); {
			state ^= state << 13
			state ^= state >> 7
			state ^= state << 17
			size := int(state%7) + 1
			end := min(start+size, len(wire))
			chunks = append(chunks, wire[start:end])
			start = end
		}
		return wire, chunks, nil
	case "crlf_boundary":
		wire = bytes.ReplaceAll(wire, []byte("\r\n"), []byte("\n"))
		wire = bytes.ReplaceAll(wire, []byte("\n"), []byte("\r\n"))
		index := bytes.Index(wire, []byte("\r\n"))
		if index < 0 {
			return nil, nil, fmt.Errorf("crlf_boundary fixture has no line ending")
		}
		return wire, splitFixtureAt(wire, index+1), nil
	case "utf8_midpoint":
		for index := 0; index < len(wire); {
			_, size := utf8.DecodeRune(wire[index:])
			if size > 1 {
				return wire, splitFixtureAt(wire, index+1), nil
			}
			index += size
		}
		return nil, nil, fmt.Errorf("utf8_midpoint fixture has no multibyte rune")
	case "sse_multiline_data":
		index := bytes.Index(wire, []byte("\ndata: "))
		if index < 0 {
			return nil, nil, fmt.Errorf("sse_multiline_data fixture has no second data line")
		}
		return wire, splitFixtureAt(wire, index+1), nil
	default:
		panic("validated chunk plan reached default branch")
	}
}

func splitFixtureAt(wire []byte, index int) [][]byte {
	return [][]byte{wire[:index], wire[index:]}
}

func validateFixtureFile(root, label, relative string) error {
	normalized := strings.ReplaceAll(relative, "\\", "/")
	if filepath.IsAbs(relative) || pathpkg.IsAbs(normalized) || hasWindowsVolumePrefix(normalized) {
		return fmt.Errorf("%s must be a relative path", label)
	}
	clean := pathpkg.Clean(normalized)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("%s contains parent traversal", label)
	}
	info, err := os.Stat(filepath.Join(root, filepath.FromSlash(clean)))
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", label)
	}
	return nil
}

func hasWindowsVolumePrefix(path string) bool {
	return len(path) >= 2 && ((path[0] >= 'a' && path[0] <= 'z') || (path[0] >= 'A' && path[0] <= 'Z')) && path[1] == ':'
}

var (
	highEntropyTokenPattern = regexp.MustCompile(`(?i)\b(?:sk|rk)-[A-Za-z0-9_-]{16,}\b`)
	authorizationPattern    = regexp.MustCompile(`(?i)"authorization"\s*:\s*\[?\s*"([^"]+)"`)
	xAPIKeyPattern          = regexp.MustCompile(`(?i)"x-api-key"\s*:\s*\[?\s*"([^"]+)"`)
	URLPattern              = regexp.MustCompile(`(?i)https?://[^\s"'<>]+`)
	windowsUserPathPattern  = regexp.MustCompile(`(?i)[a-z]:\\+(users|documents and settings)\\+`)
	unredactedMetaPattern   = regexp.MustCompile(`(?i)"metadata_redacted"\s*:\s*false`)
)

func scanFixtureSecrets(root string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("fixture symlink is not allowed: %s", fixtureRelativePath(root, path))
		}
		if entry.IsDir() {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative := fixtureRelativePath(root, path)
		if highEntropyTokenPattern.Match(content) {
			return fmt.Errorf("%s contains high-entropy token", relative)
		}
		if hasUnredactedHeaderValue(authorizationPattern, content) {
			return fmt.Errorf("%s contains authorization value", relative)
		}
		if hasUnredactedHeaderValue(xAPIKeyPattern, content) {
			return fmt.Errorf("%s contains x-api-key value", relative)
		}
		for _, raw := range URLPattern.FindAll(content, -1) {
			parsed, err := url.Parse(string(raw))
			if err != nil || !fixtureURLHostAllowed(parsed.Hostname()) {
				return fmt.Errorf("%s contains non-public URL", relative)
			}
		}
		if windowsUserPathPattern.Match(content) {
			return fmt.Errorf("%s contains Windows user path", relative)
		}
		if unredactedMetaPattern.Match(content) {
			return fmt.Errorf("%s contains unredacted metadata", relative)
		}
		return nil
	})
}

func hasUnredactedHeaderValue(pattern *regexp.Regexp, content []byte) bool {
	for _, match := range pattern.FindAllSubmatch(content, -1) {
		value := strings.TrimSpace(string(match[1]))
		if value != "" && !(strings.HasPrefix(value, "{{") && strings.HasSuffix(value, "}}")) {
			return true
		}
	}
	return false
}

func fixtureURLHostAllowed(host string) bool {
	host = strings.ToLower(host)
	return host == "localhost" || host == "127.0.0.1" || host == "::1" ||
		host == "example.com" || strings.HasSuffix(host, ".example.com") ||
		host == "example.invalid" || strings.HasSuffix(host, ".example.invalid")
}

func fixtureRelativePath(root, path string) string {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return "<fixture>"
	}
	return filepath.ToSlash(relative)
}

func TestFixtureManifestDeclaresInitialCases(t *testing.T) {
	manifest, err := loadFixtureManifest("testdata")
	if err != nil {
		t.Fatalf("load fixture manifest: %v", err)
	}
	if manifest.Version != 1 {
		t.Fatalf("manifest version = %d, want 1", manifest.Version)
	}

	wantIDs := []string{
		"anthropic_error_null_metadata",
		"anthropic_output_tokens_zero",
		"anthropic_ping_then_text",
		"anthropic_multiline_sse",
		"anthropic_200_error_event",
		"anthropic_eof_without_semantic",
		"anthropic_context_1m_required",
		"responses_output_text_delta",
		"responses_refusal_delta",
		"responses_200_error_json",
		"chat_chunk_delta",
		"ndjson_semantic_then_end",
		"plain_json_semantic",
		"count_tokens_supported",
		"count_tokens_404",
		"models_200",
		"models_404",
		"models_401",
		"models_503",
	}

	got := make(map[string]bool, len(manifest.Cases))
	for _, fixture := range manifest.Cases {
		got[fixture.ID] = true
	}
	for _, id := range wantIDs {
		if !got[id] {
			t.Errorf("manifest missing initial fixture %q", id)
		}
	}
	if len(manifest.Cases) != len(wantIDs) {
		t.Errorf("manifest contains %d cases, want exactly %d", len(manifest.Cases), len(wantIDs))
	}
}

func TestValidateFixtureManifestRejectsInvalidCases(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(root string, manifest *fixtureManifest)
		wantErr string
	}{
		{
			name: "unredacted source metadata",
			mutate: func(_ string, manifest *fixtureManifest) {
				manifest.Source.MetadataRedacted = false
			},
			wantErr: "source metadata",
		},
		{
			name: "unknown source kind",
			mutate: func(_ string, manifest *fixtureManifest) {
				manifest.Source.Kind = "live_private_capture"
			},
			wantErr: "source kind",
		},
		{
			name: "missing source client version",
			mutate: func(_ string, manifest *fixtureManifest) {
				manifest.Source.ClientVersion = ""
			},
			wantErr: "client version",
		},
		{
			name: "unknown protocol",
			mutate: func(_ string, manifest *fixtureManifest) {
				manifest.Cases[0].Protocol = "openai"
			},
			wantErr: "unknown protocol",
		},
		{
			name: "duplicate case id",
			mutate: func(_ string, manifest *fixtureManifest) {
				manifest.Cases = append(manifest.Cases, manifest.Cases[0])
			},
			wantErr: "duplicate case id",
		},
		{
			name: "missing response file",
			mutate: func(_ string, manifest *fixtureManifest) {
				manifest.Cases[0].ResponseFile = "responses/missing.bin"
			},
			wantErr: "response file",
		},
		{
			name: "absolute request path",
			mutate: func(root string, manifest *fixtureManifest) {
				manifest.Cases[0].RequestFile = filepath.Join(root, "requests", "request.json")
			},
			wantErr: "relative path",
		},
		{
			name: "foreign drive relative request path",
			mutate: func(_ string, manifest *fixtureManifest) {
				manifest.Cases[0].RequestFile = `Z:outside.json`
			},
			wantErr: "relative path",
		},
		{
			name: "foreign Unix absolute request path",
			mutate: func(_ string, manifest *fixtureManifest) {
				manifest.Cases[0].RequestFile = "/private/outside.json"
			},
			wantErr: "relative path",
		},
		{
			name: "parent path escape",
			mutate: func(_ string, manifest *fixtureManifest) {
				manifest.Cases[0].ResponseFile = "../outside.bin"
			},
			wantErr: "parent traversal",
		},
		{
			name: "foreign separator parent path escape",
			mutate: func(_ string, manifest *fixtureManifest) {
				manifest.Cases[0].ResponseFile = `..\outside.bin`
			},
			wantErr: "parent traversal",
		},
		{
			name: "empty case id",
			mutate: func(_ string, manifest *fixtureManifest) {
				manifest.Cases[0].ID = ""
			},
			wantErr: "case id",
		},
		{
			name: "unknown endpoint",
			mutate: func(_ string, manifest *fixtureManifest) {
				manifest.Cases[0].Endpoint = "completions"
			},
			wantErr: "unknown endpoint",
		},
		{
			name: "unknown wire format",
			mutate: func(_ string, manifest *fixtureManifest) {
				manifest.Cases[0].WireFormat = "text"
			},
			wantErr: "unknown wire format",
		},
		{
			name: "invalid status",
			mutate: func(_ string, manifest *fixtureManifest) {
				manifest.Cases[0].Status = 0
			},
			wantErr: "HTTP status",
		},
		{
			name: "missing headers",
			mutate: func(_ string, manifest *fixtureManifest) {
				manifest.Cases[0].Headers = nil
			},
			wantErr: "headers",
		},
		{
			name: "missing expected events",
			mutate: func(_ string, manifest *fixtureManifest) {
				manifest.Cases[0].ExpectedEvents = nil
			},
			wantErr: "expected events",
		},
		{
			name: "missing expected decision",
			mutate: func(_ string, manifest *fixtureManifest) {
				manifest.Cases[0].ExpectedDecision.Capability = ""
			},
			wantErr: "expected decision",
		},
		{
			name: "unknown chunk plan",
			mutate: func(_ string, manifest *fixtureManifest) {
				manifest.Cases[0].ChunkPlan.Name = "arbitrary"
			},
			wantErr: "chunk plan",
		},
		{
			name: "random chunk plan without seed",
			mutate: func(_ string, manifest *fixtureManifest) {
				manifest.Cases[0].ChunkPlan = fixtureChunkPlan{Name: "random"}
			},
			wantErr: "random chunk seed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixtureTestFile(t, root, "requests/request.json", []byte(`{"model":"fixture-model"}`))
			writeFixtureTestFile(t, root, "responses/response.bin", []byte(`{"ok":true}`))

			manifest := &fixtureManifest{
				Version: 1,
				Source: fixtureSource{
					Kind:             "sanitized_control_reference",
					Client:           "Claude Code",
					ClientVersion:    "fixture-version",
					MetadataRedacted: true,
				},
				Cases: []fixtureCase{{
					ID:               "valid_case",
					Protocol:         "anthropic",
					Endpoint:         "messages",
					WireFormat:       "json",
					Status:           200,
					Headers:          map[string][]string{"content-type": {"application/json"}},
					RequestFile:      "requests/request.json",
					ResponseFile:     "responses/response.bin",
					ChunkPlan:        fixtureChunkPlan{Name: "whole"},
					ExpectedEvents:   []fixtureEvent{{Type: "message", Semantic: true}},
					ExpectedDecision: fixtureDecision{Success: true, Capability: "supported", ErrorClass: "none"},
				}},
			}
			tc.mutate(root, manifest)

			err := validateFixtureManifest(root, manifest)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validate error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestLoadFixtureManifestRunsValidation(t *testing.T) {
	root := t.TempDir()
	writeFixtureTestFile(t, root, "requests/request.json", []byte(`{"model":"fixture-model"}`))
	writeFixtureTestFile(t, root, "responses/response.bin", []byte(`{"ok":true}`))

	manifest := fixtureManifest{
		Version: 1,
		Source: fixtureSource{
			Kind:             "sanitized_control_reference",
			Client:           "Claude Code",
			ClientVersion:    "fixture-version",
			MetadataRedacted: true,
		},
		Cases: []fixtureCase{{
			ID:               "unknown_protocol",
			Protocol:         "openai",
			Endpoint:         "messages",
			WireFormat:       "json",
			Status:           200,
			Headers:          map[string][]string{"content-type": {"application/json"}},
			RequestFile:      "requests/request.json",
			ResponseFile:     "responses/response.bin",
			ChunkPlan:        fixtureChunkPlan{Name: "whole"},
			ExpectedEvents:   []fixtureEvent{{Type: "message", Semantic: true}},
			ExpectedDecision: fixtureDecision{Success: true, Capability: "supported", ErrorClass: "none"},
		}},
	}
	content, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal fixture manifest: %v", err)
	}
	writeFixtureTestFile(t, root, "manifest.json", content)

	_, err = loadFixtureManifest(root)
	if err == nil || !strings.Contains(err.Error(), "unknown protocol") {
		t.Fatalf("load error = %v, want unknown protocol", err)
	}
}

func TestFixtureSecretScanRejectsSensitiveContent(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{"sk token", `{"value":"sk-` + strings.Repeat("A", 32) + `"}`, "high-entropy token"},
		{"rk token", `{"value":"rk-` + strings.Repeat("B", 32) + `"}`, "high-entropy token"},
		{"authorization value", `{"authorization":["Bearer fixture-secret-value"]}`, "authorization value"},
		{"x api key value", `{"x-api-key":["fixture-secret-value"]}`, "x-api-key value"},
		{"private upstream URL", `{"url":"https://private-upstream.test/v1/messages"}`, "non-public URL"},
		{"Windows user path", `{"cwd":"C:\\Users\\fixture-user\\project"}`, "Windows user path"},
		{"unredacted metadata", `{"metadata_redacted":false}`, "unredacted metadata"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixtureTestFile(t, root, "injected.json", []byte(tc.content))
			err := scanFixtureSecrets(root)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("scan error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestFixtureSecretScanAcceptsTrackedCorpus(t *testing.T) {
	if err := scanFixtureSecrets("testdata"); err != nil {
		t.Fatalf("tracked fixture corpus failed secret scan: %v", err)
	}
}

func TestPrivateProbeArtifactsStayOutOfGitAndDockerContexts(t *testing.T) {
	repositoryRoot := filepath.Clean(filepath.Join("..", ".."))
	privatePaths := []string{
		filepath.FromSlash(".local/p0/p0-fixture-private.txt"),
		filepath.FromSlash(".local/p0/reports/p0-fixture-private.md"),
		filepath.FromSlash(".vs/p0-fixture-private.txt"),
		filepath.FromSlash("scripts/upstreams.tsv"),
		filepath.FromSlash("scripts/p0-fixture.local.json"),
		filepath.FromSlash("docs/02-上游能力矩阵.md"),
	}
	for _, relative := range privatePaths {
		absolute := filepath.Join(repositoryRoot, relative)
		if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
			t.Fatalf("create private fixture directory: %v", err)
		}
		file, err := os.OpenFile(absolute, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil && !os.IsExist(err) {
			t.Fatalf("create private fixture %s: %v", relative, err)
		}
		if err == nil {
			if closeErr := file.Close(); closeErr != nil {
				t.Fatalf("close private fixture %s: %v", relative, closeErr)
			}
			t.Cleanup(func() { _ = os.Remove(absolute) })
		}

		command := exec.Command("git", "check-ignore", "--quiet", "--", filepath.ToSlash(relative))
		command.Dir = repositoryRoot
		if output, err := command.CombinedOutput(); err != nil {
			t.Errorf("git does not ignore %s: %v (%s)", relative, err, output)
		}
	}

	assertDockerContextExcludes(t, repositoryRoot, privatePaths)
}

func TestResponseFixtureGitAttributesPreserveWireBytes(t *testing.T) {
	repositoryRoot := filepath.Clean(filepath.Join("..", ".."))
	manifest, err := loadFixtureManifest("testdata")
	if err != nil {
		t.Fatal(err)
	}
	arguments := []string{"check-attr", "binary", "--"}
	for _, fixture := range manifest.Cases {
		arguments = append(arguments, filepath.ToSlash(filepath.Join("internal", "probe", "testdata", fixture.ResponseFile)))
	}
	command := exec.Command("git", arguments...)
	command.Dir = repositoryRoot
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("check response fixture attributes: %v (%s)", err, output)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if !strings.HasSuffix(strings.TrimSpace(line), ": binary: set") {
			t.Errorf("response fixture is not binary: %s", line)
		}
	}
}

func TestClaudeCaptureScriptFailsClosedAndProtectsOutput(t *testing.T) {
	powerShell, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh unavailable")
	}
	repositoryRoot, err := filepath.Abs(filepath.Clean(filepath.Join("..", "..")))
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(repositoryRoot, "scripts", "capture-claude-request.ps1")
	isolationRoot := t.TempDir()
	isolationWorkingDirectory := filepath.Join(isolationRoot, "neutral-cwd")
	if err := os.Mkdir(isolationWorkingDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	projectConfig := filepath.Join(isolationRoot, "CLAUDE.md")
	if err := os.WriteFile(projectConfig, []byte("fixture config"), 0o600); err != nil {
		t.Fatal(err)
	}
	ancestorCheck := fmt.Sprintf(
		". '%s'; Assert-NoClaudeProjectConfigAncestors -WorkingDirectory '%s'",
		quotePowerShellLiteral(script),
		quotePowerShellLiteral(isolationWorkingDirectory),
	)
	rootNormalizationCheck := fmt.Sprintf(
		". '%s'; $root = [IO.Path]::GetPathRoot((Get-Location).Path); $normalized = Get-NormalizedFullPath $root; if ($normalized -cne $root) { throw 'filesystem_root_changed' }",
		quotePowerShellLiteral(script),
	)
	if output, err := runPowerShellCommand(powerShell, repositoryRoot, rootNormalizationCheck); err != nil {
		t.Fatalf("filesystem root normalization changed the root: %v (%s)", err, output)
	}
	if output, err := runPowerShellCommand(powerShell, repositoryRoot, ancestorCheck); err == nil ||
		!strings.Contains(output, "claude_project_config_in_ancestor") {
		t.Fatalf("ancestor project config result = %v (%s)", err, output)
	}
	if err := os.Remove(projectConfig); err != nil {
		t.Fatal(err)
	}
	if output, err := runPowerShellCommand(powerShell, repositoryRoot, ancestorCheck); err != nil {
		t.Fatalf("neutral working directory rejected: %v (%s)", err, output)
	}
	missingHomeParent := filepath.Join(repositoryRoot, ".local", "p0")
	if err := os.MkdirAll(missingHomeParent, 0o700); err != nil {
		t.Fatal(err)
	}
	missingHomeWorkingDirectory, err := os.MkdirTemp(missingHomeParent, "home-unset-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(missingHomeWorkingDirectory) })
	missingHomeCheck := fmt.Sprintf(
		"Remove-Variable HOME -Force; . '%s'; Assert-NoClaudeProjectConfigAncestors -WorkingDirectory '%s'",
		quotePowerShellLiteral(script),
		quotePowerShellLiteral(missingHomeWorkingDirectory),
	)
	if output, err := runPowerShellCommand(powerShell, repositoryRoot, missingHomeCheck); err != nil {
		t.Fatalf("neutral working directory with missing HOME rejected: %v (%s)", err, output)
	}

	output, err := runCaptureScript(powerShell, repositoryRoot, script)
	if err != nil {
		t.Fatalf("default capture invocation: %v (%s)", err, output)
	}
	if strings.TrimSpace(output) != "capture_not_started" {
		t.Fatalf("default output = %q, want capture_not_started", output)
	}

	allowedRoot := filepath.Join(repositoryRoot, ".local", "p0", "captures")
	if err := os.MkdirAll(allowedRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	unique := fmt.Sprintf("fixture-%d-%d", os.Getpid(), time.Now().UnixNano())
	validTarget := filepath.Join(allowedRoot, unique+".json")
	t.Cleanup(func() { _ = os.Remove(validTarget) })

	common := []string{
		"-RepositoryRoot", repositoryRoot,
		"-AllowedRoot", allowedRoot,
		"-OutputPath", validTarget,
	}
	output, err = runCaptureScript(powerShell, repositoryRoot, script, append(common, "-ValidateTargetOnly")...)
	if err != nil {
		t.Fatalf("validate private capture target: %v (%s)", err, output)
	}
	if _, err := os.Stat(validTarget); !os.IsNotExist(err) {
		t.Fatalf("validation created output file: %v", err)
	}

	outsideTarget := filepath.Join(t.TempDir(), "outside.json")
	if output, err := runCaptureScript(
		powerShell,
		repositoryRoot,
		script,
		"-RepositoryRoot", repositoryRoot,
		"-AllowedRoot", allowedRoot,
		"-OutputPath", outsideTarget,
		"-ValidateTargetOnly",
	); err == nil {
		t.Fatalf("outside target accepted: %s", output)
	}

	existingTarget := filepath.Join(allowedRoot, unique+"-existing.json")
	if err := os.WriteFile(existingTarget, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(existingTarget) })
	if output, err := runCaptureScript(
		powerShell,
		repositoryRoot,
		script,
		"-RepositoryRoot", repositoryRoot,
		"-AllowedRoot", allowedRoot,
		"-OutputPath", existingTarget,
		"-ValidateTargetOnly",
	); err == nil {
		t.Fatalf("existing target accepted: %s", output)
	}

	if output, err := runCaptureScript(
		powerShell,
		repositoryRoot,
		script,
		"-RepositoryRoot", repositoryRoot,
		"-AllowedRoot", repositoryRoot,
		"-OutputPath", filepath.Join(repositoryRoot, "go.mod"),
		"-ValidateTargetOnly",
	); err == nil || !strings.Contains(output, "capture_target_is_tracked") {
		t.Fatalf("tracked target result = %v (%s)", err, output)
	}

	symlinkRoot := filepath.Join(allowedRoot, unique+"-link")
	if err := os.Symlink(t.TempDir(), symlinkRoot); err != nil {
		t.Logf("symlink/reparse assertion skipped: %v", err)
	} else {
		t.Cleanup(func() { _ = os.Remove(symlinkRoot) })
		if output, err := runCaptureScript(
			powerShell,
			repositoryRoot,
			script,
			"-RepositoryRoot", repositoryRoot,
			"-AllowedRoot", allowedRoot,
			"-OutputPath", filepath.Join(symlinkRoot, "capture.json"),
			"-ValidateTargetOnly",
		); err == nil {
			t.Fatalf("symlink target accepted: %s", output)
		}

		missingAllowedRoot := filepath.Join(symlinkRoot, "must-not-be-created")
		if output, err := runCaptureScript(
			powerShell,
			repositoryRoot,
			script,
			"-RepositoryRoot", repositoryRoot,
			"-AllowedRoot", missingAllowedRoot,
			"-OutputPath", filepath.Join(missingAllowedRoot, "capture.json"),
			"-ReservePrivateOutput",
		); err == nil {
			t.Fatalf("missing directory below symlink accepted: %s", output)
		}
		if _, err := os.Stat(missingAllowedRoot); !os.IsNotExist(err) {
			t.Fatalf("script wrote through symlink before validation: %v", err)
		}
	}

	output, err = runCaptureScript(powerShell, repositoryRoot, script, append(common, "-ReservePrivateOutput")...)
	if err != nil {
		t.Fatalf("reserve private output: %v (%s)", err, output)
	}
	info, err := os.Stat(validTarget)
	if err != nil {
		t.Fatalf("stat reserved output: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("reserved output size = %d, want 0", info.Size())
	}
	if os.PathSeparator != '\\' && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("reserved output permissions = %o, want user-only", info.Mode().Perm())
	}
	if output, err := runCaptureScript(powerShell, repositoryRoot, script, append(common, "-ReservePrivateOutput")...); err == nil {
		t.Fatalf("second atomic reservation succeeded: %s", output)
	}
	permissionTarget := filepath.Join(allowedRoot, unique+"-permission-failure.json")
	t.Cleanup(func() { _ = os.Remove(permissionTarget) })
	t.Setenv("RELAY_GATE_CAPTURE_TESTING", "1")
	t.Setenv("RELAY_GATE_CAPTURE_TEST_FAIL_PERMISSIONS", "1")
	if output, err := runCaptureScript(
		powerShell,
		repositoryRoot,
		script,
		"-RepositoryRoot", repositoryRoot,
		"-AllowedRoot", allowedRoot,
		"-OutputPath", permissionTarget,
		"-ReservePrivateOutput",
	); err == nil {
		t.Fatalf("permission failure was ignored: %s", output)
	}
	if _, err := os.Stat(permissionTarget); !os.IsNotExist(err) {
		t.Fatalf("permission failure left an output file: %v", err)
	}
	t.Setenv("RELAY_GATE_CAPTURE_TESTING", "")
	t.Setenv("RELAY_GATE_CAPTURE_TEST_FAIL_PERMISSIONS", "")

	if claude, err := exec.LookPath("claude"); err == nil {
		versionOutput, versionErr := exec.Command(claude, "--version").Output()
		if versionErr != nil {
			t.Fatalf("read Claude version: %v", versionErr)
		}
		versionFields := strings.Fields(string(versionOutput))
		if len(versionFields) == 0 {
			t.Fatal("Claude version output is empty")
		}
		if output, err := runCaptureScript(
			powerShell,
			repositoryRoot,
			script,
			"-ValidateIsolationOnly",
			"-ClaudePath", claude,
			"-ExpectedClaudeVersion", versionFields[0],
		); err != nil {
			t.Fatalf("validate wrapped Claude isolation help: %v (%s)", err, output)
		}

		unreviewedTarget := filepath.Join(allowedRoot, unique+"-unreviewed.json")
		t.Cleanup(func() { _ = os.Remove(unreviewedTarget) })
		if output, err := runCaptureScript(
			powerShell,
			repositoryRoot,
			script,
			"-RepositoryRoot", repositoryRoot,
			"-AllowedRoot", allowedRoot,
			"-OutputPath", unreviewedTarget,
			"-Execute",
			"-ClaudePath", claude,
			"-ExpectedClaudeVersion", "0.0.0-unreviewed",
		); err == nil {
			t.Fatalf("unreviewed Claude version started capture: %s", output)
		}
		if _, err := os.Stat(unreviewedTarget); !os.IsNotExist(err) {
			t.Fatalf("failed-closed capture created output: %v", err)
		}
	}

	if os.PathSeparator == '\\' {
		fakeClaude := buildFakeClaudeCaptureCLI(t)
		testStateRoot := t.TempDir()
		if err := os.WriteFile(filepath.Join(testStateRoot, "state.json"), []byte(`{"unchanged":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("RELAY_GATE_CAPTURE_TESTING", "1")
		t.Setenv("RELAY_GATE_CAPTURE_TEST_STATE_ROOT", testStateRoot)
		captureTarget := filepath.Join(allowedRoot, unique+"-control.json")
		t.Cleanup(func() { _ = os.Remove(captureTarget) })
		output, err := runCaptureScript(
			powerShell,
			repositoryRoot,
			script,
			"-RepositoryRoot", repositoryRoot,
			"-AllowedRoot", allowedRoot,
			"-OutputPath", captureTarget,
			"-Execute",
			"-ClaudePath", fakeClaude,
			"-ExpectedClaudeVersion", "2.1.220",
		)
		if err != nil {
			t.Fatalf("isolated control capture: %v (%s)", err, output)
		}
		if strings.TrimSpace(output) != "capture_completed" {
			t.Fatalf("capture output = %q, want capture_completed", output)
		}
		content, err := os.ReadFile(captureTarget)
		if err != nil {
			t.Fatal(err)
		}
		var capture struct {
			RequestLine            string `json:"request_line"`
			BodyBase64             string `json:"body_base64"`
			AuthenticationVerified bool   `json:"authentication_verified"`
		}
		if err := json.Unmarshal(content, &capture); err != nil {
			t.Fatalf("decode private capture envelope: %v", err)
		}
		body, err := base64.StdEncoding.DecodeString(capture.BodyBase64)
		if err != nil {
			t.Fatalf("decode private capture body: %v", err)
		}
		if !strings.HasPrefix(capture.RequestLine, "POST /v1/messages ") ||
			!capture.AuthenticationVerified ||
			!bytes.Contains(body, []byte("1+1=? control:")) {
			t.Fatal("private capture envelope did not preserve the verified control request")
		}

		swapRoot := filepath.Join(repositoryRoot, ".local", "p0", unique+"-swap-root")
		if err := os.MkdirAll(swapRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		swapDestination := t.TempDir()
		t.Cleanup(func() { _ = os.Remove(swapRoot) })
		t.Setenv("RELAY_GATE_FAKE_CLAUDE_SWAP_FROM", swapRoot)
		t.Setenv("RELAY_GATE_FAKE_CLAUDE_SWAP_TO", swapDestination)
		swapTarget := filepath.Join(swapRoot, "capture.json")
		output, err = runCaptureScript(
			powerShell,
			repositoryRoot,
			script,
			"-RepositoryRoot", repositoryRoot,
			"-AllowedRoot", swapRoot,
			"-OutputPath", swapTarget,
			"-Execute",
			"-ClaudePath", fakeClaude,
			"-ExpectedClaudeVersion", "2.1.220",
		)
		if err == nil {
			t.Fatalf("capture accepted a parent swapped after validation: %s", output)
		}
		if _, err := os.Stat(filepath.Join(swapDestination, "capture.json")); !os.IsNotExist(err) {
			t.Fatalf("capture wrote through swapped parent: %v", err)
		}
		t.Setenv("RELAY_GATE_FAKE_CLAUDE_SWAP_FROM", "")
		t.Setenv("RELAY_GATE_FAKE_CLAUDE_SWAP_TO", "")

		t.Setenv("RELAY_GATE_FAKE_CLAUDE_MUTATE_AND_FAIL", "1")
		changedTarget := filepath.Join(allowedRoot, unique+"-changed.json")
		t.Cleanup(func() { _ = os.Remove(changedTarget) })
		output, err = runCaptureScript(
			powerShell,
			repositoryRoot,
			script,
			"-RepositoryRoot", repositoryRoot,
			"-AllowedRoot", allowedRoot,
			"-OutputPath", changedTarget,
			"-Execute",
			"-ClaudePath", fakeClaude,
			"-ExpectedClaudeVersion", "2.1.220",
		)
		if err == nil || !strings.Contains(output, "claude_or_ccswitch_state_changed") {
			t.Fatalf("state-changing failed child result = %v (%s)", err, output)
		}
		if _, err := os.Stat(changedTarget); !os.IsNotExist(err) {
			t.Fatalf("state-changing failed child created output: %v", err)
		}
	}
}

func buildFakeClaudeCaptureCLI(t *testing.T) string {
	t.Helper()
	temporary := t.TempDir()
	source := filepath.Join(temporary, "main.go")
	executable := filepath.Join(temporary, "claude-fixture.exe")
	program := `package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	arguments := os.Args[1:]
	if len(arguments) == 1 && arguments[0] == "--version" {
		fmt.Println("2.1.220 (Claude Code fixture)")
		return
	}
	if len(arguments) == 1 && arguments[0] == "--help" {
		fmt.Println("--bare skip hooks, LSP, plugin sync, attribution, auto-memory, background prefetches, keychain reads, and CLAUDE.md auto-discovery")
		fmt.Println("--safe-mode --strict-mcp-config --settings --no-session-persistence")
		fmt.Println("--disable-slash-commands --tools --no-chrome --max-budget-usd")
		return
	}
	if len(arguments) == 0 {
		os.Exit(2)
	}
	prompt := arguments[len(arguments)-1]
	body := []byte(fmt.Sprintf(` + "`" + `{"model":"fixture","max_tokens":1,"stream":true,"messages":[{"role":"user","content":%q}]}` + "`" + `, prompt))
	request, err := http.NewRequest(http.MethodPost, strings.TrimRight(os.Getenv("ANTHROPIC_BASE_URL"), "/")+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		panic(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("x-api-key", os.Getenv("ANTHROPIC_API_KEY"))
	request.Header.Set("anthropic-version", "2023-06-01")
	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if from, to := os.Getenv("RELAY_GATE_FAKE_CLAUDE_SWAP_FROM"), os.Getenv("RELAY_GATE_FAKE_CLAUDE_SWAP_TO"); from != "" && to != "" {
		_ = os.Remove(from)
		_ = os.Symlink(to, from)
	}
	if os.Getenv("RELAY_GATE_FAKE_CLAUDE_MUTATE_AND_FAIL") == "1" {
		state := os.Getenv("RELAY_GATE_CAPTURE_TEST_STATE_ROOT")
		_ = os.WriteFile(state+"/state.json", []byte("changed"), 0600)
		os.Exit(4)
	}
	if response.StatusCode != http.StatusOK {
		os.Exit(3)
	}
}
`
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "build", "-o", executable, source)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build fake Claude CLI: %v (%s)", err, output)
	}
	return executable
}

func runCaptureScript(powerShell, repositoryRoot, script string, arguments ...string) (string, error) {
	commandArguments := []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-File", script}
	commandArguments = append(commandArguments, arguments...)
	command := exec.Command(powerShell, commandArguments...)
	command.Dir = repositoryRoot
	output, err := command.CombinedOutput()
	return string(output), err
}

func runPowerShellCommand(powerShell, repositoryRoot, commandText string) (string, error) {
	command := exec.Command(powerShell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", commandText)
	command.Dir = repositoryRoot
	output, err := command.CombinedOutput()
	return string(output), err
}

func quotePowerShellLiteral(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func assertDockerContextExcludes(t *testing.T, repositoryRoot string, privatePaths []string) {
	t.Helper()
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Log("docker executable unavailable; Docker context assertion deferred to CI")
		return
	}
	probeContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := exec.CommandContext(probeContext, docker, "info").Run(); err != nil {
		t.Logf("docker daemon unavailable; Docker context assertion deferred to CI: %v", err)
		return
	}

	temporary := t.TempDir()
	dockerfile := filepath.Join(temporary, "Dockerfile")
	if err := os.WriteFile(dockerfile, []byte("FROM scratch\nCOPY . /context\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outputRoot := filepath.Join(temporary, "output")
	buildContext, buildCancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer buildCancel()
	command := exec.CommandContext(
		buildContext,
		docker,
		"build",
		"--quiet",
		"--output", "type=local,dest="+outputRoot,
		"--file", dockerfile,
		".",
	)
	command.Dir = repositoryRoot
	command.Env = append(os.Environ(), "DOCKER_BUILDKIT=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("export Docker build context: %v (%s)", err, output)
	}
	for _, relative := range privatePaths {
		if _, err := os.Stat(filepath.Join(outputRoot, "context", relative)); !os.IsNotExist(err) {
			t.Errorf("Docker build context contains private path %s", relative)
		}
	}
}

func TestFixtureChunkPlansExerciseRequiredBoundaries(t *testing.T) {
	manifest, err := loadFixtureManifest("testdata")
	if err != nil {
		t.Fatalf("load fixture manifest: %v", err)
	}
	wantPlans := map[string]bool{
		"single_byte":        false,
		"random":             false,
		"crlf_boundary":      false,
		"utf8_midpoint":      false,
		"sse_multiline_data": false,
	}

	for _, fixture := range manifest.Cases {
		body, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(fixture.ResponseFile)))
		if err != nil {
			t.Fatalf("read %s: %v", fixture.ID, err)
		}
		wire, chunks, err := splitFixtureResponse(body, fixture.ChunkPlan)
		if err != nil {
			t.Fatalf("split %s: %v", fixture.ID, err)
		}
		if !bytes.Equal(bytes.Join(chunks, nil), wire) {
			t.Errorf("%s chunks do not reconstruct wire bytes", fixture.ID)
		}

		switch fixture.ChunkPlan.Name {
		case "single_byte":
			wantPlans["single_byte"] = true
			for i, chunk := range chunks {
				if len(chunk) != 1 {
					t.Errorf("%s chunk %d length = %d, want 1", fixture.ID, i, len(chunk))
				}
			}
		case "random":
			wantPlans["random"] = true
			if len(chunks) < 2 {
				t.Errorf("%s random plan produced %d chunk", fixture.ID, len(chunks))
			}
		case "crlf_boundary":
			wantPlans["crlf_boundary"] = true
			if !bytes.Contains(wire, []byte("\r\n")) || !hasChunkBoundary(chunks, '\r', '\n') {
				t.Errorf("%s does not split between CR and LF", fixture.ID)
			}
		case "utf8_midpoint":
			wantPlans["utf8_midpoint"] = true
			if !hasInvalidUTF8ChunkBoundary(wire, chunks) {
				t.Errorf("%s does not split inside a UTF-8 rune", fixture.ID)
			}
		case "sse_multiline_data":
			wantPlans["sse_multiline_data"] = true
			if !bytes.Contains(wire, []byte("\ndata: ")) || !hasChunkStartingWith(chunks[1:], []byte("data: ")) {
				t.Errorf("%s does not split SSE multiline data lines", fixture.ID)
			}
		}
	}

	for plan, seen := range wantPlans {
		if !seen {
			t.Errorf("fixture corpus does not exercise chunk plan %q", plan)
		}
	}
}

func hasChunkBoundary(chunks [][]byte, before, after byte) bool {
	for i := 0; i+1 < len(chunks); i++ {
		if len(chunks[i]) > 0 && len(chunks[i+1]) > 0 &&
			chunks[i][len(chunks[i])-1] == before && chunks[i+1][0] == after {
			return true
		}
	}
	return false
}

func hasInvalidUTF8ChunkBoundary(wire []byte, chunks [][]byte) bool {
	offset := 0
	for i := 0; i+1 < len(chunks); i++ {
		offset += len(chunks[i])
		if offset > 0 && offset < len(wire) && !utf8.Valid(wire[:offset]) {
			return true
		}
	}
	return false
}

func hasChunkStartingWith(chunks [][]byte, prefix []byte) bool {
	for _, chunk := range chunks {
		if bytes.HasPrefix(chunk, prefix) {
			return true
		}
	}
	return false
}

func writeFixtureTestFile(t *testing.T, root, relative string, content []byte) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create fixture test directory: %v", err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write fixture test file: %v", err)
	}
}
