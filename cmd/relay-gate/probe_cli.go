// probe_cli.go — P0-16 在线/离线 Probe 对照 CLI。
//
// 在打开 Store、启动 worker 或 HTTP listener 之前由 main 分派。
// Key 只从 TSV/stdin 读取，从不作为子进程 argv。
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	exitOK           = 0
	exitFail         = 1
	exitUsage        = 2
	controlFreshness = 60 * time.Second
)

type probeFlags struct {
	cmd                 string
	online              bool
	acceptProbeCost     bool
	acceptControlReplay bool
	input               string
	name                string
	output              string
	report              string
	controlManifest     string
	unknownAuth         []string
	// 单站 flag 模式：不写 TSV 也能探。key 只从 --key-env 指名的环境变量读，
	// 不接受 key 本身作为 argv。
	baseURL     string
	keyEnv      string
	claudeModel string
	gptModel    string
}

type tsvRow struct {
	Alias        string
	BaseURL      string
	APIKey       string
	ClaudeModels []string
	GPTModels    []string
	Note         string
}

type controlEntry struct {
	Alias  string `json:"alias"`
	loaded *validatedControl

	Protocol     string `json:"protocol"`
	Endpoint     string `json:"endpoint"`
	FixturePath  string `json:"fixture_path"`
	ControlID    string `json:"control_id"`
	Nonce        string `json:"nonce"`
	CapturedAt   string `json:"captured_at"`
	CompletedAt  string `json:"completed_at"`
	HeaderSHA256 string `json:"header_sha256"`
	BodySHA256   string `json:"body_sha256"`
	BodyBytes    int    `json:"body_bytes"`
	Truncated    bool   `json:"truncated"`
	Source       string `json:"source"`
	SecretScan   string `json:"secret_scan_version"`
}

type controlManifest struct {
	Version string         `json:"version"`
	Entries []controlEntry `json:"entries"`
}

type probeResultRow struct {
	Alias                string              `json:"alias"`
	Endpoint             string              `json:"endpoint"`
	ModelAlias           string              `json:"model_alias,omitempty"`
	HTTPStatus           int                 `json:"http_status"`
	ConnectMS            int64               `json:"connect_ms,omitempty"`
	TTFTMS               int64               `json:"ttft_ms,omitempty"`
	DecisionSuccess      bool                `json:"decision_success"`
	DecisionReachable    bool                `json:"decision_reachable"`
	Capability           string              `json:"capability,omitempty"`
	ErrorClass           string              `json:"error_class,omitempty"`
	ControlStatus        string              `json:"control_status"`
	RequestHash          string              `json:"request_hash,omitempty"`
	RequestHashScope     string              `json:"request_hash_scope,omitempty"`
	ResponseHash         string              `json:"response_hash,omitempty"`
	ResponseHashScope    string              `json:"response_hash_scope,omitempty"`
	EstimatedTokens      int64               `json:"estimated_tokens,omitempty"`
	CompatOK             bool                `json:"compat_ok"`
	Control              *probeControlResult `json:"control,omitempty"`
	RecipeStorage        string              `json:"recipe_storage"`
	RecipeOrigin         string              `json:"recipe_origin"`
	RecipeVersionID      int64               `json:"recipe_version_id,omitempty"`
	AuthRevision         int64               `json:"auth_revision"`
	SentAtMS             int64               `json:"sent_at_ms"`
	ResponseHeaderAtMS   int64               `json:"response_header_at_ms"`
	FirstByteAtMS        int64               `json:"first_byte_at_ms"`
	FirstEventAtMS       int64               `json:"first_event_at_ms"`
	FirstSemanticAtMS    int64               `json:"first_semantic_at_ms"`
	DoneAtMS             int64               `json:"done_at_ms"`
	RequestBytes         int64               `json:"request_bytes"`
	ResponseBytes        int64               `json:"decoded_response_bytes"`
	EstimatedInputTokens int64               `json:"estimated_input_tokens"`
	ObservedOutputTokens int64               `json:"observed_output_tokens"`
	ExpectedCancel       bool                `json:"expected_cancel"`
}

type probeControlResult struct {
	Success              bool   `json:"success"`
	Status               int    `json:"status"`
	ErrorClass           string `json:"error_class"`
	SentAtMS             int64  `json:"sent_at_ms"`
	DoneAtMS             int64  `json:"done_at_ms"`
	RequestHash          string `json:"request_hash,omitempty"`
	ResponseHash         string `json:"observed_response_hash,omitempty"`
	EstimatedInputTokens int64  `json:"estimated_input_tokens"`
	ObservedOutputTokens int64  `json:"observed_output_tokens"`
	ExpectedCancel       bool   `json:"expected_cancel"`
}

type probeCLIDeps struct {
	transport http.RoundTripper
	now       func() time.Time
	repoRoot  string
	getenv    func(string) string
}

func runProbeCLI(args []string, stdin io.Reader, stdout, stderr io.Writer, deps probeCLIDeps) int {
	if deps.now == nil {
		deps.now = time.Now
	}
	if deps.getenv == nil {
		deps.getenv = os.Getenv
	}
	if deps.repoRoot == "" {
		if root, err := findRepoRoot(); err == nil {
			deps.repoRoot = root
		}
	}

	flags, err := parseProbeFlags(args)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return exitUsage
	}
	if len(flags.unknownAuth) > 0 {
		fmt.Fprintln(stderr, "未知授权 flag")
		return exitUsage
	}

	// 缺授权：零网络、不写假成功输出。
	if !flags.online || !flags.acceptProbeCost {
		fmt.Fprintln(stderr, "在线 Probe 需要同时提供 --online 与 --accept-probe-cost；未授权，不发送任何请求")
		if flags.controlManifest != "" && !flags.acceptControlReplay {
			fmt.Fprintln(stderr, "另：提供 --control-manifest 时还需要 --accept-control-replay")
		}
		return exitFail
	}
	if flags.controlManifest != "" && !flags.acceptControlReplay {
		fmt.Fprintln(stderr, "提供 --control-manifest 时必须同时提供 --accept-control-replay")
		return exitFail
	}

	var rows []tsvRow
	if flags.baseURL != "" {
		rows, err = rowFromFlags(flags, deps.getenv)
	} else {
		if flags.input == "-" {
			rows, err = loadTSV("-", stdin)
		} else {
			var data []byte
			data, err = readCLIPrivateFile(flags.input, deps.repoRoot, 4<<20)
			if err == nil {
				rows, err = loadTSV("-", bytes.NewReader(data))
			}
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, "输入校验失败；未发送任何请求")
		return exitFail
	}
	if err := validateProbeCLIRows(rows); err != nil {
		fmt.Fprintln(stderr, "站点 alias/凭据/候选校验失败；未发送任何请求")
		return exitFail
	}
	for _, path := range []string{flags.output, flags.report} {
		if path != "" {
			if _, err := privateCLIPath(path, deps.repoRoot, true); err != nil {
				fmt.Fprintln(stderr, errCLIPrivateInput)
				return exitFail
			}
		}
	}
	if flags.cmd == "probe-one" && flags.baseURL == "" {
		filtered := rows[:0]
		for _, r := range rows {
			if r.Alias == flags.name {
				filtered = append(filtered, r)
			}
		}
		if len(filtered) == 0 {
			fmt.Fprintln(stderr, "输入中找不到指定 alias")
			return exitFail
		}
		rows = filtered
	}

	var manifest *controlManifest
	if flags.controlManifest != "" {
		knownSecrets := make([]string, 0, len(rows))
		for _, row := range rows {
			knownSecrets = append(knownSecrets, row.APIKey)
		}
		manifest, err = loadControlManifest(flags.controlManifest, deps.repoRoot, deps.now(), knownSecrets...)
		if err != nil {
			fmt.Fprintln(stderr, errCLIPrivateInput)
			return exitFail
		}
	}

	runner, err := newProbeCLIRunner(context.Background(), rows, deps)
	if err != nil {
		fmt.Fprintln(stderr, "无法准备探活配置；未发送任何请求")
		return exitFail
	}
	defer runner.Close()
	if err := runner.prepareControls(context.Background(), manifest); err != nil {
		fmt.Fprintln(stderr, "无法准备 control；未发送任何请求")
		return exitFail
	}
	if err := runner.warnOnlineCost(stderr); err != nil {
		fmt.Fprintln(stderr, "无法计算请求预算；未发送任何请求")
		return exitFail
	}
	results := make([]probeResultRow, 0, len(runner.candidates))
	compatFail := false
	for _, candidate := range runner.candidates {
		res, err := runner.execute(context.Background(), candidate)
		if err != nil {
			fmt.Fprintln(stderr, "探活执行失败；详情不包含在公开输出中")
			return exitFail
		}
		results = append(results, res)
		if !res.DecisionSuccess || (manifest != nil && candidate.endpoint != "models" && !res.CompatOK) {
			compatFail = true
		}
		printProbeLine(stdout, res)
	}

	if flags.output != "" {
		if err := writeJSONFile(flags.output, deps.repoRoot, results); err != nil {
			fmt.Fprintln(stderr, "私有结果写入失败")
			return exitFail
		}
	}
	if flags.report != "" {
		if err := writeReport(flags.report, deps.repoRoot, results); err != nil {
			fmt.Fprintln(stderr, "私有报告写入失败")
			return exitFail
		}
	}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{
		"results": len(results),
		"trips":   runner.transports.trips.Load(),
	})
	if compatFail {
		return exitFail
	}
	return exitOK
}

// printProbeLine 给人看的逐端点结论。只打印 alias，不打印 base URL 或 key。
func printProbeLine(w io.Writer, r probeResultRow) {
	verdict := "FAIL"
	if r.DecisionSuccess {
		verdict = "PASS"
	}
	class := r.ErrorClass
	if class == "" {
		class = "-"
	}
	fmt.Fprintf(w, "%s\t%s\t%s\thttp=%d\tclass=%s\tmodel=%s\n",
		verdict, r.Alias, r.Endpoint, r.HTTPStatus, class, r.ModelAlias)
}

func rowFromFlags(flags probeFlags, getenv func(string) string) ([]tsvRow, error) {
	claude := splitModels(flags.claudeModel)
	gpt := splitModels(flags.gptModel)
	if len(claude) == 0 && len(gpt) == 0 {
		return nil, errors.New("--base-url 需要至少一个 --claude-model 或 --gpt-model")
	}
	key := ""
	if flags.keyEnv != "" {
		key = getenv(flags.keyEnv)
		if key == "" {
			return nil, fmt.Errorf("环境变量 %s 为空", flags.keyEnv)
		}
	}
	alias := flags.name
	if alias == "" {
		alias = "cli"
	}
	return []tsvRow{{Alias: alias, BaseURL: flags.baseURL, APIKey: key,
		ClaudeModels: claude, GPTModels: gpt}}, nil
}

func parseProbeFlags(args []string) (probeFlags, error) {
	if len(args) == 0 {
		return probeFlags{}, errors.New("缺少子命令")
	}
	f := probeFlags{cmd: args[0]}
	if f.cmd != "probe-one" && f.cmd != "probe-matrix" {
		return f, fmt.Errorf("未知子命令 %q", f.cmd)
	}
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--online":
			f.online = true
		case a == "--accept-probe-cost":
			f.acceptProbeCost = true
		case a == "--accept-control-replay":
			f.acceptControlReplay = true
		case a == "--input" && i+1 < len(args):
			i++
			f.input = args[i]
		case a == "--name" && i+1 < len(args):
			i++
			f.name = args[i]
		case a == "--output" && i+1 < len(args):
			i++
			f.output = args[i]
		case a == "--report" && i+1 < len(args):
			i++
			f.report = args[i]
		case a == "--control-manifest" && i+1 < len(args):
			i++
			f.controlManifest = args[i]
		case a == "--base-url" && i+1 < len(args):
			i++
			f.baseURL = args[i]
		case a == "--key-env" && i+1 < len(args):
			i++
			f.keyEnv = args[i]
		case a == "--claude-model" && i+1 < len(args):
			i++
			f.claudeModel = args[i]
		case a == "--gpt-model" && i+1 < len(args):
			i++
			f.gptModel = args[i]
		case strings.HasPrefix(a, "--accept-"):
			f.unknownAuth = append(f.unknownAuth, a)
		case strings.HasPrefix(a, "--"):
			return f, errors.New("未知 flag")
		default:
			return f, errors.New("意外参数")
		}
	}
	if f.input != "" && f.baseURL != "" {
		return f, errors.New("--input 与 --base-url 只能二选一")
	}
	if f.input == "" && f.baseURL == "" {
		return f, errors.New("需要 --input <tsv> 或 --base-url <url>")
	}
	if f.cmd == "probe-one" && f.baseURL == "" && f.name == "" {
		return f, errors.New("probe-one 需要 --name")
	}
	return f, nil
}

func loadTSV(path string, stdin io.Reader) ([]tsvRow, error) {
	var r io.Reader
	if path == "-" {
		r = stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	seen := map[string]struct{}{}
	var rows []tsvRow
	sc := bufio.NewScanner(r)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) < 5 {
			return nil, fmt.Errorf("第 %d 行列数不足（需要至少 5 列 Tab 分隔）", lineNo)
		}
		alias := strings.TrimSpace(cols[0])
		if alias == "" {
			continue
		}
		if _, ok := seen[alias]; ok {
			return nil, fmt.Errorf("重复 alias %q", alias)
		}
		seen[alias] = struct{}{}
		claude := splitModels(cols[3])
		gpt := splitModels(cols[4])
		if len(claude) == 0 && len(gpt) == 0 {
			return nil, fmt.Errorf("alias %q 的 claude/gpt 模型列都是 -", alias)
		}
		note := ""
		if len(cols) > 5 {
			note = cols[5]
		}
		rows = append(rows, tsvRow{
			Alias: alias, BaseURL: strings.TrimSpace(cols[1]), APIKey: cols[2],
			ClaudeModels: claude, GPTModels: gpt, Note: note,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errors.New("TSV 无有效行")
	}
	return rows, nil
}

func splitModels(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "-" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" && p != "-" {
			out = append(out, p)
		}
	}
	return out
}

func writeJSONFile(path, root string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := scanCLISecrets(data); err != nil {
		return fmt.Errorf("输出 secret scan: %w", err)
	}
	return writeCLIPrivateFile(path, root, data)
}

func writeReport(path, root string, rows []probeResultRow) error {
	var b strings.Builder
	b.WriteString("# P0 probe matrix\n\n")
	b.WriteString("| alias | endpoint | status | success | control | compat |\n|---|---|---|---|---|---|\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | %s | %d | %v | %s | %v |\n",
			r.Alias, r.Endpoint, r.HTTPStatus, r.DecisionSuccess, r.ControlStatus, r.CompatOK)
	}
	data := []byte(b.String())
	if err := scanCLISecrets(data); err != nil {
		return err
	}
	return writeCLIPrivateFile(path, root, data)
}

func findRepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("找不到 go.mod")
		}
		dir = parent
	}
}

func scanCLISecrets(data []byte) error {
	s := string(data)
	lower := strings.ToLower(s)
	if strings.Contains(lower, "authorization") && strings.Contains(s, "Bearer ") &&
		!strings.Contains(s, "{{secret:") {
		// 输出/manifest 不应含明文 Bearer；测试用 fake key 也禁止进报告。
		if strings.Contains(s, "sk-") || strings.Contains(s, "rk-") {
			return errors.New("high-entropy token")
		}
	}
	if strings.Contains(s, `C:\Users\`) || strings.Contains(s, "/home/") {
		return errors.New("user path")
	}
	return nil
}
