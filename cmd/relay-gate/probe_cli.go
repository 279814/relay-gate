// probe_cli.go — P0-16 在线/离线 Probe 对照 CLI。
//
// 在打开 Store、启动 worker 或 HTTP listener 之前由 main 分派。
// Key 只从 TSV/stdin 读取，从不作为子进程 argv。
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probe"
)

const (
	exitOK           = 0
	exitFail         = 1
	exitUsage        = 2
	controlFreshness = 60 * time.Second
)

type countingDialer struct {
	dials atomic.Int64
}

func (d *countingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.dials.Add(1)
	var nd net.Dialer
	return nd.DialContext(ctx, network, address)
}

type countingTransport struct {
	base   http.RoundTripper
	trips  atomic.Int64
	dialer *countingDialer
}

func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.trips.Add(1)
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

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
	Alias             string `json:"alias"`
	Endpoint          string `json:"endpoint"`
	ModelAlias        string `json:"model_alias,omitempty"`
	HTTPStatus        int    `json:"http_status"`
	ConnectMS         int64  `json:"connect_ms,omitempty"`
	TTFTMS            int64  `json:"ttft_ms,omitempty"`
	DecisionSuccess   bool   `json:"decision_success"`
	DecisionReachable bool   `json:"decision_reachable"`
	Capability        string `json:"capability,omitempty"`
	ErrorClass        string `json:"error_class,omitempty"`
	ControlStatus     string `json:"control_status"`
	RequestHash       string `json:"request_hash,omitempty"`
	ResponseHash      string `json:"response_hash,omitempty"`
	EstimatedTokens   int64  `json:"estimated_tokens,omitempty"`
	CompatOK          bool   `json:"compat_ok"`
}

type probeCLIDeps struct {
	transport http.RoundTripper
	now       func() time.Time
	repoRoot  string
}

func runProbeCLI(args []string, stdin io.Reader, stdout, stderr io.Writer, deps probeCLIDeps) int {
	if deps.now == nil {
		deps.now = time.Now
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
		fmt.Fprintf(stderr, "未知授权 flag: %s\n", strings.Join(flags.unknownAuth, ", "))
		return exitUsage
	}

	dialer := &countingDialer{}
	ct := &countingTransport{dialer: dialer, base: deps.transport}
	if ct.base == nil {
		ct.base = &http.Transport{
			Proxy:       http.ProxyFromEnvironment,
			DialContext: dialer.DialContext,
		}
	}

	// 缺授权：零网络、不写假成功输出。
	if !flags.online || !flags.acceptProbeCost {
		fmt.Fprintln(stderr, "在线 Probe 需要同时提供 --online 与 --accept-probe-cost；未授权，不发送任何请求")
		if flags.controlManifest != "" && !flags.acceptControlReplay {
			fmt.Fprintln(stderr, "另：提供 --control-manifest 时还需要 --accept-control-replay")
		}
		assertNoIO(flags)
		if ct.trips.Load() != 0 || dialer.dials.Load() != 0 {
			fmt.Fprintln(stderr, "内部错误：未授权路径产生了网络调用")
			return exitFail
		}
		return exitFail
	}
	if flags.controlManifest != "" && !flags.acceptControlReplay {
		fmt.Fprintln(stderr, "提供 --control-manifest 时必须同时提供 --accept-control-replay")
		assertNoIO(flags)
		if ct.trips.Load() != 0 || dialer.dials.Load() != 0 {
			return exitFail
		}
		return exitFail
	}

	rows, err := loadTSV(flags.input, stdin)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return exitFail
	}
	if flags.cmd == "probe-one" {
		filtered := rows[:0]
		for _, r := range rows {
			if r.Alias == flags.name {
				filtered = append(filtered, r)
			}
		}
		if len(filtered) == 0 {
			fmt.Fprintf(stderr, "输入中找不到 alias %q\n", flags.name)
			return exitFail
		}
		rows = filtered
	}

	var manifest *controlManifest
	if flags.controlManifest != "" {
		manifest, err = loadControlManifest(flags.controlManifest, deps.repoRoot)
		if err != nil {
			fmt.Fprintln(stderr, err.Error())
			return exitFail
		}
	}

	warnOnlineCost(stderr, rows, manifest)
	// 禁止跟随重定向：默认 Client 最多跟 10 次，会把上游 API key
	// 带到 Location 指向的另一台主机。与真实转发 / 探活 Executor 一样，
	// 302 等状态原样交给分类器，不发第二次请求。
	client := &http.Client{
		Transport: ct,
		Timeout:   120 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	results := make([]probeResultRow, 0)
	compatFail := false
	for _, row := range rows {
		endpoints := endpointsForRow(row)
		for _, ep := range endpoints {
			res := runOneProbe(client, row, ep, manifest, deps)
			results = append(results, res)
			if !res.CompatOK {
				compatFail = true
			}
		}
	}

	if err := writeJSONFile(flags.output, results); err != nil {
		fmt.Fprintln(stderr, err.Error())
		return exitFail
	}
	if flags.cmd == "probe-matrix" && flags.report != "" {
		if err := writeReport(flags.report, results); err != nil {
			fmt.Fprintln(stderr, err.Error())
			return exitFail
		}
	}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{
		"results": len(results),
		"trips":   ct.trips.Load(),
	})
	if compatFail {
		return exitFail
	}
	return exitOK
}

func assertNoIO(flags probeFlags) {
	// 故意不创建 output/report：未授权不得留下假成功文件。
	_ = flags
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
		case strings.HasPrefix(a, "--accept-"):
			f.unknownAuth = append(f.unknownAuth, a)
		case strings.HasPrefix(a, "--"):
			return f, fmt.Errorf("未知 flag %s", a)
		default:
			return f, fmt.Errorf("意外参数 %s", a)
		}
	}
	if f.cmd == "probe-one" && f.name == "" {
		return f, errors.New("probe-one 需要 --name")
	}
	if f.input == "" {
		return f, errors.New("需要 --input <tsv>")
	}
	if f.output == "" {
		return f, errors.New("需要 --output <json>")
	}
	if f.cmd == "probe-matrix" && f.report == "" {
		return f, errors.New("probe-matrix 需要 --report <md>")
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

func endpointsForRow(row tsvRow) []model.EndpointKind {
	eps := []model.EndpointKind{model.EndpointModels}
	if len(row.ClaudeModels) > 0 {
		eps = append(eps, model.EndpointMessages, model.EndpointCountTokens)
	}
	if len(row.GPTModels) > 0 {
		eps = append(eps, model.EndpointChatCompletions, model.EndpointResponses)
	}
	return eps
}

func warnOnlineCost(w io.Writer, rows []tsvRow, manifest *controlManifest) {
	bodyBytes := 0
	maxReq := 0
	protocols := map[string]struct{}{}
	for _, row := range rows {
		eps := endpointsForRow(row)
		maxReq += len(eps)
		for _, ep := range eps {
			protocols[string(ep)] = struct{}{}
		}
	}
	if manifest != nil {
		for _, e := range manifest.Entries {
			bodyBytes += e.BodyBytes
			protocols[e.Protocol] = struct{}{}
		}
	}
	fmt.Fprintf(w, "隐私警告：内容将发送给多个第三方站点。sites=%d protocols=%d max_requests=%d body_bytes≈%d estimated_tokens≈%d\n",
		len(rows), len(protocols), maxReq, bodyBytes, maxReq*32)
}

func loadControlManifest(path, repoRoot string) (*controlManifest, error) {
	if err := assertIgnoredPrivatePath(path, repoRoot); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("control manifest 不得是 symlink/reparse")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := scanCLISecrets(data); err != nil {
		return nil, fmt.Errorf("control manifest secret scan: %w", err)
	}
	var m controlManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m.Version == "" {
		return nil, errors.New("control manifest 缺少 version")
	}
	now := time.Now()
	for i, e := range m.Entries {
		if e.Truncated {
			return nil, fmt.Errorf("control entry %d truncated=true", i)
		}
		if e.FixturePath == "" || e.ControlID == "" || e.Nonce == "" {
			return nil, fmt.Errorf("control entry %d 缺字段", i)
		}
		completed, err := time.Parse(time.RFC3339, e.CompletedAt)
		if err != nil {
			return nil, fmt.Errorf("control entry %d completed_at: %w", i, err)
		}
		if now.Sub(completed) > controlFreshness {
			return nil, fmt.Errorf("control entry %d 超过 %s 新鲜度", i, controlFreshness)
		}
		fixPath := e.FixturePath
		if !filepath.IsAbs(fixPath) {
			fixPath = filepath.Join(filepath.Dir(path), fixPath)
		}
		if err := assertIgnoredPrivatePath(fixPath, repoRoot); err != nil {
			return nil, err
		}
	}
	return &m, nil
}

func findControl(manifest *controlManifest, endpoint model.EndpointKind) *controlEntry {
	if manifest == nil {
		return nil
	}
	for i := range manifest.Entries {
		e := &manifest.Entries[i]
		if e.Endpoint == string(endpoint) {
			return e
		}
	}
	return nil
}

func runOneProbe(client *http.Client, row tsvRow, endpoint model.EndpointKind,
	manifest *controlManifest, deps probeCLIDeps) probeResultRow {

	res := probeResultRow{
		Alias: row.Alias, Endpoint: string(endpoint), ControlStatus: "none",
	}
	entry := findControl(manifest, endpoint)
	if manifest != nil && entry == nil {
		res.ControlStatus = "control_missing"
		res.CompatOK = false
		// 无对应 control：仍可探测，但不得宣称与原生一致。
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	req, modelAlias, err := buildProbeRequest(ctx, row, endpoint, entry)
	if err != nil {
		res.ErrorClass = "config_error"
		res.CompatOK = false
		return res
	}
	res.ModelAlias = modelAlias
	reqHash := sha256.Sum256([]byte(req.URL.String() + "|" + string(endpoint)))
	res.RequestHash = hex.EncodeToString(reqHash[:8])

	start := deps.now()
	resp, err := client.Do(req)
	if err != nil {
		res.ErrorClass = "transport"
		res.CompatOK = false
		if entry != nil {
			res.ControlStatus = "control_ok_probe_fail"
		}
		return res
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	res.HTTPStatus = resp.StatusCode
	res.TTFTMS = deps.now().Sub(start).Milliseconds()
	respHash := sha256.Sum256(body)
	res.ResponseHash = hex.EncodeToString(respHash[:8])

	decision := classifyProbeResponse(endpoint, row, resp.StatusCode, resp.Header, body)
	res.DecisionSuccess = decision.Success
	res.DecisionReachable = decision.Reachable
	res.Capability = string(decision.Capability)
	res.ErrorClass = string(decision.ErrorClass)
	res.EstimatedTokens = decision.ObservedOutputTokens
	if entry != nil {
		res.ControlStatus = "paired"
	}
	// control 成功而 Probe 失败 → 门禁失败；两者失败不算兼容性回归。
	if entry != nil && !decision.Success {
		res.ControlStatus = "control_ok_probe_fail"
		res.CompatOK = false
		return res
	}
	if entry == nil {
		res.CompatOK = decision.Success // 无 control 时仅表示 Probe 自身，不宣称原生一致
		if manifest != nil {
			res.CompatOK = false
		}
		return res
	}
	res.CompatOK = decision.Success
	return res
}

func buildProbeRequest(ctx context.Context, row tsvRow, endpoint model.EndpointKind,
	entry *controlEntry) (*http.Request, string, error) {

	base := strings.TrimRight(row.BaseURL, "/")
	path := endpoint.CanonicalPath()
	if path == "" {
		return nil, "", fmt.Errorf("未知 endpoint %s", endpoint)
	}
	u, err := url.Parse(base + path)
	if err != nil {
		return nil, "", err
	}

	modelName := ""
	var body []byte
	method := endpoint.Method()
	switch endpoint {
	case model.EndpointModels:
		method = http.MethodGet
	case model.EndpointMessages, model.EndpointCountTokens:
		if len(row.ClaudeModels) == 0 {
			return nil, "", errors.New("无 claude 模型")
		}
		modelName = row.ClaudeModels[0]
		prompt := "1+1=?"
		if entry != nil && entry.Nonce != "" {
			prompt = "1+1=? control:" + entry.Nonce
		}
		payload := map[string]any{
			"model":      modelName,
			"max_tokens": 16,
			"messages":   []map[string]string{{"role": "user", "content": prompt}},
			"stream":     true,
		}
		if endpoint == model.EndpointCountTokens {
			delete(payload, "max_tokens")
			delete(payload, "stream")
		}
		body, _ = json.Marshal(payload)
	case model.EndpointChatCompletions, model.EndpointResponses:
		if len(row.GPTModels) == 0 {
			return nil, "", errors.New("无 gpt 模型")
		}
		modelName = row.GPTModels[0]
		prompt := "1+1=?"
		if entry != nil && entry.Nonce != "" {
			prompt = "1+1=? control:" + entry.Nonce
		}
		if endpoint == model.EndpointChatCompletions {
			body, _ = json.Marshal(map[string]any{
				"model": modelName, "stream": true, "max_tokens": 16,
				"messages": []map[string]string{{"role": "user", "content": prompt}},
			})
		} else {
			body, _ = json.Marshal(map[string]any{
				"model": modelName, "stream": true,
				"input": prompt,
			})
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	if row.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+row.APIKey)
		req.Header.Set("x-api-key", row.APIKey)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "relay-gate-probe-cli/1.0")
	return req, modelName, nil
}

func classifyProbeResponse(endpoint model.EndpointKind, row tsvRow,
	status int, header http.Header, body []byte) probe.Decision {

	protocol := model.Protocol("")
	switch endpoint {
	case model.EndpointMessages, model.EndpointCountTokens:
		protocol = model.ProtoAnthropic
	case model.EndpointModels:
		protocol = ""
	case model.EndpointChatCompletions:
		protocol = model.ProtoOpenAIChat
	case model.EndpointResponses:
		protocol = model.ProtoOpenAIResponses
	}
	_ = row

	clf := probe.NewResponseClassifier(probe.ObserveProbe, endpoint, status, header, time.Now())
	if status == 0 {
		return clf.Finish(nil, nil)
	}
	dec, err := probe.NewDecoder(probe.DecoderSpec{Endpoint: endpoint, Protocol: protocol},
		probe.WireAuto, 256<<10, 1<<20)
	if err != nil {
		return clf.Finish(err, nil)
	}
	events, feedErr := dec.Feed(body)
	for _, ev := range events {
		if _, done := clf.Observe(ev); done {
			return clf.Finish(feedErr, nil)
		}
	}
	more, finErr := dec.Finish()
	for _, ev := range more {
		if _, done := clf.Observe(ev); done {
			if finErr != nil {
				return clf.Finish(finErr, nil)
			}
			return clf.Finish(feedErr, nil)
		}
	}
	if finErr != nil {
		return clf.Finish(finErr, nil)
	}
	return clf.Finish(feedErr, nil)
}

func writeJSONFile(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := scanCLISecrets(data); err != nil {
		return fmt.Errorf("输出 secret scan: %w", err)
	}
	return os.WriteFile(path, data, 0o600)
}

func writeReport(path string, rows []probeResultRow) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
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
	return os.WriteFile(path, data, 0o600)
}

func assertIgnoredPrivatePath(path, repoRoot string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if repoRoot != "" {
		rel, err := filepath.Rel(repoRoot, abs)
		if err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("路径不在仓库内: %s", path)
		}
		rel = filepath.ToSlash(rel)
		ok := strings.HasPrefix(rel, ".local/p0/") ||
			rel == "scripts/upstreams.tsv" ||
			(strings.HasPrefix(rel, "scripts/") && strings.Contains(filepath.Base(rel), ".local."))
		if !ok {
			return fmt.Errorf("私有路径必须位于 .local/p0/ 或已忽略的 scripts 输入: %s", rel)
		}
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("拒绝 symlink/reparse")
	}
	return nil
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
