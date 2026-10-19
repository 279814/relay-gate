package security

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"regexp"
	"regexp/syntax"
	"strings"

	"github.com/279814/relay-gate/internal/model"
)

var (
	reScript    = regexp.MustCompile(`(?i)<\s*script\b|\bjavascript\s*:|\bon[a-z]+\s*=`)
	reHTML      = regexp.MustCompile(`(?i)<!doctype\s+html|<html\b|<head\b|<body\b`)
	reLogin     = regexp.MustCompile(`(?i)<form\b|type\s*=\s*["']?password|sign\s*in|log\s*in|登录`)
	reAd        = regexp.MustCompile(`(?i)advertisement|sponsored|affiliate|广告|推广`)
	reInjection = regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions|disregard\s+(the\s+)?(system|previous)|override\s+(your\s+)?(system|instructions)|忽略.{0,12}(指令|规则)|绕过.{0,12}(限制|规则)`)
	reSensitive = regexp.MustCompile(`(?i)api[ _-]?key|password|credential|access[ _-]?token|system\s+prompt|private\s+(context|file|data)|\.ssh|id_rsa|环境变量|系统提示|私有上下文|凭据|密钥|密码`)
	reRequest   = regexp.MustCompile(`(?i)send|upload|paste|provide|reveal|print|disclose|show\s+(me|your)|发送|上传|粘贴|提供|泄露|显示`)
	reLink      = regexp.MustCompile(`(?i)https?://[^\s<>"'\x60\\]+`)
	reCommand   = regexp.MustCompile(`(?i)\b(curl|wget)\b.{0,200}\|\s*(sh|bash|powershell)|\b(rm\s+-rf|invoke-expression|iex\s*\(|downloadstring\s*\()`)
)

// Rule is compiled Go RE2 or a literal. It cannot execute scripts or callbacks.
// The scanner does not accept an unbounded list or unbounded patterns.
type Rule struct {
	ID, Category, Summary, Literal string
	Severity                       Severity
	re                             *regexp.Regexp
	pattern                        string
	workFactor                     int
}

func CompileRule(id, pattern, literal, category string, severity Severity) (Rule, error) {
	if id == "" || len(id) > 64 || category == "" || len(category) > 64 || (pattern == "") == (literal == "") || len(pattern) > MaxPatternBytes || len(literal) > MaxPatternBytes {
		return Rule{}, errors.New("invalid security rule: require one bounded RE2 pattern or literal")
	}
	if severity != SeverityInfo && severity != SeverityLow && severity != SeverityMedium && severity != SeverityHigh && severity != SeverityCritical {
		return Rule{}, errors.New("invalid security rule severity")
	}
	r := Rule{ID: id, Category: category, Severity: severity, Summary: "匹配本地安全规则 " + id, Literal: literal, pattern: pattern}
	if pattern != "" {
		var err error
		r.re, err = regexp.Compile(pattern)
		if err != nil {
			return Rule{}, errors.New("invalid security RE2 expression")
		}
		parsed, err := syntax.Parse(pattern, syntax.Perl)
		if err != nil {
			return Rule{}, errors.New("invalid security RE2 expression")
		}
		program, err := syntax.Compile(parsed.Simplify())
		if err != nil {
			return Rule{}, errors.New("invalid security RE2 expression")
		}
		r.workFactor = len(program.Inst)
	}
	return r, nil
}

func NewScanner(rules []Rule) (*Scanner, error) {
	if len(rules) > 64 {
		return nil, errors.New("too many security rules")
	}
	h := sha256.New()
	compiled := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		validated, err := CompileRule(rule.ID, rule.pattern, rule.Literal, rule.Category, rule.Severity)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, validated)
		h.Write([]byte(rule.ID + "\x00" + rule.Category + "\x00" + string(rule.Severity) + "\x00" + rule.pattern + "\x00" + rule.Literal + "\x00"))
	}
	version := RuleVersion
	if len(rules) > 0 {
		version += "-" + hex.EncodeToString(h.Sum(nil)[:8])
	}
	return &Scanner{rules: compiled, version: version, budget: ScanBudget, expandedLimit: MaxExpandedBytes}, nil
}

func (r *scanRun) inspectTextVisible(text, evidence string, depth int, visible string) {
	if text == "" || !r.spend(len(text)) {
		return
	}
	r.depth = max(r.depth, depth)
	r.credentialSignals(text, evidence, depth)
	if reScript.MatchString(text) {
		r.add(SeverityLow, "xss_pattern", "发现脚本/HTML 线索；单项不证明恶意", evidence)
	}
	html := reHTML.MatchString(visible)
	login := reLogin.MatchString(visible)
	injection := reInjection.MatchString(visible)
	sensitive := reSensitive.MatchString(visible) && reRequest.MatchString(visible)
	links := reLink.FindAllString(visible, 16)
	if html {
		severity := SeverityMedium
		if login || reScript.MatchString(visible) {
			severity = SeverityHigh
		}
		r.add(severity, "protocol_html", "响应包含协议外 HTML 文档/登录页", evidence)
	}
	if reAd.MatchString(visible) && (html || len(links) > 0) {
		r.add(SeverityMedium, "advertisement", "响应包含广告及跳转线索", evidence)
	}
	if injection {
		r.add(SeverityMedium, "prompt_injection", "检测到试图改变既有指令的措辞", evidence)
	}
	if sensitive {
		severity := SeverityMedium
		if injection || len(links) > 0 {
			severity = SeverityHigh
		}
		r.add(severity, "data_exfiltration", "响应索取凭据、系统提示或私有上下文", evidence)
	}
	if reCommand.MatchString(visible) {
		r.add(SeverityMedium, "command_instruction", "响应包含下载后执行或破坏性命令指令", evidence)
	}
	for _, link := range links {
		u, err := url.Parse(link)
		if err != nil {
			continue
		}
		host := strings.ToLower(u.Hostname())
		suspicious := sensitive || injection || u.User != nil || net.ParseIP(host) != nil || strings.HasPrefix(host, "xn--") || strings.HasSuffix(host, ".onion") || strings.Contains(u.RawQuery, "token=")
		if suspicious {
			r.add(SeverityMedium, "suspicious_link", "外链与敏感指令或异常目标同时出现", evidence)
		}
	}
	for _, rule := range r.scanner.rules {
		if !r.available() {
			return
		}
		// RE2 is linear, but its program size is the constant factor. Refuse
		// a large NFA/window product before starting an uninterruptible Match.
		if rule.re != nil && rule.workFactor > maxRegexWorkUnits/max(1, len(text)) {
			r.incomplete("regex_work_budget", true)
			continue
		}
		if rule.re != nil && rule.re.MatchString(text) || rule.Literal != "" && strings.Contains(text, rule.Literal) {
			r.add(rule.Severity, rule.Category, rule.Summary, evidence)
		}
	}
	for _, value := range decodedVariants(text) {
		if value.failed {
			r.incomplete("payload_decode_failed", false)
			continue
		}
		if value.hidden {
			r.add(SeverityLow, "unicode_hidden", "响应包含隐藏或双向控制 Unicode 字符", evidence)
		}
		if depth >= MaxDecodeDepth {
			r.incomplete("decode_depth_limit", true)
			continue
		}
		r.add(SeverityLow, "encoded_payload", "响应包含可解码或规范化的载荷", evidence)
		childVisible, _ := codeVisibility(value.text, false)
		if strings.TrimSpace(visible) == "" {
			childVisible = strings.Repeat(" ", len(value.text))
		}
		r.inspectTextVisible(value.text, evidence, depth+1, childVisible)
	}
}

func (r *scanRun) credentialSignals(text, evidence string, depth int) {
	redacted := RedactSecrets(text, r.input.Keys)
	if redacted != text {
		r.add(SeverityCritical, "credential_exposure", "响应包含已知 Credential", evidence)
		if depth > 0 && RedactSecrets(evidence, r.input.Keys) == evidence {
			r.hiddenCredential = true
		}
	}
	for _, key := range r.input.Keys {
		if len(key) >= 24 && (strings.Contains(text, key[:12]) || strings.Contains(text, key[len(key)-12:])) {
			r.add(SeverityHigh, "credential_fragment", "响应包含已知 Credential 片段", evidence)
		}
	}
}

func codeVisibility(text string, inFence bool) (string, bool) {
	var b strings.Builder
	b.Grow(len(text))
	for _, line := range strings.SplitAfter(text, "\n") {
		trimmed := strings.TrimSpace(line)
		fence := strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~")
		if fence || inFence {
			// Preserve byte positions for the scanner's windows; only the contextual
			// rules use this mask. Credential detection still sees original bytes.
			for range len(line) {
				b.WriteByte(' ')
			}
		} else {
			b.WriteString(line)
		}
		if fence {
			inFence = !inFence
		}
	}
	return b.String(), inFence
}

func safeEvidence(text string, keys []string) string {
	text = RedactSecrets(text, keys)
	for _, key := range keys {
		if len(key) < model.MinRedactableKeyLen {
			continue
		}
		if len(key) >= 24 {
			text = strings.ReplaceAll(text, key[:12], "[Credential片段]")
			text = strings.ReplaceAll(text, key[len(key)-12:], "[Credential片段]")
		}
	}
	return clip(text, 512)
}
