// Package security implements P3 passive content scanning and Security Center DTO.
//
// Scanners never modify forwarded bytes (§14). Findings are plain text only.
package security

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

// Severity of a Finding.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Finding is one passive observation.
type Finding struct {
	ID                string   `json:"id"`
	AtMS              int64    `json:"at_ms"`
	Severity          Severity `json:"severity"`
	Category          string   `json:"category"`
	Summary           string   `json:"summary"`
	Detail            string   `json:"detail"`
	Upstream          string   `json:"upstream,omitempty"`
	RouteID           int64    `json:"route_id,omitempty"`
	ReqID             string   `json:"req_id,omitempty"`
	Source            string   `json:"source"` // passive | canary | smtp_test
	ScannerVersion    string   `json:"scanner_version,omitempty"`
	RuleVersion       string   `json:"rule_version,omitempty"`
	BytesScanned      int64    `json:"bytes_scanned,omitempty"`
	IncompleteReason  string   `json:"incomplete_reason,omitempty"`
}

// Center is the in-process Security Center store (bounded ring).
type Center struct {
	mu       sync.Mutex
	findings []Finding
	limit    int
	seq      uint64
}

// NewCenter constructs a bounded finding store.
func NewCenter(limit int) *Center {
	if limit < 1 {
		limit = 200
	}
	return &Center{limit: limit}
}

// Record appends a finding (plain text; caller must already redact secrets).
func (c *Center) Record(f Finding) Finding {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	if f.ID == "" {
		f.ID = time.Now().UTC().Format("20060102T150405") + "-" + itoa(c.seq)
	}
	if f.AtMS == 0 {
		f.AtMS = time.Now().UnixMilli()
	}
	if f.Source == "" {
		f.Source = "passive"
	}
	c.findings = append([]Finding{f}, c.findings...)
	if len(c.findings) > c.limit {
		c.findings = c.findings[:c.limit]
	}
	return f
}

// List returns newest-first findings, optionally filtered by severity.
func (c *Center) List(severity Severity, limit int) []Finding {
	c.mu.Lock()
	defer c.mu.Unlock()
	if limit <= 0 || limit > len(c.findings) {
		limit = len(c.findings)
	}
	out := make([]Finding, 0, limit)
	for _, f := range c.findings {
		if severity != "" && f.Severity != severity {
			continue
		}
		out = append(out, f)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// Count returns total retained findings.
func (c *Center) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.findings)
}

var (
	reScript    = regexp.MustCompile(`(?i)<\s*script\b`)
	reJSURL     = regexp.MustCompile(`(?i)\bjavascript\s*:`)
	reOnAttr    = regexp.MustCompile(`(?i)\bon[a-z]+\s*=`)
	rePromptInj = regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions`)
)

// ScanText runs passive rules on a text body. Does not mutate input.
func ScanText(text, sourceLabel string) []Finding {
	if text == "" {
		return nil
	}
	var out []Finding
	add := func(sev Severity, cat, summary string) {
		out = append(out, Finding{
			Severity: sev,
			Category: cat,
			Summary:  summary,
			Detail:   clip(text, 512),
			Source:   "passive",
		})
		_ = sourceLabel
	}
	if reScript.MatchString(text) {
		add(SeverityHigh, "xss_pattern", "检测到疑似 script 标签")
	}
	if reJSURL.MatchString(text) {
		add(SeverityMedium, "xss_pattern", "检测到 javascript: URL")
	}
	if reOnAttr.MatchString(text) {
		add(SeverityMedium, "xss_pattern", "检测到 HTML 事件属性")
	}
	if rePromptInj.MatchString(text) {
		add(SeverityMedium, "prompt_injection", "检测到常见提示注入措辞")
	}
	return out
}

func clip(s string, n int) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func itoa(v uint64) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = digits[v%10]
		v /= 10
	}
	return string(buf[i:])
}
