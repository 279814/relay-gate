// Package security implements P3 passive content scanning and Security Center DTO.
//
// Scanners never modify forwarded bytes (§14). Findings are plain text only.
package security

import (
	"crypto/rand"
	"encoding/hex"
	"net/url"
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
	ID               string   `json:"id"`
	AtMS             int64    `json:"at_ms"`
	Severity         Severity `json:"severity"`
	Category         string   `json:"category"`
	Summary          string   `json:"summary"`
	Detail           string   `json:"detail"`
	Upstream         string   `json:"upstream,omitempty"`
	RouteID          int64    `json:"route_id,omitempty"`
	ReqID            string   `json:"req_id,omitempty"`
	Source           string   `json:"source"` // passive | canary | smtp_test
	ScannerVersion   string   `json:"scanner_version,omitempty"`
	RuleVersion      string   `json:"rule_version,omitempty"`
	BytesScanned     int64    `json:"bytes_scanned,omitempty"`
	IncompleteReason string   `json:"incomplete_reason,omitempty"`
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
		f.ID = newFindingID(time.Now().UTC(), c.seq)
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

// newFindingID builds a durable finding id. The second-granularity clock plus
// per-process seq alone collide across restarts in the same UTC second
// (seq resets to 1); a random suffix keeps INSERT OR REPLACE from wiping an
// older security_finding row. Existing YYYYMMDDTHHMMSS-N ids remain valid.
func newFindingID(now time.Time, seq uint64) string {
	return now.UTC().Format("20060102T150405") + "-" + itoa(seq) + "-" + findingIDSuffix()
}

func findingIDSuffix() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Entropy failure is rare; nanoseconds still differ across process
		// restarts in the same wall-clock second for practical purposes.
		return itoa(uint64(time.Now().UnixNano()))
	}
	return hex.EncodeToString(b[:])
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
//
// keys are upstream/relay secrets known for this scan. They are redacted from
// Detail before the finding is returned so security_finding never stores the
// raw matched secret (§14.3 / §14.5 / §16.4). Scanning still uses the original
// text so pattern detection is unchanged.
func ScanText(text, sourceLabel string, keys ...string) []Finding {
	if text == "" {
		return nil
	}
	safeDetail := clip(redactSecrets(text, keys), 512)
	var out []Finding
	add := func(sev Severity, cat, summary string) {
		out = append(out, Finding{
			Severity: sev,
			Category: cat,
			Summary:  summary,
			Detail:   safeDetail,
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

// redactSecrets replaces known credential values in evidence text.
// Keep behavior aligned with store.MaskKey (security cannot import store:
// store already imports this package).
//
// Also replaces the url.QueryEscape form of each key (same one-pass encoding
// as sample.RedactText), plus the equivalent form with lowercase hex digits
// (%2f vs %2F) that some clients emit. Response bodies can echo query/URL
// text where the secret appears only percent-encoded; scanning still uses
// the original text.
//
// Also replaces the JSON \u00XX form of each key (one \u00XX per byte).
// Hex digits inside each \uXXXX are matched case-insensitively so lowercase
// (\u006b), uppercase (\u006B), and mixed per-unit forms are all removed.
// Observer scans raw response bytes, so a secret may appear only as those
// escapes inside a JSON string; the whole document is never decoded.
func redactSecrets(s string, keys []string) string {
	for _, k := range keys {
		if k == "" {
			continue
		}
		masked := maskSecret(k)
		s = strings.ReplaceAll(s, k, masked)
		if enc := url.QueryEscape(k); enc != k {
			s = strings.ReplaceAll(s, enc, masked)
			if lower := percentEncodingLowerHex(enc); lower != enc {
				s = strings.ReplaceAll(s, lower, masked)
			}
		}
		if esc := jsonByteUnicodeEscape(k); esc != k {
			s = replaceJSONUnicodeEscapedSecret(s, k, masked)
		}
	}
	return s
}

// replaceJSONUnicodeEscapedSecret replaces any hex-case variant of the
// JSON \u00XX-per-byte form of key with masked. Unrelated \u sequences are
// left untouched; the surrounding text is never decoded.
func replaceJSONUnicodeEscapedSecret(s, key, masked string) string {
	n := len(key)
	if n == 0 {
		return s
	}
	patLen := n * 6
	if len(s) < patLen {
		return s
	}
	var b strings.Builder
	matched := false
	for i := 0; i < len(s); {
		if i+patLen <= len(s) && matchJSONByteUnicodeEscape(s[i:i+patLen], key) {
			if !matched {
				b.Grow(len(s))
				b.WriteString(s[:i])
				matched = true
			}
			b.WriteString(masked)
			i += patLen
			continue
		}
		if matched {
			b.WriteByte(s[i])
		}
		i++
	}
	if !matched {
		return s
	}
	return b.String()
}

// matchJSONByteUnicodeEscape reports whether chunk is key encoded as one
// \u00XX per byte, with hex digits in either case.
func matchJSONByteUnicodeEscape(chunk, key string) bool {
	if len(chunk) != len(key)*6 {
		return false
	}
	for i := 0; i < len(key); i++ {
		off := i * 6
		if chunk[off] != '\\' || chunk[off+1] != 'u' {
			return false
		}
		c := key[i]
		if hexDigitVal(chunk[off+2]) != 0 || hexDigitVal(chunk[off+3]) != 0 ||
			hexDigitVal(chunk[off+4]) != c>>4 || hexDigitVal(chunk[off+5]) != c&0xf {
			return false
		}
	}
	return true
}

// hexDigitVal returns the 0–15 value of c, or 0xFF if c is not a hex digit.
func hexDigitVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 0xFF
	}
}

// jsonByteUnicodeEscape encodes each byte of s as \u00XX with lowercase hex
// (the style encoding/json uses for escaped bytes). Unrelated \u sequences
// are not invented; callers only ReplaceAll this exact form of a known key.
func jsonByteUnicodeEscape(s string) string {
	if s == "" {
		return ""
	}
	const hex = "0123456789abcdef"
	var b strings.Builder
	b.Grow(len(s) * 6)
	for i := 0; i < len(s); i++ {
		c := s[i]
		b.WriteString(`\u00`)
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0xf])
	}
	return b.String()
}

// jsonUnicodeEscapeUpperHex returns s with a–f hex digits inside \uXXXX
// sequences uppercased. Other bytes are unchanged so unrelated \u sequences
// are not invented or dropped.
func jsonUnicodeEscapeUpperHex(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if i+5 < len(s) && s[i] == '\\' && s[i+1] == 'u' &&
			isHexDigit(s[i+2]) && isHexDigit(s[i+3]) && isHexDigit(s[i+4]) && isHexDigit(s[i+5]) {
			b.WriteByte('\\')
			b.WriteByte('u')
			b.WriteByte(toUpperHexDigit(s[i+2]))
			b.WriteByte(toUpperHexDigit(s[i+3]))
			b.WriteByte(toUpperHexDigit(s[i+4]))
			b.WriteByte(toUpperHexDigit(s[i+5]))
			i += 6
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func toUpperHexDigit(c byte) byte {
	if c >= 'a' && c <= 'f' {
		return c - ('a' - 'A')
	}
	return c
}

// percentEncodingLowerHex returns s with A–F hex digits inside %XX sequences
// lowercased. Other bytes are unchanged so unrelated percent-sequences are
// not invented or dropped.
func percentEncodingLowerHex(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '%' && i+2 < len(s) && isHexDigit(s[i+1]) && isHexDigit(s[i+2]) {
			b.WriteByte('%')
			b.WriteByte(toLowerHexDigit(s[i+1]))
			b.WriteByte(toLowerHexDigit(s[i+2]))
			i += 3
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func toLowerHexDigit(c byte) byte {
	if c >= 'A' && c <= 'F' {
		return c + ('a' - 'A')
	}
	return c
}

func maskSecret(key string) string {
	const keep = 4
	if key == "" {
		return ""
	}
	if len(key) < keep*2+6 {
		return strings.Repeat("*", len(key))
	}
	return key[:keep] + "…" + key[len(key)-keep:]
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
