package security

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/279814/relay-gate/internal/protocol"
)

const (
	MaxEventBytes     = 256 << 10
	MaxExpandedBytes  = 4 << 20
	MaxDecodeDepth    = 2
	MaxPatternBytes   = 4 << 10
	maxRegexWorkUnits = 1 << 20
	ScanBudget        = 100 * time.Millisecond
	scanWindow        = 32 << 10
	scanOverlap       = 4 << 10
)

// Segment preserves wire offsets. A missing interval is never concatenated
// with another interval to create a fictitious event or cross-gap match.
type Segment struct {
	Offset int64
	Body   []byte
}

type RequestContext struct {
	ToolsKnown    bool
	AllowedTools  []string
	ExpectedNonce string
}

type ScanInput struct {
	Segments         []Segment
	TotalBytes       int64
	Encoding         string
	ContentType      string
	Spec             protocol.DecoderSpec // empty for the plain-text diagnostic API
	Context          RequestContext
	Keys             []string
	Source           string
	IncompleteReason string
}

// Scanner is immutable after construction. Each call owns its budgets, parser
// and findings; no response text is retained in the Scanner.
type Scanner struct {
	rules         []Rule
	version       string
	budget        time.Duration
	expandedLimit int
}

var defaultScanner = &Scanner{version: RuleVersion, budget: ScanBudget, expandedLimit: MaxExpandedBytes}

type scanRun struct {
	scanner          *Scanner
	input            ScanInput
	started          time.Time
	bytes            int64
	expanded         int
	depth            int
	truncated        bool
	reasons          map[string]bool
	found            map[string]Finding
	order            []string
	hiddenCredential bool
	textTails        map[string]string
	textFences       map[string]bool
	nonceSeen        bool
	toolNames        map[string]string
	toolOrder        []string
}

func (s *Scanner) Scan(input ScanInput) []Finding {
	if s == nil {
		s = defaultScanner
	}
	started := time.Now()
	var limited bool
	input.Keys, limited = boundedCredentials(input.Keys)
	r := &scanRun{scanner: s, input: input, started: started, reasons: map[string]bool{}, found: map[string]Finding{}}
	if limited {
		r.incomplete("credential_context_limit", true)
	}
	if input.IncompleteReason != "" {
		r.incomplete(input.IncompleteReason, true)
	}
	encoding := strings.ToLower(strings.TrimSpace(input.Encoding))
	if encoding != "" && encoding != "identity" {
		r.compressed(encoding)
	} else {
		var next int64
		for _, segment := range input.Segments {
			if segment.Offset != next {
				r.incomplete("capture_gap", true)
			}
			next = segment.Offset + int64(len(segment.Body))
		}
		segments := input.Segments
		if len(segments) > 1 {
			// Inspect the retained tail before a large prefix can exhaust the
			// time budget. Offsets, not slice adjacency, decide frame identity.
			segments = append([]Segment{segments[len(segments)-1]}, segments[:len(segments)-1]...)
		}
		for _, segment := range segments {
			if !r.available() {
				break
			}
			remaining := MaxScanBytes - int(r.bytes)
			data := segment.Body
			if len(data) > remaining {
				data = data[:remaining]
				r.incomplete("max_scan_bytes", true)
			}
			if len(data) == 0 {
				continue
			}
			r.bytes += int64(len(data))
			r.inspectBody(data, segment.Offset == 0)
		}
		if input.TotalBytes > int64(totalSegmentBytes(input.Segments)) {
			r.incomplete("capture_gap", true)
		}
		if input.TotalBytes > MaxScanBytes {
			r.incomplete("max_scan_bytes", true)
		}
	}
	return r.finish()
}

func totalSegmentBytes(segments []Segment) int {
	n := 0
	for _, s := range segments {
		n += len(s.Body)
	}
	return n
}

func (r *scanRun) compressed(encoding string) {
	// Only a contiguous prefix can feed a compression decoder. A compressed
	// suffix cannot independently recover decoded tail bytes.
	var prefix []byte
	var next int64
	for _, segment := range r.input.Segments {
		if segment.Offset != next {
			break
		}
		if len(prefix)+len(segment.Body) > MaxScanBytes {
			r.incomplete("encoded_limit", true)
			break
		}
		prefix = append(prefix, segment.Body...)
		next += int64(len(segment.Body))
	}
	if next < r.input.TotalBytes {
		r.incomplete("compressed_capture_gap", true)
	}
	reader, err := protocol.NewContentDecoder(encoding, bytes.NewReader(prefix), protocol.ContentCodingLimits{MaxEncodedBytes: MaxScanBytes, MaxDecodedBytes: MaxScanBytes, MaxWorkUnits: 4096})
	if err != nil {
		r.incomplete("content_decode_failed", false)
		return
	}
	defer reader.Close()
	var decoded bytes.Buffer
	buf := make([]byte, 16<<10)
	for r.available() {
		n, readErr := reader.Read(buf)
		if n > 0 {
			decoded.Write(buf[:n])
			r.bytes += int64(n)
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				reason := "content_decode_failed"
				if errors.Is(readErr, protocol.ErrDecodedBodyTooLarge) {
					reason = "max_scan_bytes"
				}
				if errors.Is(readErr, protocol.ErrEncodedBodyTooLarge) {
					reason = "encoded_limit"
				}
				r.incomplete(reason, true)
			}
			break
		}
	}
	if decoded.Len() > 0 {
		r.inspectBody(decoded.Bytes(), true)
	}
}

func (r *scanRun) inspectBody(data []byte, completePrefix bool) {
	if !utf8.Valid(data) {
		r.incomplete("invalid_utf8", false)
	}
	if r.input.Spec.Endpoint == "" {
		r.windows(string(data), 0)
		return
	}
	if !completePrefix {
		// A retained suffix has unknown frame/string context. Scan it only as
		// lexical evidence, never as a reconstructed protocol event.
		r.incomplete("protocol_segment_gap", true)
		r.windows(string(data), 0)
		return
	}
	format := protocol.DetectWireFormat(r.input.ContentType, data)
	eventLimit := int64(MaxEventBytes)
	if format == protocol.WireJSON {
		eventLimit = MaxScanBytes
	}
	decoder, err := protocol.NewDecoderWithPayloadSink(r.input.Spec, format, eventLimit, MaxScanBytes, func(v protocol.PayloadView) { r.payload(v) })
	if err != nil {
		r.incomplete("protocol_spec", false)
		r.windows(string(data), 0)
		return
	}
	for offset := 0; offset < len(data) && r.available(); {
		end := min(offset+(16<<10), len(data))
		_, err = decoder.Feed(data[offset:end])
		offset = end
		if err != nil {
			break
		}
	}
	if err == nil && r.available() {
		_, err = decoder.Finish()
	}
	if err != nil {
		reason := "protocol_decode_failed"
		if errors.Is(err, protocol.ErrEventTooLarge) {
			reason = "max_event_bytes"
		}
		r.incomplete(reason, errors.Is(err, protocol.ErrEventTooLarge))
		r.windows(string(data), 0)
	}
}

func (r *scanRun) windows(text string, depth int) {
	r.windowsWithFence(text, depth, false)
}

func (r *scanRun) windowsWithFence(text string, depth int, initiallyFenced bool) {
	if nonce := r.input.Context.ExpectedNonce; nonce != "" && len(nonce) <= 128 && strings.Contains(text, nonce) {
		r.nonceSeen = true
	}
	visible, _ := codeVisibility(text, initiallyFenced)
	// Inspect a real tail early. Visibility is derived before slicing so a long
	// code example cannot become protocol HTML just because its fence is outside
	// this rolling window.
	if len(text) > scanWindow && r.available() {
		start := len(text) - scanWindow
		r.inspectTextVisible(text[start:], text[start:], depth, visible[start:])
	}
	for offset := 0; offset < len(text) && r.available(); {
		end := min(offset+scanWindow, len(text))
		r.inspectTextVisible(text[offset:end], text[offset:end], depth, visible[offset:end])
		if end == len(text) {
			break
		}
		offset = end - scanOverlap
	}
}

func (r *scanRun) available() bool {
	if r.reasons["cpu_budget"] {
		return false
	}
	if time.Since(r.started) >= r.scanner.budget {
		r.incomplete("cpu_budget", true)
		return false
	}
	return true
}

func (r *scanRun) spend(n int) bool {
	if !r.available() {
		return false
	}
	if n > r.scanner.expandedLimit-r.expanded {
		r.incomplete("expanded_bytes", true)
		return false
	}
	r.expanded += n
	return true
}

func (r *scanRun) incomplete(reason string, truncated bool) {
	for _, part := range strings.Split(reason, ",") {
		if part != "" {
			r.reasons[part] = true
		}
	}
	r.truncated = r.truncated || truncated
}

func (r *scanRun) add(severity Severity, category, summary, detail string) {
	r.addRule("builtin:"+category, severity, category, summary, detail)
}

func (r *scanRun) addRule(ruleID string, severity Severity, category, summary, detail string) {
	if _, ok := r.found[ruleID]; ok {
		return
	}
	publicRuleID := ruleID
	if RedactSecrets(ruleID, r.input.Keys) != ruleID {
		publicRuleID = ""
	}
	r.found[ruleID] = Finding{RuleID: publicRuleID, Severity: severity, Category: category, Summary: safeEvidence(summary, r.input.Keys), Detail: safeEvidence(detail, r.input.Keys), Source: "passive"}
	r.order = append(r.order, ruleID)
}

func (r *scanRun) finish() []Finding {
	for _, channel := range r.toolOrder {
		if len(r.reasons) > 0 {
			r.incomplete("tool_name_unverified", false)
			break
		}
		r.tool(r.toolNames[channel])
	}
	_ = r.available() // Include work performed by the final operation in the budget.
	if nonce := r.input.Context.ExpectedNonce; nonce != "" {
		if len(nonce) > 128 {
			r.incomplete("nonce_context_limit", true)
		} else if !r.nonceSeen {
			if len(r.reasons) > 0 {
				r.incomplete("nonce_unverified", false)
			} else {
				r.add(SeverityHigh, "canary_nonce_violation", "完整响应未包含预期 canary nonce", "nonce mismatch; raw nonce omitted")
			}
		}
	}
	if len(r.reasons) > 0 {
		r.add(SeverityInfo, "incomplete", "扫描不完整；缺失部分没有安全结论", "")
	}
	reasons := make([]string, 0, len(r.reasons))
	for reason := range r.reasons {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	out := make([]Finding, 0, len(r.order))
	for _, ruleID := range r.order {
		f := r.found[ruleID]
		f.ScannerVersion = ScannerVersion
		f.RuleVersion = r.scanner.version
		f.BytesScanned = r.bytes
		f.Truncated = r.truncated
		f.DecodeDepth = r.depth
		f.IncompleteReason = strings.Join(reasons, ",")
		if r.reasons["credential_context_limit"] && f.Detail != "" {
			f.Summary = "扫描发现风险；凭据上下文超限"
			f.Detail = "凭据上下文超限；原始证据不保存"
		} else if r.hiddenCredential && f.Detail != "" {
			f.Detail = "编码载荷中的 Credential 已脱敏；原始证据不保存"
		}
		hash := sha256.Sum256([]byte(f.Detail))
		f.EvidenceHash = hex.EncodeToString(hash[:])
		out = append(out, f)
	}
	return out
}
