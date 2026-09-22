package transform

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Compile validates rules and prepares RE2 patterns. Rejects scripts, CR/LF
// in header values, protected headers as final control, and oversized regex.
func Compile(v Version) (*Compiled, error) {
	if len(v.Rules) == 0 {
		return nil, fmt.Errorf("version has no rules")
	}
	if len(v.Rules) > MaxRulesPerVersion {
		return nil, fmt.Errorf("too many rules: %d > %d", len(v.Rules), MaxRulesPerVersion)
	}
	if v.ReqFailPolicy == "" {
		v.ReqFailPolicy = FailClosed
	}
	if v.ResFailPolicy == "" {
		v.ResFailPolicy = FailOpen
	}
	switch v.ReqFailPolicy {
	case FailClosed, FailOpen:
	default:
		return nil, fmt.Errorf("invalid req_fail_policy %q", v.ReqFailPolicy)
	}
	switch v.ResFailPolicy {
	case FailClosed, FailOpen:
	default:
		return nil, fmt.Errorf("invalid res_fail_policy %q", v.ResFailPolicy)
	}

	out := &Compiled{Version: v, regex: make(map[int]*regexp.Regexp)}
	for i, rule := range v.Rules {
		if err := validateRule(i, rule); err != nil {
			return nil, err
		}
		if rule.Regex != "" {
			if len(rule.Regex) > MaxRegexBytes {
				return nil, fmt.Errorf("rule %d: regex exceeds %d bytes", i, MaxRegexBytes)
			}
			re, err := regexp.Compile(rule.Regex)
			if err != nil {
				return nil, fmt.Errorf("rule %d: RE2 compile: %w", i, err)
			}
			out.regex[i] = re
		}
	}
	return out, nil
}

func validateRule(i int, rule Rule) error {
	kind := strings.TrimSpace(rule.Kind)
	if kind == "" {
		return fmt.Errorf("rule %d: kind required", i)
	}
	switch kind {
	case KindSetHeader, KindDeleteHeader:
		if strings.TrimSpace(rule.Name) == "" {
			return fmt.Errorf("rule %d: header name required", i)
		}
		if isProtectedHeader(rule.Name) {
			return fmt.Errorf("rule %d: cannot control protected header %q", i, rule.Name)
		}
		if kind == KindSetHeader {
			if err := rejectCRLFinHeaderValue(rule.Value); err != nil {
				return fmt.Errorf("rule %d: %w", i, err)
			}
		}
	case KindRenameHeader:
		if strings.TrimSpace(rule.From) == "" || strings.TrimSpace(rule.To) == "" {
			return fmt.Errorf("rule %d: rename requires from and to", i)
		}
		if isProtectedHeader(rule.From) || isProtectedHeader(rule.To) {
			return fmt.Errorf("rule %d: cannot rename protected header", i)
		}
		if err := rejectCRLFinHeaderValue(rule.To); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
	case KindReplaceBytes:
		if rule.From == "" {
			return fmt.Errorf("rule %d: replace_bytes requires from", i)
		}
		if len(rule.From)+len(rule.To) > MaxAddedBytes {
			return fmt.Errorf("rule %d: replace_bytes size exceeds budget", i)
		}
	case KindSetJSONPointer:
		if !strings.HasPrefix(rule.Name, "/") && rule.Name != "" {
			return fmt.Errorf("rule %d: json pointer must start with /", i)
		}
		if rule.Name == "" {
			return fmt.Errorf("rule %d: json pointer required", i)
		}
	case KindJSONPatchAdd:
		if err := requireJSONPointer(i, rule.Name); err != nil {
			return err
		}
		if strings.TrimSpace(rule.Value) == "" {
			return fmt.Errorf("rule %d: json_patch_add requires value", i)
		}
	case KindJSONPatchRemove:
		if err := requireJSONPointer(i, rule.Name); err != nil {
			return err
		}
	case KindJSONPatchCopy:
		if strings.TrimSpace(rule.From) == "" || !strings.HasPrefix(strings.TrimSpace(rule.From), "/") {
			return fmt.Errorf("rule %d: json_patch_copy requires from pointer starting with /", i)
		}
		if strings.TrimSpace(rule.To) == "" || !strings.HasPrefix(strings.TrimSpace(rule.To), "/") {
			return fmt.Errorf("rule %d: json_patch_copy requires to pointer starting with /", i)
		}
	case KindSetStatus:
		if rule.Value == "" {
			return fmt.Errorf("rule %d: status value required", i)
		}
	case KindSSEMatch:
		if strings.TrimSpace(rule.Match) == "" {
			return fmt.Errorf("rule %d: sse_match requires match event type", i)
		}
	case KindSSEAppendEnd:
		// synthetic completion; Value is optional trailing event payload
	default:
		return fmt.Errorf("rule %d: unknown kind %q (no scripts)", i, kind)
	}
	if looksLikeScript(rule.Value) || looksLikeScript(rule.To) || looksLikeScript(rule.From) {
		return fmt.Errorf("rule %d: script-like payloads rejected", i)
	}
	return nil
}

func rejectCRLFinHeaderValue(v string) error {
	if strings.ContainsAny(v, "\r\n") {
		return fmt.Errorf("header value must not contain CR/LF")
	}
	if !utf8.ValidString(v) {
		return fmt.Errorf("header value must be valid UTF-8")
	}
	return nil
}

func looksLikeScript(s string) bool {
	lower := strings.ToLower(s)
	if strings.Contains(lower, "<script") {
		return true
	}
	if strings.Contains(lower, "javascript:") {
		return true
	}
	// Reject obvious shell/lua/js function wrappers as user "scripts".
	if strings.HasPrefix(strings.TrimSpace(lower), "function(") ||
		strings.HasPrefix(strings.TrimSpace(lower), "#!/") {
		return true
	}
	return false
}

func requireJSONPointer(i int, pointer string) error {
	pointer = strings.TrimSpace(pointer)
	if pointer == "" {
		return fmt.Errorf("rule %d: json pointer required", i)
	}
	if !strings.HasPrefix(pointer, "/") {
		return fmt.Errorf("rule %d: json pointer must start with /", i)
	}
	return nil
}
