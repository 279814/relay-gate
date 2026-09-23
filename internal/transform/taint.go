package transform

import (
	"fmt"
	"regexp"
	"strings"
)

// secretPlaceholderRE matches declarative {{SECRET:name}} tokens only.
var secretPlaceholderRE = regexp.MustCompile(`\{\{SECRET:([A-Za-z][A-Za-z0-9_]*)\}\}`)

// SecretMap resolves named secrets for apply. Plaintext must not appear in
// diagnostics; callers pass this only on the live/proxy path.
type SecretMap map[string][]byte

// TaintBag tracks rendered secret plaintext and redacts it from diagnostics (§15.3).
type TaintBag struct {
	plains [][]byte
}

func (t *TaintBag) note(plain []byte) {
	if t == nil || len(plain) == 0 {
		return
	}
	t.plains = append(t.plains, append([]byte(nil), plain...))
}

func (t *TaintBag) Redact(s string) string {
	if t == nil || s == "" {
		return s
	}
	out := s
	for _, p := range t.plains {
		if len(p) == 0 {
			continue
		}
		out = strings.ReplaceAll(out, string(p), "[REDACTED]")
	}
	return out
}

func (t *TaintBag) RedactErr(err error) error {
	if err == nil || t == nil {
		return err
	}
	msg := t.Redact(err.Error())
	if msg == err.Error() {
		return err
	}
	return fmt.Errorf("%s", msg)
}

// applySecrets is the per-Apply resolution + taint bag.
type applySecrets struct {
	lookup SecretMap
	taint  TaintBag
}

func (a *applySecrets) resolveRuleValue(rule Rule) (string, error) {
	ref := strings.TrimSpace(rule.SecretRef)
	if ref != "" {
		if a == nil || a.lookup == nil {
			return "", fmt.Errorf("secret_ref %q unresolved", ref)
		}
		plain, ok := a.lookup[ref]
		if !ok || len(plain) == 0 {
			return "", fmt.Errorf("secret_ref %q unresolved", ref)
		}
		a.taint.note(plain)
		return string(plain), nil
	}
	return a.expandPlaceholders(rule.Value)
}

func (a *applySecrets) expandPlaceholders(s string) (string, error) {
	if !strings.Contains(s, "{{SECRET:") {
		return s, nil
	}
	var err error
	out := secretPlaceholderRE.ReplaceAllStringFunc(s, func(tok string) string {
		if err != nil {
			return ""
		}
		m := secretPlaceholderRE.FindStringSubmatch(tok)
		if len(m) != 2 {
			err = fmt.Errorf("invalid secret placeholder")
			return ""
		}
		name := m[1]
		if a == nil || a.lookup == nil {
			err = fmt.Errorf("secret_ref %q unresolved", name)
			return ""
		}
		plain, ok := a.lookup[name]
		if !ok || len(plain) == 0 {
			err = fmt.Errorf("secret_ref %q unresolved", name)
			return ""
		}
		a.taint.note(plain)
		return string(plain)
	})
	if err != nil {
		return "", err
	}
	if strings.Contains(out, "{{SECRET:") {
		return "", fmt.Errorf("unresolved secret placeholder")
	}
	return out, nil
}

func validateSecretRefName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("secret_ref required")
	}
	if !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`).MatchString(name) {
		return fmt.Errorf("invalid secret_ref %q", name)
	}
	return nil
}

func secretRefsInValue(value string) []string {
	matches := secretPlaceholderRE.FindAllStringSubmatch(value, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]string, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		if len(m) != 2 {
			continue
		}
		if _, ok := seen[m[1]]; ok {
			continue
		}
		seen[m[1]] = struct{}{}
		out = append(out, m[1])
	}
	return out
}

func kindAllowsSecretRef(kind string) bool {
	switch kind {
	case KindSetHeader, KindSetJSONPointer, KindJSONPatchAdd, KindBodyTemplate:
		return true
	default:
		return false
	}
}

// ruleUsesSecret reports secret_ref or {{SECRET:name}} in the rule. Response
// apply must reject these: docs/01 §15.4 lists Secret refs under request rules
// only; resolving them into a client response header would echo upstream keys.
func ruleUsesSecret(rule Rule) bool {
	if strings.TrimSpace(rule.SecretRef) != "" {
		return true
	}
	return len(secretRefsInValue(rule.Value)) > 0
}
