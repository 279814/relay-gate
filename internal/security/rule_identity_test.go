package security

import (
	"encoding/json"
	"testing"
)

func TestDifferentRuleIDsWithTheSameCategoryRemainIndependentFindings(t *testing.T) {
	first, err := CompileRule("site-one", "", "sentinel-one", "shared", SeverityLow)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CompileRule("site-two", "", "sentinel-two", "shared", SeverityHigh)
	if err != nil {
		t.Fatal(err)
	}
	scanner, err := NewScanner([]Rule{first, second})
	if err != nil {
		t.Fatal(err)
	}
	text := "sentinel-one sentinel-two sentinel-one"
	found := scanner.Scan(ScanInput{Segments: []Segment{{Body: []byte(text)}}, TotalBytes: int64(len(text))})
	if len(found) != 2 {
		t.Fatalf("independent rules were combined by category: %+v", found)
	}
	data, err := json.Marshal(found)
	if err != nil {
		t.Fatal(err)
	}
	var identities []struct {
		RuleID   string `json:"rule_id"`
		Category string `json:"category"`
	}
	if err := json.Unmarshal(data, &identities); err != nil {
		t.Fatal(err)
	}
	if identities[0].RuleID != "custom:site-one" || identities[1].RuleID != "custom:site-two" || identities[0].Category != "shared" || identities[1].Category != "shared" || found[0].Severity != SeverityLow || found[1].Severity != SeverityHigh {
		t.Fatalf("per-rule identity or evidence was lost: %s", data)
	}
	if found[0].ScannerVersion != "3" {
		t.Fatalf("new rule-identity aggregation used the historical scanner version: %q", found[0].ScannerVersion)
	}
}

func TestCustomRuleDoesNotReplaceBuiltinWithTheSameCategory(t *testing.T) {
	rule, err := CompileRule("site-injection", "", "sentinel", "prompt_injection", SeverityLow)
	if err != nil {
		t.Fatal(err)
	}
	scanner, err := NewScanner([]Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	text := "ignore previous instructions sentinel"
	found := scanner.Scan(ScanInput{Segments: []Segment{{Body: []byte(text)}}, TotalBytes: int64(len(text))})
	if len(found) != 2 || found[0].Severity != SeverityMedium || found[1].Severity != SeverityLow {
		t.Fatalf("custom and built-in rule were confused: %+v", found)
	}
}

func TestScannerRejectsAmbiguousDuplicateRuleIDs(t *testing.T) {
	first, _ := CompileRule("same-id", "", "first", "one", SeverityLow)
	second, _ := CompileRule("same-id", "", "second", "two", SeverityHigh)
	if _, err := NewScanner([]Rule{first, second}); err == nil {
		t.Fatal("duplicate rule IDs can make a scoped ignore affect a different rule")
	}
}

func TestCustomRuleNamespaceCannotCollideWithBuiltinIdentity(t *testing.T) {
	rule, err := CompileRule("builtin:prompt_injection", "", "sentinel", "prompt_injection", SeverityLow)
	if err != nil {
		t.Fatal(err)
	}
	scanner, err := NewScanner([]Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	text := "ignore previous instructions sentinel"
	found := scanner.Scan(ScanInput{Segments: []Segment{{Body: []byte(text)}}, TotalBytes: int64(len(text))})
	if len(found) != 2 || found[0].RuleID != "builtin:prompt_injection" || found[1].RuleID != "custom:builtin:prompt_injection" {
		t.Fatalf("a custom literal ID shadowed a builtin rule: %+v", found)
	}
}
