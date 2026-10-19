package transform

import "testing"

func TestRequestReencodeIsExplicitAndHasNoRuleParameters(t *testing.T) {
	for _, rule := range []Rule{
		{Kind: KindRequestReencode, Name: "gzip"},
		{Kind: KindRequestReencode, Value: "on"},
		{Kind: KindRequestReencode, SecretRef: "secret"},
		{Kind: KindRequestReencode, FailOpen: true},
		{Kind: KindRequestReencode, Regex: ".*"},
	} {
		if _, err := Compile(Version{Rules: []Rule{rule}}); err == nil {
			t.Fatalf("accepted ambiguous reencoding rule: %+v", rule)
		}
	}
	c, err := Compile(Version{Rules: []Rule{{Kind: KindRequestReencode}}})
	if err != nil || !c.AllowsRequestReencoding() || c.HasRequestBodyRules() {
		t.Fatalf("explicit opt-in=%v err=%v", c, err)
	}
	c, err = Compile(Version{Rules: []Rule{{Kind: KindSetHeader, Name: "X-Only", Value: "header"}}})
	if err != nil || c.AllowsRequestReencoding() {
		t.Fatal("ordinary rules implicitly authorized reencoding")
	}
}
