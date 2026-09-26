package sample

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// RedactBodyFile must share RedactSecrets encoding coverage with RedactBodyKeys:
// a spill that only has the QueryEscape form of a long key must be rewritten,
// and short needles must not corrupt a URL in the file. Raw-only Contains
// would skip the rewrite entirely when the raw key is absent.
func TestRedactBodyFile_RedactsQueryEscapedKey_SkipsShort(t *testing.T) {
	const key = "sk-spill/OMIT+TEST=KEY-7e4d9a2c"
	enc := url.QueryEscape(key)
	if enc == key {
		t.Fatal("test key must differ under QueryEscape")
	}
	path := filepath.Join(t.TempDir(), "spill.dat")
	const rawURL = "https://example.com/v1/messages?key=1"
	body := []byte(`upstream echo token=` + enc + ` trail ` + rawURL)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RedactBodyFile(path, []string{key, "key", "1", ""}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	if strings.Contains(s, enc) {
		t.Fatalf("spill still contains query-escaped key: %q", s)
	}
	if strings.Contains(s, key) {
		t.Fatalf("spill still contains raw key: %q", s)
	}
	if !strings.Contains(s, rawURL) {
		t.Fatalf("short needle must not corrupt URL in spill: %q", s)
	}
	if !strings.Contains(s, "upstream echo") || !strings.Contains(s, "trail") {
		t.Fatalf("unrelated spill text must stay: %q", s)
	}
}
