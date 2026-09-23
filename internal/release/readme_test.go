package release

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// TestREADMEReferencedScriptsExist proves §23 "README 与实际命令一致" for
// local script paths: every scripts/* and root deploy.* referenced in README
// must exist on disk. Does not claim public cert smoke or multi-day soak.
func TestREADMEReferencedScriptsExist(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	readmePath := filepath.Join(root, "README.md")
	raw, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)

	// Status prose must not claim delivered P1–P4 surfaces are absent.
	for _, bad := range []string{
		"那些分别在 P1–P4，现在没有",
		"本分支做 P2 局部",
		"P0 至 P1 已在 main。本分支做 P2",
	} {
		if strings.Contains(text, bad) {
			t.Fatalf("README still claims unfinished local work: %q", bad)
		}
	}
	if !strings.Contains(text, "scripts/check-p5.sh") {
		t.Fatal("README must document scripts/check-p5.sh (CI P5 offline gate)")
	}
	if !strings.Contains(text, "deploy.ps1 -Local") || !strings.Contains(text, "./deploy.sh --local") {
		t.Fatal("README must document local one-line deploy commands")
	}

	re := regexp.MustCompile(`(?:scripts/[A-Za-z0-9._/-]+\.(?:sh|ps1)|deploy\.(?:ps1|sh))`)
	seen := map[string]bool{}
	for _, m := range re.FindAllString(text, -1) {
		rel := filepath.FromSlash(m)
		if seen[rel] {
			continue
		}
		seen[rel] = true
		path := filepath.Join(root, rel)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("README references missing path %s: %v", m, err)
		}
	}
	if len(seen) == 0 {
		t.Fatal("README had no script/deploy path matches")
	}
}
