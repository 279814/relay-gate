package sample

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

// Stored spill paths (.. or absolute outside SpillDir) must not open files
// outside the spill directory; a normal CreateTemp spill must still redact.
func TestRedactBodyFile_RejectsPathEscape_AllowsNormalSpill(t *testing.T) {
	const key = "sk-spill-confine-TEST-KEY-9f3a"
	root := model.SpillDir()
	parent := filepath.Dir(root)
	outsideDir, err := os.MkdirTemp(parent, "relay-gate-spill-outside-*")
	if err != nil {
		t.Fatalf("MkdirTemp outside spill root: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(outsideDir) })

	outside := filepath.Join(outsideDir, "secret.txt")
	const payload = "token=" + key + " keep-me"
	if err := os.WriteFile(outside, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := RedactBodyFile(outside, []string{key}); err == nil {
		t.Fatal("absolute outside spill path must not open")
	}
	escape := filepath.Join(root, "..", filepath.Base(outsideDir), "secret.txt")
	if err := RedactBodyFile(escape, []string{key}); err == nil {
		t.Fatalf(".. stored path %q must not open", escape)
	}
	got, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("outside file must stay untouched, got %q", got)
	}

	f, err := os.CreateTemp(root, spillTempGlob)
	if err != nil {
		t.Fatal(err)
	}
	normalPath := f.Name()
	t.Cleanup(func() { _ = os.Remove(normalPath) })
	if _, err := f.WriteString("token=" + key + " trail"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := RedactBodyFile(normalPath, []string{key}); err != nil {
		t.Fatalf("normal spill must still redact: %v", err)
	}
	body, err := os.ReadFile(normalPath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	if strings.Contains(s, key) {
		t.Fatalf("normal spill still contains key: %q", s)
	}
	if !strings.Contains(s, "trail") {
		t.Fatalf("normal spill lost unrelated text: %q", s)
	}
}
