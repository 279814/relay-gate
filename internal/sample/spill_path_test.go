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
	outsideDir := mkdirOutsideSpill(t)
	outside := filepath.Join(outsideDir, "secret.txt")
	const payload = "token=" + key + " keep-me"
	if err := os.WriteFile(outside, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := RedactBodyFile(outside, []string{key}); err == nil {
		t.Fatal("absolute outside spill path must not open")
	}
	dotDot := filepath.Join(model.SpillDir(), "..", "relay-gate-not-a-spill")
	if err := RedactBodyFile(dotDot, []string{key}); err == nil {
		t.Fatalf(".. stored path %q must not open", dotDot)
	}
	got, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("outside file must stay untouched, got %q", got)
	}

	f, err := os.CreateTemp(model.SpillDir(), spillTempGlob)
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

func mkdirOutsideSpill(t *testing.T) string {
	t.Helper()
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		base, err = os.UserHomeDir()
		if err != nil || base == "" {
			t.Fatalf("need a writable dir outside SpillDir: %v", err)
		}
	}
	if rel, relErr := filepath.Rel(model.SpillDir(), base); relErr == nil && filepath.IsLocal(rel) {
		t.Skipf("cache/home %q is under SpillDir %q; cannot build outside fixture", base, model.SpillDir())
	}
	dir, err := os.MkdirTemp(base, "relay-gate-spill-outside-*")
	if err != nil {
		t.Fatalf("MkdirTemp outside spill root: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
