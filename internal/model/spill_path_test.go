package model

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfinedSpillPath_RejectsEscapeAllowsNormal(t *testing.T) {
	outsideDir := mkdirOutsideSpill(t)
	outside := filepath.Join(outsideDir, "secret.txt")
	const payload = "SECRET_OUTSIDE"
	if err := os.WriteFile(outside, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := ConfinedSpillPath(outside); err == nil {
		t.Fatal("absolute path outside SpillDir must be rejected")
	}
	dotDot := filepath.Join(SpillDir(), "..", "relay-gate-not-a-spill")
	if _, err := ConfinedSpillPath(dotDot); err == nil {
		t.Fatalf(".. escape %q must be rejected", dotDot)
	}
	got, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("outside file must stay untouched, got %q", got)
	}

	// Custom root: sibling of a TempDir child must not resolve as in-tree.
	root := t.TempDir()
	sibling := filepath.Join(filepath.Dir(root), "sibling-secret.txt")
	if err := os.WriteFile(sibling, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(sibling) })
	if _, err := ConfinedSpillPathIn(root, sibling); err == nil {
		t.Fatal("path outside explicit spill root must be rejected")
	}
	if _, err := ConfinedSpillPathIn(root, filepath.Join(root, "..", filepath.Base(sibling))); err == nil {
		t.Fatal(".. relative to explicit spill root must be rejected")
	}

	normal, err := os.CreateTemp(SpillDir(), "relay-gate-sample-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	normalPath := normal.Name()
	t.Cleanup(func() { _ = os.Remove(normalPath) })
	if _, err := normal.WriteString("ok-spill"); err != nil {
		t.Fatal(err)
	}
	if err := normal.Close(); err != nil {
		t.Fatal(err)
	}
	gotPath, err := ConfinedSpillPath(normalPath)
	if err != nil {
		t.Fatalf("normal spill under SpillDir must resolve: %v", err)
	}
	body, err := os.ReadFile(gotPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "ok-spill" {
		t.Fatalf("normal spill read = %q, want ok-spill", body)
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
	if rel, relErr := filepath.Rel(SpillDir(), base); relErr == nil && filepath.IsLocal(rel) {
		t.Skipf("cache/home %q is under SpillDir %q; cannot build outside fixture", base, SpillDir())
	}
	dir, err := os.MkdirTemp(base, "relay-gate-spill-outside-*")
	if err != nil {
		t.Fatalf("MkdirTemp outside spill root: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
