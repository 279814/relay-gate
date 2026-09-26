package model

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfinedSpillPath_RejectsEscapeAllowsNormal(t *testing.T) {
	root := SpillDir()
	parent := filepath.Dir(root)
	outsideDir, err := os.MkdirTemp(parent, "relay-gate-spill-outside-*")
	if err != nil {
		t.Fatalf("MkdirTemp outside spill root: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(outsideDir) })

	outside := filepath.Join(outsideDir, "secret.txt")
	const payload = "SECRET_OUTSIDE"
	if err := os.WriteFile(outside, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := ConfinedSpillPath(outside); err == nil {
		t.Fatal("absolute path outside SpillDir must be rejected")
	}
	escape := filepath.Join(root, "..", filepath.Base(outsideDir), "secret.txt")
	if _, err := ConfinedSpillPath(escape); err == nil {
		t.Fatalf(".. escape %q must be rejected", escape)
	}
	got, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("outside file must stay untouched, got %q", got)
	}

	normal, err := os.CreateTemp(root, "relay-gate-sample-*.tmp")
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
