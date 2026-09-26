package model

import (
	"fmt"
	"os"
	"path/filepath"
)

// SpillDir is the directory that owns sample spill temp files.
// openSpill uses CreateTemp with this root (empty CreateTemp dir ≡ os.TempDir).
func SpillDir() string {
	return os.TempDir()
}

// RemoveSpillFile deletes path only when it resolves under SpillDir.
func RemoveSpillFile(path string) {
	if p, err := ConfinedSpillPath(path); err == nil {
		_ = os.Remove(p)
	}
}

// ConfinedSpillPath resolves path and rejects anything outside SpillDir
// (.., absolute escape, or Rel failure). Call before open/remove of a
// stored spill path so a poisoned RespBodyFile cannot leave the spill tree.
func ConfinedSpillPath(path string) (string, error) {
	return ConfinedSpillPathIn(SpillDir(), path)
}

// ConfinedSpillPathIn is ConfinedSpillPath against an explicit spill root
// (RemoveOrphanSpills may pass a non-default dir in tests).
func ConfinedSpillPathIn(dir, path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("spill path empty")
	}
	if dir == "" {
		dir = SpillDir()
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	root = filepath.Clean(root)
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	rel, err := filepath.Rel(root, abs)
	if err != nil || !filepath.IsLocal(rel) {
		return "", fmt.Errorf("spill path escapes directory")
	}
	return abs, nil
}
