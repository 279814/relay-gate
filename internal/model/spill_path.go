package model

import (
	"errors"
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
// (.., absolute escape, Rel failure, or a symlink whose open/remove would
// leave the spill tree). Call before open/remove of a stored spill path so
// a poisoned RespBodyFile cannot leave the spill tree.
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
	// Lexical Rel accepts a symlink that lives under SpillDir; os.Open /
	// os.Remove would follow it outside. Reject the link itself (Lstat).
	info, err := os.Lstat(abs)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("spill path is symlink")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	} else {
		return abs, nil
	}
	// Also reject when an intermediate component is a symlink that lands
	// outside SpillDir (Lstat on the leaf would not see ModeSymlink).
	evalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	evalRoot = filepath.Clean(evalRoot)
	evalPath, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	evalPath = filepath.Clean(evalPath)
	rel, err = filepath.Rel(evalRoot, evalPath)
	if err != nil || !filepath.IsLocal(rel) {
		return "", fmt.Errorf("spill path escapes directory")
	}
	return abs, nil
}
