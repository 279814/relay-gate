package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var errCLIPrivateInput = errors.New("私有输入、来源或文件保护校验失败；未发送请求")

// This deliberately accepts the documented private roots, rather than trying
// to interpret arbitrary ignore rules as a security policy.
func privateCLIPath(path, root string, missing bool) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", errCLIPrivateInput
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return "", errCLIPrivateInput
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil || !strings.EqualFold(filepath.Clean(resolvedRoot), filepath.Clean(root)) || cliPathIsReparse(root) {
		return "", errCLIPrivateInput
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return "", errCLIPrivateInput
	}
	rel = filepath.ToSlash(rel)
	allowed := strings.HasPrefix(rel, ".local/p0/") || rel == "scripts/upstreams.tsv" || (strings.HasPrefix(rel, "scripts/") && strings.Contains(filepath.Base(rel), ".local."))
	if !allowed {
		return "", errCLIPrivateInput
	}
	if err := exec.Command("git", "-C", root, "check-ignore", "--no-index", "-q", "--", rel).Run(); err != nil {
		return "", errCLIPrivateInput
	}
	// Do not accept a tracked file even if --no-index reports an ignore rule.
	if exec.Command("git", "-C", root, "ls-files", "--error-unmatch", "--", rel).Run() == nil {
		return "", errCLIPrivateInput
	}
	ignore, err := os.ReadFile(filepath.Join(root, ".dockerignore"))
	if err != nil {
		return "", errCLIPrivateInput
	}
	excluded := false
	for _, line := range strings.Split(string(ignore), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "!") {
			return "", errCLIPrivateInput
		}
		pattern := strings.TrimPrefix(line, "/")
		if strings.HasPrefix(rel, strings.TrimSuffix(pattern, "/")+"/") || pattern == rel {
			excluded = true
		}
		if match, _ := filepath.Match(pattern, rel); match {
			excluded = true
		}
	}
	if !excluded {
		return "", errCLIPrivateInput
	}
	current := root
	parts := strings.Split(filepath.FromSlash(rel), string(os.PathSeparator))
	for index, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) && missing && index == len(parts)-1 {
			break
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || cliPathIsReparse(current) {
			return "", errCLIPrivateInput
		}
		if index < len(parts)-1 && !info.IsDir() {
			return "", errCLIPrivateInput
		}
		if index == len(parts)-1 && !info.Mode().IsRegular() {
			return "", errCLIPrivateInput
		}
		if index == len(parts)-1 {
			if err := cliCheckPrivatePermissions(current, info); err != nil {
				return "", errCLIPrivateInput
			}
		}
		if index >= 1 && parts[0] == ".local" {
			if err := cliCheckPrivatePermissions(current, info); err != nil {
				return "", errCLIPrivateInput
			}
		}
	}
	return abs, nil
}

func readCLIPrivateFile(path, root string, limit int64) ([]byte, error) {
	abs, err := privateCLIPath(path, root, false)
	if err != nil {
		return nil, err
	}
	before, err := os.Lstat(abs)
	if err != nil || before.Size() > limit {
		return nil, errCLIPrivateInput
	}
	file, err := os.Open(abs)
	if err != nil {
		return nil, errCLIPrivateInput
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errCLIPrivateInput
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errCLIPrivateInput
	}
	after, err := os.Lstat(abs)
	if err != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) {
		return nil, errCLIPrivateInput
	}
	if _, err := privateCLIPath(abs, root, false); err != nil {
		return nil, err
	}
	return data, nil
}

func writeCLIPrivateFile(path, root string, data []byte) error {
	abs, err := privateCLIPath(path, root, true)
	if err != nil {
		return err
	}
	before, statErr := os.Lstat(abs)
	if statErr != nil && !os.IsNotExist(statErr) {
		return errCLIPrivateInput
	}
	stage, err := os.CreateTemp(filepath.Dir(abs), ".probe-report-*")
	if err != nil {
		return errCLIPrivateInput
	}
	stagePath := stage.Name()
	defer os.Remove(stagePath)
	if err := cliRestrictPrivatePath(stagePath); err != nil {
		stage.Close()
		return errCLIPrivateInput
	}
	if _, err := stage.Write(data); err != nil {
		stage.Close()
		return errCLIPrivateInput
	}
	if err := stage.Sync(); err != nil {
		stage.Close()
		return errCLIPrivateInput
	}
	if err := stage.Close(); err != nil {
		return errCLIPrivateInput
	}
	if _, err := privateCLIPath(abs, root, true); err != nil {
		return err
	}
	after, afterErr := os.Lstat(abs)
	if statErr == nil {
		if afterErr != nil || !os.SameFile(before, after) {
			return errCLIPrivateInput
		}
	} else if !os.IsNotExist(afterErr) {
		return errCLIPrivateInput
	}
	if err := os.Rename(stagePath, abs); err != nil {
		return errCLIPrivateInput
	}
	return nil
}
