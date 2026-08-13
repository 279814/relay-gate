package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var (
	ErrInstanceLocked = errors.New("数据库已被另一个 relay-gate 实例锁定")
	ErrUnsafeLockPath = errors.New("数据库锁路径不安全")
)

type instanceLock struct {
	file     *os.File
	once     sync.Once
	closeErr error
}

func acquireInstanceLock(databasePath string) (*instanceLock, error) {
	path := dbPathOf(databasePath)
	if path == "" || path == ":memory:" {
		return nil, fmt.Errorf("%w: 需要本地数据库文件", ErrUnsafeLockPath)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsafeLockPath, err)
	}
	parent := filepath.Dir(absolute)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return nil, fmt.Errorf("%w: 校验目录 %s: %v", ErrUnsafeLockPath, parent, err)
	}
	if !sameFilesystemPath(parent, resolvedParent) {
		return nil, fmt.Errorf("%w: 数据库目录含 symlink/reparse point", ErrUnsafeLockPath)
	}

	lockPath := absolute + ".lock"
	if info, statErr := os.Lstat(lockPath); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || pathInfoIsReparsePoint(info) {
			return nil, fmt.Errorf("%w: %s", ErrUnsafeLockPath, lockPath)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, fmt.Errorf("检查数据库锁文件: %w", statErr)
	}

	file, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("打开数据库锁文件: %w", err)
	}
	if err := os.Chmod(lockPath, 0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("收紧数据库锁文件权限: %w", err)
	}
	info, err := os.Lstat(lockPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || pathInfoIsReparsePoint(info) {
		_ = file.Close()
		return nil, fmt.Errorf("%w: 锁文件在打开时发生变化", ErrUnsafeLockPath)
	}
	if err := lockInstanceFile(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &instanceLock{file: file}, nil
}

func sameFilesystemPath(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func (lock *instanceLock) Close() error {
	if lock == nil {
		return nil
	}
	lock.once.Do(func() {
		unlockErr := unlockInstanceFile(lock.file)
		closeErr := lock.file.Close()
		lock.closeErr = errors.Join(unlockErr, closeErr)
	})
	return lock.closeErr
}
