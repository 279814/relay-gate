//go:build !windows

package store

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func lockInstanceFile(file *os.File) error {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return ErrInstanceLocked
	}
	if err != nil {
		return fmt.Errorf("锁定数据库实例: %w", err)
	}
	return nil
}

func unlockInstanceFile(file *os.File) error {
	if err := unix.Flock(int(file.Fd()), unix.LOCK_UN); err != nil {
		return fmt.Errorf("释放数据库实例锁: %w", err)
	}
	return nil
}

func pathInfoIsReparsePoint(os.FileInfo) bool { return false }
