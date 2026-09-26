//go:build windows

package credential

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func (b *Bootstrap) acquireLock() (func(), error) {
	lockPath := filepath.Join(b.secretsDir(), "credentials-bootstrap.lock")
	if err := ensureSecretsDir(b.DataDir); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("打开 bootstrap 锁: %w", err)
	}
	_ = os.Chmod(lockPath, 0o600)
	err = windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &windows.Overlapped{},
	)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		_ = f.Close()
		return nil, errors.New("credentials bootstrap 正在由另一进程执行")
	}
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("锁定 bootstrap: %w", err)
	}
	return func() {
		_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &windows.Overlapped{})
		_ = f.Close()
	}, nil
}
