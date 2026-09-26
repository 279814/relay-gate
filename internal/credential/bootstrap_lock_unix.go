//go:build !windows

package credential

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
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
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("锁定 bootstrap: %w", err)
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}
