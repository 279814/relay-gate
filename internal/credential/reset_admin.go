package credential

import (
	"errors"
	"fmt"
	"io"
	"os"
)

var (
	// ErrResetNoHash means there is no on-disk admin hash to replace.
	ErrResetNoHash = errors.New("未找到管理员密码哈希；请先 credentials bootstrap 或 migrate")
)

// ResetAdmin replaces the Argon2id hash under data/secrets/ and returns the new
// plaintext once (§12.5). The old password is never printed (and is not recoverable).
func ResetAdmin(dataDir string, out io.Writer) (newPassword string, err error) {
	if dataDir == "" {
		return "", errors.New("需要 data 目录")
	}
	if out == nil {
		out = io.Discard
	}
	if err := ensureSecretsDir(dataDir); err != nil {
		return "", err
	}

	b := &Bootstrap{DataDir: dataDir}
	unlock, err := b.acquireLock()
	if err != nil {
		return "", err
	}
	defer unlock()

	if _, err := LoadAdminHash(dataDir); err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrBootstrapIncomplete) {
			return "", ErrResetNoHash
		}
		return "", err
	}

	newPW, err := GenerateAdminPassword()
	if err != nil {
		return "", err
	}
	hash, err := HashAdminPassword(newPW)
	if err != nil {
		return "", err
	}
	if err := ReplaceAdminHash(dataDir, hash); err != nil {
		return "", err
	}
	fmt.Fprintf(out, "ADMIN_PASSWORD=%s\n", newPW)
	fmt.Fprintf(out, "# 新管理员密码仅显示一次；旧密码不可恢复、未打印。\n")
	return newPW, nil
}
