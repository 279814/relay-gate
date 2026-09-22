package credential

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters for admin password hashing (§12.5).
const (
	argonTime    = 1
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16
)

// HashAdminPassword returns a PHC-encoded Argon2id hash.
func HashAdminPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", errors.New("管理员密码至少 8 字符")
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("生成 salt: %w", err)
	}
	sum := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum),
	), nil
}

// VerifyAdminPassword checks plaintext against a PHC Argon2id hash.
func VerifyAdminPassword(password, encoded string) bool {
	salt, expect, timeCost, memory, threads, err := parseArgon2PHC(encoded)
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, timeCost, memory, threads, uint32(len(expect)))
	return subtle.ConstantTimeCompare(got, expect) == 1
}

func parseArgon2PHC(encoded string) (salt, hash []byte, timeCost, memory uint32, threads uint8, err error) {
	parts := strings.Split(encoded, "$")
	// "", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, nil, 0, 0, 0, errors.New("不是 argon2id PHC")
	}
	var version int
	if _, err = fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, nil, 0, 0, 0, err
	}
	if version != argon2.Version {
		return nil, nil, 0, 0, 0, fmt.Errorf("不支持的 argon2 版本 %d", version)
	}
	var t, m, p int
	if _, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return nil, nil, 0, 0, 0, err
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, 0, 0, 0, err
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, 0, 0, 0, err
	}
	return salt, hash, uint32(t), uint32(m), uint8(p), nil
}
