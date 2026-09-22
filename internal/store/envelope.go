package store

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// EncryptEnvelope returns v1:<key-id>:<base64(nonce||ciphertext)> (§12.4).
func (c *Cipher) EncryptEnvelope(plain string) (string, error) {
	inner, err := c.Encrypt(plain)
	if err != nil {
		return "", err
	}
	return "v1:" + c.KeyID() + ":" + inner, nil
}

// DecryptEnvelope accepts v1:key-id:payload or legacy bare base64 from Encrypt.
func (c *Cipher) DecryptEnvelope(encoded string) (string, error) {
	if strings.HasPrefix(encoded, "v1:") {
		parts := strings.SplitN(encoded, ":", 3)
		if len(parts) != 3 || parts[1] == "" || parts[2] == "" {
			return "", fmt.Errorf("信封格式无效")
		}
		if parts[1] != c.KeyID() {
			return "", fmt.Errorf("信封 key-id 不匹配（可能未完成 Master Key 轮换）")
		}
		return c.Decrypt(parts[2])
	}
	// Legacy: reject accidental non-base64 to keep errors clear.
	if _, err := base64.StdEncoding.DecodeString(encoded); err != nil && strings.Contains(encoded, ":") {
		return "", fmt.Errorf("无法识别的密文信封")
	}
	return c.Decrypt(encoded)
}
