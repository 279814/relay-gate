package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Cipher 用 AES-256-GCM 加解密上游 api_key。
//
// 选 GCM 而不是 CBC：GCM 自带完整性校验，密文被改过会解密失败而不是静默返回垃圾。
// 若返回垃圾 key，症状是上游 401，你会以为是站挂了 —— 那种排查方向完全是错的。
type Cipher struct {
	aead cipher.AEAD
}

// ErrNoKey 表示未配置加密密钥。
var ErrNoKey = errors.New("未设置 ENCRYPTION_KEY")

// NewCipher 从任意长度的口令派生 32 字节密钥。
//
// 用 SHA-256 而非 KDF：这个口令存在服务器环境变量里，不是用户密码，
// 不面对离线爆破场景（能读到环境变量的人也能读到数据库文件）。
// 上 argon2 只会增加依赖，不增加实际安全性。
func NewCipher(passphrase string) (*Cipher, error) {
	if strings.TrimSpace(passphrase) == "" {
		return nil, ErrNoKey
	}
	sum := sha256.Sum256([]byte(passphrase))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, fmt.Errorf("初始化 AES: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("初始化 GCM: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// Encrypt 返回 base64(nonce || ciphertext)。
// nonce 每次随机生成并前置存储 —— GCM 下 nonce 复用会直接泄露明文异或值，
// 所以绝不能用固定 nonce 或计数器。
func (c *Cipher) Encrypt(plain string) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("生成 nonce: %w", err)
	}
	out := c.aead.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(out), nil
}

func (c *Cipher) Decrypt(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("密文 base64 解码失败: %w", err)
	}
	ns := c.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("密文长度不足，数据可能已损坏")
	}
	plain, err := c.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		// 最常见的原因是 ENCRYPTION_KEY 换了。明确指出来，
		// 否则会被当成「数据库坏了」而去做无谓的恢复操作。
		return "", fmt.Errorf("解密失败（ENCRYPTION_KEY 是否与写入时一致？）: %w", err)
	}
	return string(plain), nil
}

// MaskKey 把 key 脱敏为 sk-abcd…wxyz，用于 API 回显与样本记录（§3.6.3b）。
//
// 短 key 全部打码：留前后各 4 位对一个 12 字符的 key 等于泄露 2/3。
func MaskKey(key string) string {
	const keep = 4
	if key == "" {
		return ""
	}
	if len(key) < keep*2+6 {
		return strings.Repeat("*", len(key))
	}
	return key[:keep] + "…" + key[len(key)-keep:]
}
