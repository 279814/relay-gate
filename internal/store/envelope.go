package store

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// sampleEnvelopePrefix marks AES-GCM sample body BLOBs (§5.4 / P5).
const sampleEnvelopePrefix = "v1:"

// EncryptEnvelope returns v1:<key-id>:<base64(nonce||ciphertext)> (§12.4).
// Always uses the live active master (§12.7 key_activated+).
func (c *Cipher) EncryptEnvelope(plain string) (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	inner, err := encryptWith(c.aead, plain)
	if err != nil {
		return "", err
	}
	return sampleEnvelopePrefix + keyIDOf(c.rootKey) + ":" + inner, nil
}

// DecryptEnvelope accepts v1:key-id:payload or legacy bare base64 from Encrypt.
// After ActivateMaster, envelopes whose key-id matches a retired master still
// decrypt in-process. Durable rotation reseals sample envelopes in
// RewrapDirectSecrets so a restart with only the new master succeeds.
func (c *Cipher) DecryptEnvelope(encoded string) (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if strings.HasPrefix(encoded, sampleEnvelopePrefix) {
		parts := strings.SplitN(encoded, ":", 3)
		if len(parts) != 3 || parts[1] == "" || parts[2] == "" {
			return "", fmt.Errorf("信封格式无效")
		}
		kid := parts[1]
		if kid == keyIDOf(c.rootKey) {
			return decryptWith(c.aead, parts[2])
		}
		for _, prev := range c.previous {
			if kid == keyIDOf(prev.rootKey) {
				return decryptWith(prev.aead, parts[2])
			}
		}
		return "", fmt.Errorf("信封 key-id 不匹配（可能未完成 Master Key 轮换）")
	}
	// Legacy: reject accidental non-base64 to keep errors clear.
	if _, err := base64.StdEncoding.DecodeString(encoded); err != nil && strings.Contains(encoded, ":") {
		return "", fmt.Errorf("无法识别的密文信封")
	}
	plain, err := decryptWith(c.aead, encoded)
	if err == nil {
		return plain, nil
	}
	for _, prev := range c.previous {
		if p, e := decryptWith(prev.aead, encoded); e == nil {
			return p, nil
		}
	}
	return "", err
}

// EncryptSampleBlob wraps sample body bytes in a v1 envelope. Empty stays empty.
func (c *Cipher) EncryptSampleBlob(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return plain, nil
	}
	enc, err := c.EncryptEnvelope(string(plain))
	if err != nil {
		return nil, err
	}
	return []byte(enc), nil
}

// DecryptSampleBlob accepts v1 envelopes or legacy plaintext sample rows.
// Plaintext history is never refused so unread rows survive migration.
func (c *Cipher) DecryptSampleBlob(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return raw, nil
	}
	if !IsSampleEnvelope(raw) {
		return append([]byte(nil), raw...), nil
	}
	plain, err := c.DecryptEnvelope(string(raw))
	if err != nil {
		return nil, err
	}
	return []byte(plain), nil
}

// IsSampleEnvelope reports whether a sample BLOB already uses the v1 envelope.
func IsSampleEnvelope(raw []byte) bool {
	return len(raw) >= len(sampleEnvelopePrefix) &&
		string(raw[:len(sampleEnvelopePrefix)]) == sampleEnvelopePrefix
}
