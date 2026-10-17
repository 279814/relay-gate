package store

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
)

// sampleEnvelopePrefix is the legacy Master envelope marker, still used for
// direct secrets and wrapping independent Data Keys.
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
// decrypt in-process until verified rotation cleanup. Sample bodies now use
// independent v2 Data Key envelopes; only their small wrappers are resealed.
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

// EncryptSampleBlob uses the independent Sample Data Key. Larger in-memory
// bodies use authenticated v2m frames just like spill files. Empty stays empty.
func (c *Cipher) EncryptSampleBlob(plain []byte) ([]byte, error) {
	if len(plain) > dataChunkLimit {
		var out bytes.Buffer
		if err := encryptDataStream(c, sampleKeyPurpose, &out, bytes.NewReader(plain), int64(len(plain)), dataChunkLimit); err != nil {
			return nil, err
		}
		return out.Bytes(), nil
	}
	return c.encryptDataBlob(sampleKeyPurpose, plain)
}

// DecryptSampleBlob dual-reads legacy plaintext/v1/v1m and current v2/v2m.
// Startup migration authenticates legacy frames before upgrading them; schema8
// full-state validation requires every non-empty stored body to use a Data Key.
func (c *Cipher) DecryptSampleBlob(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return raw, nil
	}
	if strings.HasPrefix(string(raw[:min(len(raw), 4)]), "v2:") {
		return c.decryptDataBlob(sampleKeyPurpose, raw)
	}
	if strings.HasPrefix(string(raw[:min(len(raw), 4)]), "v2m:") {
		return decryptDataMultipart(c, sampleKeyPurpose, raw)
	}
	if isSampleMultipart(raw) {
		if c == nil {
			return nil, fmt.Errorf("分块样本信封需要 Cipher")
		}
		return decryptSampleMultipart(c, raw)
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

// IsSampleEnvelope recognizes legacy/current single-message envelopes.
func IsSampleEnvelope(raw []byte) bool {
	return len(raw) >= 3 && (string(raw[:3]) == sampleEnvelopePrefix || string(raw[:3]) == "v2:")
}
