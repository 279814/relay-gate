package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const sampleKeyPurpose = "sample"
const securityKeyPurpose = "security"

type dataCipher struct {
	id   string
	aead cipher.AEAD
}

type wrappedDataKey struct {
	Purpose string `json:"purpose"`
	ID      string `json:"key_id"`
	Key     []byte `json:"key"`
}

type encryptedStateQuery interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func newWrappedDataKey(c *Cipher, purpose string) (string, string, error) {
	var key [32]byte
	var id [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", "", err
	}
	if _, err := rand.Read(id[:]); err != nil {
		return "", "", err
	}
	kid := hex.EncodeToString(id[:])
	raw, err := json.Marshal(wrappedDataKey{Purpose: purpose, ID: kid, Key: key[:]})
	if err != nil {
		return "", "", err
	}
	wrapped, err := c.EncryptEnvelope(string(raw))
	return kid, wrapped, err
}

func readDataKeys(ctx context.Context, q encryptedStateQuery, c *Cipher) (map[string]*dataCipher, error) {
	rows, err := q.QueryContext(ctx, `SELECT purpose,key_id,wrapped_key FROM data_key ORDER BY purpose`)
	if err != nil {
		return nil, fmt.Errorf("读取 Data Key: %w", err)
	}
	defer rows.Close()
	keys := map[string]*dataCipher{}
	for rows.Next() {
		var purpose, id, wrapped string
		if err := rows.Scan(&purpose, &id, &wrapped); err != nil {
			return nil, err
		}
		if purpose != sampleKeyPurpose && purpose != securityKeyPurpose {
			return nil, errors.New("Data Key purpose 无效")
		}
		plain, err := c.DecryptEnvelope(wrapped)
		if err != nil {
			return nil, fmt.Errorf("解包 %s Data Key 失败", purpose)
		}
		var value wrappedDataKey
		if err := json.Unmarshal([]byte(plain), &value); err != nil || value.Purpose != purpose || value.ID != id || len(value.Key) != 32 {
			return nil, errors.New("Data Key 包装身份或长度无效")
		}
		block, err := aes.NewCipher(value.Key)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		keys[purpose] = &dataCipher{id: id, aead: aead}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(keys) != 2 {
		return nil, errors.New("Sample/Security Data Key 缺失；拒绝重新生成以免丢失数据")
	}
	return keys, nil
}

func (c *Cipher) dataKey(purpose string) (*dataCipher, error) {
	if c == nil {
		return nil, ErrNoKey
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	key := c.dataKeys[purpose]
	if key == nil {
		return nil, errors.New("Data Key 尚未装载")
	}
	return key, nil
}

func (c *Cipher) installDataKeys(keys map[string]*dataCipher) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dataKeys = keys
}

func dataAAD(purpose, id string) []byte {
	return []byte("relay-gate/data-envelope/v2\x00" + purpose + "\x00" + id)
}

func (c *Cipher) encryptDataBlob(purpose string, plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return plain, nil
	}
	key, err := c.dataKey(purpose)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, key.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	sealed := key.aead.Seal(nonce, nonce, plain, dataAAD(purpose, key.id))
	return []byte("v2:" + key.id + ":" + base64.StdEncoding.EncodeToString(sealed)), nil
}

func (c *Cipher) decryptDataBlob(purpose string, raw []byte) ([]byte, error) {
	key, err := c.dataKey(purpose)
	if err != nil {
		return nil, err
	}
	parts := strings.SplitN(string(raw), ":", 3)
	if len(parts) != 3 || parts[0] != "v2" || parts[1] != key.id {
		return nil, errors.New("Data Key 信封身份不匹配")
	}
	sealed, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("Data Key 信封编码无效")
	}
	ns := key.aead.NonceSize()
	if len(sealed) < ns+key.aead.Overhead() {
		return nil, errors.New("Data Key 信封截断")
	}
	plain, err := key.aead.Open(nil, sealed[:ns], sealed[ns:], dataAAD(purpose, key.id))
	if err != nil {
		return nil, errors.New("Data Key 信封认证失败")
	}
	return plain, nil
}
