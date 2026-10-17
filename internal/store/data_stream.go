package store

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const dataChunkLimit = 1 << 20

// The authenticated header fixes the object, total size and frame layout.
// Frame indices in AAD reject reordering, removal, duplication and cross-object
// frame substitution; each frame still has a fresh random GCM nonce.
func encryptDataStream(c *Cipher, purpose string, dst io.Writer, src io.Reader, total int64, chunk int) error {
	key, err := c.dataKey(purpose)
	if err != nil {
		return err
	}
	if total < 1 {
		return errors.New("分块正文长度无效")
	}
	if chunk < 1 || chunk > dataChunkLimit {
		chunk = dataChunkLimit
	}
	var object [16]byte
	if _, err := rand.Read(object[:]); err != nil {
		return err
	}
	header := fmt.Sprintf("v2m:%s:%s:%d:%d:\n", key.id, hex.EncodeToString(object[:]), total, chunk)
	if _, err := io.WriteString(dst, header); err != nil {
		return err
	}
	remaining := total
	for index := int64(0); remaining > 0; index++ {
		n := min(int64(chunk), remaining)
		plain := make([]byte, int(n))
		if _, err := io.ReadFull(src, plain); err != nil {
			return errors.New("加密分块正文源被截断")
		}
		nonce := make([]byte, key.aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		aad := []byte("relay-gate/data-chunk/v2\x00" + purpose + "\x00" + header + strconv.FormatInt(index, 10))
		sealed := key.aead.Seal(nonce, nonce, plain, aad)
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(sealed)))
		if _, err := dst.Write(length[:]); err != nil {
			return err
		}
		if _, err := dst.Write(sealed); err != nil {
			return err
		}
		remaining -= n
	}
	var extra [1]byte
	if n, err := src.Read(extra[:]); n != 0 || err != io.EOF {
		return errors.New("加密分块正文源长度改变")
	}
	return nil
}

func decryptDataStream(c *Cipher, purpose string, dst io.Writer, src io.Reader) error {
	key, err := c.dataKey(purpose)
	if err != nil {
		return err
	}
	reader := bufio.NewReaderSize(src, 512)
	headerBytes, err := reader.ReadSlice('\n')
	if err != nil || len(headerBytes) > 256 {
		return errors.New("分块 Data Key 信封头无效")
	}
	header := string(headerBytes)
	parts := strings.Split(strings.TrimSuffix(header, "\n"), ":")
	if len(parts) != 6 || parts[0] != "v2m" || parts[1] != key.id || parts[5] != "" {
		return errors.New("分块 Data Key 信封身份无效")
	}
	object, err := hex.DecodeString(parts[2])
	if err != nil || len(object) != 16 {
		return errors.New("分块 Data Key 对象身份无效")
	}
	total, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || total < 1 {
		return errors.New("分块 Data Key 正文长度无效")
	}
	chunk, err := strconv.Atoi(parts[4])
	if err != nil || chunk < 1 || chunk > dataChunkLimit {
		return errors.New("分块 Data Key 窗口无效")
	}
	remaining := total
	for index := int64(0); remaining > 0; index++ {
		n := min(int64(chunk), remaining)
		var length [4]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return errors.New("分块 Data Key 信封截断")
		}
		want := int(n) + key.aead.NonceSize() + key.aead.Overhead()
		if int64(binary.BigEndian.Uint32(length[:])) != int64(want) {
			return errors.New("分块 Data Key 帧长度无效")
		}
		sealed := make([]byte, want)
		if _, err := io.ReadFull(reader, sealed); err != nil {
			return errors.New("分块 Data Key 帧截断")
		}
		ns := key.aead.NonceSize()
		aad := []byte("relay-gate/data-chunk/v2\x00" + purpose + "\x00" + header + strconv.FormatInt(index, 10))
		plain, err := key.aead.Open(nil, sealed[:ns], sealed[ns:], aad)
		if err != nil {
			return errors.New("分块 Data Key 帧认证失败")
		}
		if _, err := dst.Write(plain); err != nil {
			return err
		}
		remaining -= n
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		return errors.New("分块 Data Key 信封含多余帧")
	}
	return nil
}

func decryptDataMultipart(c *Cipher, purpose string, raw []byte) ([]byte, error) {
	var out bytes.Buffer
	if err := decryptDataStream(c, purpose, &out, bytes.NewReader(raw)); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
