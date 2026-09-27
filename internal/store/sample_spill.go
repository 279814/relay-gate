package store

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/279814/relay-gate/internal/model"
)

// sampleBlobChunk 与 sample.fullSpillAt（默认 1 MiB）对齐：分块加密封顶缓冲。
// 测试可调低以覆盖 v1m 分帧路径。
var sampleBlobChunk = 1 << 20

// sampleMultipartPrefix marks chunked sample body BLOBs (spill insert path).
const sampleMultipartPrefix = "v1m:"

func isSampleMultipart(raw []byte) bool {
	return len(raw) >= len(sampleMultipartPrefix) &&
		string(raw[:len(sampleMultipartPrefix)]) == sampleMultipartPrefix
}

// encryptSampleBodyFile 把明文 spill 按 sampleBlobChunk 分块封成信封文件。
// 单块不超过窗口时仍写单个 v1: 信封；多块写 v1m: 分帧，避免整文件进一个 []byte。
func (s *Store) encryptSampleBodyFile(srcPath string) (encPath string, err error) {
	srcPath, err = model.ConfinedSpillPath(srcPath)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(srcPath)
	if err != nil {
		return "", err
	}
	src, err := os.Open(srcPath)
	if err != nil {
		return "", err
	}
	defer src.Close()

	dst, err := os.CreateTemp(model.SpillDir(), "relay-gate-sample-enc-*.tmp")
	if err != nil {
		return "", err
	}
	encPath = dst.Name()
	ok := false
	defer func() {
		_ = dst.Close()
		if !ok {
			_ = os.Remove(encPath)
			encPath = ""
		}
	}()

	if s.cipher == nil {
		if _, err := io.Copy(dst, src); err != nil {
			return "", err
		}
		ok = true
		return encPath, nil
	}

	chunk := sampleBlobChunk
	if chunk < 1 {
		chunk = 1
	}

	if fi.Size() <= int64(chunk) {
		plain := make([]byte, int(fi.Size()))
		if _, err := io.ReadFull(src, plain); err != nil && err != io.EOF {
			return "", err
		}
		enc, err := s.cipher.EncryptSampleBlob(plain)
		if err != nil {
			return "", err
		}
		if _, err := dst.Write(enc); err != nil {
			return "", err
		}
		ok = true
		return encPath, nil
	}

	kid := s.cipher.KeyID()
	header := sampleMultipartPrefix + kid + ":\n"
	if _, err := io.WriteString(dst, header); err != nil {
		return "", err
	}
	buf := make([]byte, chunk)
	var lenBuf [4]byte
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			enc, err := s.cipher.EncryptSampleBlob(buf[:n])
			if err != nil {
				return "", err
			}
			binary.BigEndian.PutUint32(lenBuf[:], uint32(len(enc)))
			if _, err := dst.Write(lenBuf[:]); err != nil {
				return "", err
			}
			if _, err := dst.Write(enc); err != nil {
				return "", err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", readErr
		}
	}
	ok = true
	return encPath, nil
}

func decryptSampleMultipart(cipher *Cipher, raw []byte) ([]byte, error) {
	// v1m:<key-id>:\n + frames
	rest := raw[len(sampleMultipartPrefix):]
	colon := -1
	for i := 0; i < len(rest); i++ {
		if rest[i] == ':' {
			colon = i
			break
		}
	}
	if colon < 0 || colon+1 >= len(rest) || rest[colon+1] != '\n' {
		return nil, fmt.Errorf("分块样本信封格式无效")
	}
	payload := rest[colon+2:]
	var out []byte
	for len(payload) > 0 {
		if len(payload) < 4 {
			return nil, fmt.Errorf("分块样本信封截断")
		}
		n := int(binary.BigEndian.Uint32(payload[:4]))
		payload = payload[4:]
		if n < 0 || n > len(payload) {
			return nil, fmt.Errorf("分块样本信封长度无效")
		}
		frame := payload[:n]
		payload = payload[n:]
		plain, err := cipher.DecryptSampleBlob(frame)
		if err != nil {
			return nil, err
		}
		out = append(out, plain...)
	}
	return out, nil
}
