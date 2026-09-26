package sample

import (
	"bytes"
	"io"
	"os"
	"path/filepath"

	"github.com/279814/relay-gate/internal/model"
)

// RedactBodyFile 按窗口流式脱敏 spill 文件；无命中时不改文件。
// 峰值缓冲约 SpillMemLimit + 最长 needle（含 JSON \u 形态），
// 绝不整文件读进一个 []byte。
//
// 与 finding Detail / RedactBodyKeys / RedactDiagnostic 共用
// security.RedactSecrets：原文、url.QueryEscape、小写 hex 百分号编码、
// 以及 JSON \uXXXX（hex 大小写不敏感）一并遮掉。命中检测与改写都走
// RedactBodyKeys，不能只做原文 Contains / ReplaceAll，否则仅编码形态
// 会漏进 spill。短于 MinRedactableKeyLen 的 needle 跳过。
// 只改落库 spill；live 客户端字节不经此路径。
func RedactBodyFile(path string, keys []string) error {
	if path == "" || len(keys) == 0 {
		return nil
	}
	usable := make([]string, 0, len(keys))
	maxK := 0
	for _, k := range keys {
		if len(k) < model.MinRedactableKeyLen {
			continue
		}
		usable = append(usable, k)
		// Longest RedactSecrets needle is JSON \u00XX-per-byte (6× raw).
		if n := len(k) * 6; n > maxK {
			maxK = n
		}
	}
	if len(usable) == 0 {
		return nil
	}
	hit, err := fileContainsAny(path, usable, maxK)
	if err != nil || !hit {
		return err
	}
	return rewriteRedactedFile(path, usable, maxK)
}

func fileContainsAny(path string, keys []string, maxK int) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	overlap := maxK - 1
	if overlap < 0 {
		overlap = 0
	}
	buf := make([]byte, SpillMemLimit())
	carry := make([]byte, 0, overlap)
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			work := append(carry, buf[:n]...)
			// Same rules as rewrite: RedactBodyKeys → RedactSecrets covers
			// raw + QueryEscape + lower-%XX + JSON \u forms.
			if !bytes.Equal(RedactBodyKeys(work, keys), work) {
				return true, nil
			}
			if len(work) > overlap {
				carry = append(carry[:0], work[len(work)-overlap:]...)
			} else {
				carry = append(carry[:0], work...)
			}
		}
		if readErr == io.EOF {
			return false, nil
		}
		if readErr != nil {
			return false, readErr
		}
	}
}

func rewriteRedactedFile(path string, keys []string, maxK int) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}

	out, err := os.CreateTemp(filepath.Dir(path), "relay-gate-sample-redact-*.tmp")
	if err != nil {
		_ = in.Close()
		return err
	}
	outPath := out.Name()
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(outPath)
		}
	}()

	overlap := maxK - 1
	if overlap < 0 {
		overlap = 0
	}
	buf := make([]byte, SpillMemLimit())
	carry := []byte(nil)
	var copyErr error
	for copyErr == nil {
		n, readErr := in.Read(buf)
		if n > 0 {
			work := RedactBodyKeys(append(carry, buf[:n]...), keys)
			if readErr == io.EOF {
				_, copyErr = out.Write(work)
				carry = nil
			} else if len(work) > overlap {
				_, copyErr = out.Write(work[:len(work)-overlap])
				if copyErr == nil {
					carry = append([]byte(nil), work[len(work)-overlap:]...)
				}
			} else {
				carry = work
			}
		}
		if readErr == io.EOF {
			if copyErr == nil && len(carry) > 0 {
				_, copyErr = out.Write(RedactBodyKeys(carry, keys))
			}
			break
		}
		if readErr != nil {
			copyErr = readErr
			break
		}
	}
	// Windows cannot replace path while the source handle is still open.
	_ = in.Close()
	if copyErr != nil {
		return copyErr
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Rename(outPath, path); err != nil {
		_ = os.Remove(outPath)
		return err
	}
	ok = true
	return nil
}
